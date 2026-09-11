"""FastAPI application (spec Section 18).

Local, unauthenticated by default (``uvicorn app.main:app``). Needs the ``[api]``
extra.

Two layers are kept separate on purpose:
  * HTTP status  - transport-level "could I process this request?"
  * policy outcome - a ``PolicyOutcome`` in the response body

A policy-blocked assessment returns HTTP 422 with ``status="POLICY_BLOCKED"`` and
the ``policy_decision`` in the body - never HTTP 200 with empty findings.
``human_review_required`` is a workflow flag inside a COMPLETED (HTTP 200) body,
not an error.

There is **no endpoint that changes knowledge content**. ``/v1/knowledge/reindex``
only re-derives the FTS index from the already-verified read-only knowledge root.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict

from app.config import Settings
from app.ingestion.validator import Level, validate_markdown
from app.llm.factory import get_client
from app.models.answer import AnswerPatch
from app.models.assessment import AssessmentInput
from app.models.report import AssessmentReport, ReportStatus
from app.policy.safe_test import load_safe_test_templates
from app.retrieval.index import ReindexReport, reindex_atomic
from app.reviewer.answers import AnswerValidationError, apply_patch
from app.reviewer.report import build_report, render_text
from app.reviewer.rule_loader import load_rules
from app.storage.db import connect

app = FastAPI(title="Security Knowledge OS", version="0.1.0")

# Codex cross-review finding #10 (2026-09-11): the in-memory store had no size
# bound at all. Accepted as in-memory for the MVP (spec Section 18, localhost
# scope), but unbounded growth from repeated /v1/assessments or /answers calls
# is still a resource-exhaustion vector on its own. Simple FIFO cap - not a
# full LRU/expiry policy, but it turns "unbounded" into "bounded" cheaply.
_MAX_STORE_ENTRIES = 5000
_STORE: dict[str, tuple[AssessmentInput, AssessmentReport]] = {}

# Codex cross-review finding #6, part 2 (round 2, 2026-09-11): resubmitting
# the SAME (non-no-op) patch against the SAME parent repeatedly used to create
# a brand-new assessment + store entry every time - each call is a full
# re-assessment (LLM/provider cost too, when configured) for a result that is
# byte-for-byte identical to one already computed. Cached by
# (parent_assessment_id, resulting merged-input hash) -> the assessment_id
# that patch already produced, so a repeat returns the existing result instead
# of paying to recompute (and store) a duplicate. Bounded the same way as
# _STORE; a cache miss (evicted or never seen) just re-runs, same as before -
# this is a cost/dedup optimization, not a correctness requirement.
_MAX_ANSWER_CACHE_ENTRIES = 5000
_ANSWER_CACHE: dict[tuple[str, str], str] = {}


def _store_put(assessment_id: str, entry: tuple[AssessmentInput, AssessmentReport]) -> None:
    _STORE[assessment_id] = entry
    while len(_STORE) > _MAX_STORE_ENTRIES:
        _STORE.pop(next(iter(_STORE)))  # evict oldest (dict preserves insertion order)


def _answer_cache_put(key: tuple[str, str], assessment_id: str) -> None:
    _ANSWER_CACHE[key] = assessment_id
    while len(_ANSWER_CACHE) > _MAX_ANSWER_CACHE_ENTRIES:
        _ANSWER_CACHE.pop(next(iter(_ANSWER_CACHE)))


# Codex cross-review finding #11 (2026-09-11): /v1/knowledge/reindex accepted
# requests regardless of Host/Origin - a form-encoded POST from any page could
# trigger it. The service is documented as loopback/localhost-only (spec
# Section 18); this makes that assumption an enforced check, not just a
# deployment note, without requiring authentication for the MVP. "testserver"
# is Starlette TestClient's own fixed default Host header, not a real,
# externally-routable hostname - allowing it only enables this app's own test
# suite, it grants nothing to an actual remote client.
_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1", "testserver"}


def _hostname_only(value: str) -> str:
    """Strip a port (and IPv6 brackets) from a Host/Origin/Referer authority."""
    value = value.strip()
    if value.startswith("["):
        return value[1:].split("]", 1)[0]
    head, sep, tail = value.rpartition(":")
    return head if sep and tail.isdigit() else value


def _require_local_origin(request: Request) -> None:
    """ADV-09 / Codex#3 (round 2, 2026-09-11): the original check inspected
    only the Host header. Host names the DESTINATION the client is connecting
    to - for a request routed to this loopback service, Host is always
    "localhost"/"127.0.0.1" regardless of who initiated it. Origin (or,
    failing that, Referer) names the PAGE that initiated the request, which is
    what actually distinguishes "this app called itself" from "a page on
    https://attacker.example made a cross-origin POST that happened to land
    here" - the real CSRF vector. Only a client that sends neither header
    (curl, httpx, this app's own scripts - never a browser navigation/fetch
    doing a real cross-origin request) falls back to the Host check.
    """
    for header in ("origin", "referer"):
        value = request.headers.get(header)
        if value:
            authority = urlsplit(value).netloc
            if _hostname_only(authority) not in _ALLOWED_HOSTS:
                raise HTTPException(
                    status_code=403, detail="this endpoint only serves local clients"
                )
            return
    host = _hostname_only(request.headers.get("host") or "")
    if host not in _ALLOWED_HOSTS:
        raise HTTPException(status_code=403, detail="this endpoint only serves local clients")


def _settings() -> Settings:
    return Settings.from_env()


def _run(inp: AssessmentInput, settings: Settings) -> AssessmentReport:
    catalogue = load_rules(settings.rules_root)
    safe_tests = load_safe_test_templates(settings.safe_tests_root)
    client = get_client(settings)
    db_path = Path(settings.db_path)
    conn = connect(db_path, read_only=True) if db_path.exists() else None
    try:
        return build_report(
            inp, catalogue, settings=settings, client=client, index_conn=conn, safe_tests=safe_tests
        )
    finally:
        if conn is not None:
            conn.close()


def _respond(report: AssessmentReport) -> AssessmentReport:
    if report.status is ReportStatus.POLICY_BLOCKED:
        raise HTTPException(status_code=422, detail=report.model_dump(mode="json"))
    return report


# --------------------------------------------------------------------------- #
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/assessments", response_model=AssessmentReport)
def create_assessment(inp: AssessmentInput) -> AssessmentReport:
    settings = _settings()
    report = _run(inp, settings)
    if report.result is not None:
        _store_put(report.result.assessment_id, (inp, report))
    return _respond(report)


@app.get("/v1/assessments/{assessment_id}", response_model=AssessmentReport)
def get_assessment(assessment_id: str) -> AssessmentReport:
    entry = _STORE.get(assessment_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    return entry[1]


@app.post("/v1/assessments/{assessment_id}/answers", response_model=AssessmentReport)
def submit_answers(assessment_id: str, patch: AnswerPatch) -> AssessmentReport:
    entry = _STORE.get(assessment_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    if patch.is_empty():
        raise HTTPException(status_code=422, detail="the answer patch is empty")

    original_input, original_report = entry
    try:
        new_input = apply_patch(original_input, patch)
    except AnswerValidationError as exc:
        raise HTTPException(status_code=422, detail={"rejected": exc.reasons}) from exc

    # Codex cross-review finding #10 (2026-09-11): patch.is_empty() only catches
    # "no field set at all" (every field None); a patch that sets a field to a
    # value that merges to a no-op (e.g. human_approval={}, which .update()s
    # into the existing dict and changes nothing) passed is_empty() and still
    # triggered a full re-assessment + a new stored revision every single call
    # - a free, repeatable cost/storage-growth amplifier. Comparing the merged
    # input to the original catches every such no-op, not just the empty case.
    if new_input == original_input:
        return _respond(original_report)

    # Codex cross-review finding #6, part 2 (round 2, 2026-09-11): a repeat of
    # the SAME (non-no-op) patch against the SAME parent - e.g. a client
    # retrying after a dropped response - used to re-run the full assessment
    # and create yet another store entry every time, even though the result
    # is byte-for-byte identical to one already computed. new_input's own
    # canonical JSON is deterministic (pydantic v2 preserves field-declaration
    # order), so it doubles as the dedup key - no need to hash the raw patch.
    cache_key = (assessment_id, new_input.model_dump_json())
    cached_id = _ANSWER_CACHE.get(cache_key)
    if cached_id is not None:
        cached_entry = _STORE.get(cached_id)
        if cached_entry is not None:
            return _respond(cached_entry[1])

    report = _run(new_input, _settings())
    if report.result is not None:
        prev_revision = (
            original_report.result.revision if original_report.result is not None else 1
        )
        report.result.supersedes = assessment_id
        report.result.revision = prev_revision + 1
        _store_put(report.result.assessment_id, (new_input, report))
        _answer_cache_put(cache_key, report.result.assessment_id)
    return _respond(report)


@app.get("/v1/assessments/{assessment_id}/history")
def get_history(assessment_id: str) -> list[dict[str, Any]]:
    """The revision chain, oldest first, reached by following ``supersedes``."""
    chain: list[dict[str, Any]] = []
    current: str | None = assessment_id
    seen: set[str] = set()
    while current is not None and current not in seen:
        seen.add(current)
        entry = _STORE.get(current)
        if entry is None or entry[1].result is None:
            break
        r = entry[1].result
        chain.append(
            {
                "assessment_id": r.assessment_id,
                "revision": r.revision,
                "supersedes": r.supersedes,
                "overall_status": r.overall_status.value,
            }
        )
        current = r.supersedes
    return list(reversed(chain))


@app.get("/v1/assessments/{assessment_id}/report")
def get_assessment_report(assessment_id: str) -> Response:
    entry = _STORE.get(assessment_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    return Response(content=render_text(entry[1]), media_type="text/plain")


class KnowledgeDoc(BaseModel):
    # Codex cross-review finding #15 (2026-09-11): every other externally-fed
    # request model (AssessmentInput, AnswerPatch, ...) is extra="forbid";
    # this one silently discarded unknown fields instead of rejecting them.
    model_config = ConfigDict(extra="forbid")

    content: str
    source: str = "<api>"


@app.post("/v1/knowledge/validate")
def validate_knowledge_doc(doc: KnowledgeDoc) -> dict[str, Any]:
    """Read-only: validate one Knowledge Unit. Nothing is stored or written."""
    issues = validate_markdown(doc.content, source=doc.source)
    return {
        "errors": [i.__dict__ | {"level": i.level.value} for i in issues if i.level is Level.ERROR],
        "warnings": [
            i.__dict__ | {"level": i.level.value} for i in issues if i.level is Level.WARNING
        ],
        "valid": not any(i.level is Level.ERROR for i in issues),
    }


@app.post("/v1/knowledge/reindex", response_model=ReindexReport)
def reindex(request: Request) -> ReindexReport:
    """Re-derive the FTS index from the existing verified read-only knowledge root.

    This does not accept or change knowledge content. classification + integrity
    are verified before the atomic swap; on failure the existing index is kept."""
    _require_local_origin(request)
    settings = _settings()
    report = reindex_atomic(settings.knowledge_root, settings.db_path)
    if not report.ok:
        raise HTTPException(status_code=422, detail=report.model_dump(mode="json"))
    return report
