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

import hashlib
import ipaddress
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

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

# Codex cross-review finding #4 (round 4, 2026-09-12), reproduced exactly as
# reported: POSTing two million bytes of whitespace padding around a tiny
# valid AssessmentInput returned 200 - pydantic's canonical serialization
# drops insignificant JSON whitespace, so AssessmentInput's total-size
# model_validator (round 3) only ever sees the small PARSED object, never the
# actual wire size the server had to receive and parse. Counting bytes as
# they stream in (rather than trusting a Content-Length header, which
# chunked transfer-encoding omits) bounds memory/CPU spent on the request
# body regardless of what it deserializes to.
_MAX_BODY_BYTES = 1_000_000


class _MaxBodySizeMiddleware:
    """Raw ASGI middleware: reject a request body over `_MAX_BODY_BYTES`
    before FastAPI/pydantic ever parses it. Added via `app.add_middleware()`
    (not `@app.middleware("http")`, which would need to fully buffer the body
    itself via `Request.body()` to inspect it - defeating the point). Counts
    bytes on the raw `receive()` channel and aborts as soon as the cap is
    crossed, rather than trusting a Content-Length header (absent under
    chunked transfer-encoding) or waiting for the full body to buffer.

    Raises an ``HTTPException`` (not a plain exception) because FastAPI's own
    body-reading (``fastapi/routing.py``'s ``request_body_to_args``) wraps
    ``await request.json()`` in `except HTTPException: raise` / `except
    Exception: raise HTTPException(400, "There was an error parsing the
    body")` - a plain exception raised from inside `receive()` while that
    runs is caught by the second branch and reported as a generic 400,
    masking this as a body-parsing error rather than the deliberate 413 it
    actually is."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        seen = 0

        async def _limited_receive() -> Any:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body") or b"")
                if seen > _MAX_BODY_BYTES:
                    raise HTTPException(status_code=413, detail="request body too large")
            return message

        await self.app(scope, _limited_receive, send)


app.add_middleware(_MaxBodySizeMiddleware)

# Codex cross-review finding #10 (2026-09-11): the in-memory store had no size
# bound at all. Accepted as in-memory for the MVP (spec Section 18, localhost
# scope), but unbounded growth from repeated /v1/assessments or /answers calls
# is still a resource-exhaustion vector on its own. Simple FIFO cap - not a
# full LRU/expiry policy, but it turns "unbounded" into "bounded" cheaply.
#
# Codex#8 (round 8, 2026-09-12), reproduced exactly as reported: an
# entry-COUNT cap alone bounds nothing meaningful about actual memory -
# AssessmentInput's own total-size cap (_MAX_SERIALIZED_BYTES, 300_000)
# means 5,000 entries near that limit retain ~1.5 GB from the inputs
# alone, before the AssessmentReport half of each entry, the Pydantic
# object overhead, and any LLM raw-result storage are even counted. A
# byte-weighted budget bounds what actually matters (memory), with the
# entry count as a secondary belt-and-suspenders cap for the common case
# of many small entries.
_MAX_STORE_ENTRIES = 5000
_MAX_STORE_BYTES = 50_000_000  # ~50 MB
_STORE: dict[str, tuple[AssessmentInput, AssessmentReport]] = {}
_STORE_ENTRY_BYTES: dict[str, int] = {}
_STORE_TOTAL_BYTES = 0

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

# Codex#5 (round 5, 2026-09-12), reproduced exactly as reported: with
# `_MAX_STORE_ENTRIES = 1`, 32 threads calling `_store_put` concurrently (each
# FastAPI sync endpoint runs in its own worker thread) produced
# `RuntimeError("dictionary changed size during iteration")` and `KeyError`
# from the unguarded assign-then-evict sequence below. `_answer_lock_for`
# (round 4) already serializes the compute-and-store critical section for a
# given cache key, but the plain assignment/eviction here races across
# *different* keys/callers regardless of that. A single lock per dict is
# sufficient (these are cheap dict operations, not the assessment compute
# itself) and keeps the FIFO-eviction contract intact under concurrency.
_STORE_GUARD = threading.Lock()
_ANSWER_CACHE_GUARD = threading.Lock()


def _entry_size(entry: tuple[AssessmentInput, AssessmentReport]) -> int:
    inp, report = entry
    return len(inp.model_dump_json().encode("utf-8")) + len(
        report.model_dump_json().encode("utf-8")
    )


def _store_put(assessment_id: str, entry: tuple[AssessmentInput, AssessmentReport]) -> None:
    global _STORE_TOTAL_BYTES
    size = _entry_size(entry)
    with _STORE_GUARD:
        _STORE_TOTAL_BYTES -= _STORE_ENTRY_BYTES.pop(assessment_id, 0)
        _STORE[assessment_id] = entry
        _STORE_ENTRY_BYTES[assessment_id] = size
        _STORE_TOTAL_BYTES += size
        while _STORE and (
            len(_STORE) > _MAX_STORE_ENTRIES or _STORE_TOTAL_BYTES > _MAX_STORE_BYTES
        ):
            oldest = next(iter(_STORE))  # evict oldest (dict preserves insertion order)
            _STORE.pop(oldest)
            _STORE_TOTAL_BYTES -= _STORE_ENTRY_BYTES.pop(oldest, 0)


def _answer_cache_put(key: tuple[str, str], assessment_id: str) -> None:
    with _ANSWER_CACHE_GUARD:
        _ANSWER_CACHE[key] = assessment_id
        while len(_ANSWER_CACHE) > _MAX_ANSWER_CACHE_ENTRIES:
            _ANSWER_CACHE.pop(next(iter(_ANSWER_CACHE)))


# Codex cross-review finding #6 (round 4, 2026-09-12), reproduced exactly as
# reported: two threads submitting the SAME patch against the SAME parent,
# synchronized so both miss the cache before either writes to it, each ran a
# full re-assessment and produced two distinct child assessments - the cache
# above only dedupes SEQUENTIAL repeats. A lock per cache key serializes the
# "check cache, else run and store" critical section (double-checked: the
# second thread through re-checks the cache once it has the lock, so it gets
# the first thread's result instead of also recomputing). Bounded the same
# FIFO way as the caches it guards.
_MAX_ANSWER_LOCKS = 5000
_ANSWER_LOCKS_GUARD = threading.Lock()
_ANSWER_LOCKS: dict[tuple[str, str], threading.Lock] = {}


def _answer_lock_for(key: tuple[str, str]) -> threading.Lock:
    with _ANSWER_LOCKS_GUARD:
        lock = _ANSWER_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _ANSWER_LOCKS[key] = lock
            while len(_ANSWER_LOCKS) > _MAX_ANSWER_LOCKS:
                _ANSWER_LOCKS.pop(next(iter(_ANSWER_LOCKS)))
        return lock


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


def _effective_port(scheme: str, port: int | None) -> int:
    if port is not None:
        return port
    return 443 if scheme == "https" else 80


def _is_local_origin(request: Request) -> bool:
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

    Codex#3 (round 8, 2026-09-12), reproduced exactly as reported:
    comparing only the HOSTNAME discarded scheme and port, so
    `Origin: http://localhost:9999` passed against a service actually
    running on `http://localhost:8000` - `_hostname_only` reduces both to
    "localhost". A hostile page on ANY other localhost port (a common
    situation: several dev servers bound to loopback at once) could
    therefore trigger this service. The browser's own same-origin policy
    already treats a different port as a different origin; this check must
    match that and compare the full (scheme, hostname, effective port)
    tuple against the ACTUAL port this request arrived on
    (`request.url`), not just a static hostname allowlist.
    """
    for header in ("origin", "referer"):
        value = request.headers.get(header)
        if value:
            parts = urlsplit(value)
            hostname = (parts.hostname or "").lower()
            if hostname not in _ALLOWED_HOSTS:
                return False
            return parts.scheme == request.url.scheme and _effective_port(
                parts.scheme, parts.port
            ) == _effective_port(request.url.scheme, request.url.port)
    host = _hostname_only(request.headers.get("host") or "")
    return host in _ALLOWED_HOSTS


def _peer_is_loopback(request: Request) -> bool:
    """Codex#1 (round 5, 2026-09-12): `Host`/`Origin`/`Referer` are values
    the CLIENT supplies in the request - they say nothing about who actually
    opened the TCP connection. If Uvicorn is ever bound to a non-loopback
    address (`--host 0.0.0.0`), a remote client can send `Host: localhost`
    (with no Origin/Referer) and pass `_is_local_origin` outright. The ASGI
    transport's peer address is the one thing a client cannot forge, so it is
    checked in addition to (not instead of) `_is_local_origin`: the peer
    check stops a remote client regardless of headers, and `_is_local_origin`
    still stops a same-machine browser page from CSRFing this service via a
    cross-origin request that arrives from the real loopback peer."""
    client = request.client
    if client is None:
        return False
    try:
        return ipaddress.ip_address(client.host).is_loopback
    except ValueError:
        return False


# Codex#5 / Antigravity SKOS-ADV-13 (round 4, 2026-09-12): only
# /v1/knowledge/reindex called _require_local_origin() (as it then was) - the
# assessment endpoints (create/get/answers/history/report), which can trigger
# LLM-provider spend and return excerpts of internal/confidential Knowledge
# Units, had no Host/Origin check at all. A DNS-rebinding attacker (a domain
# with a low-TTL record that rebinds to 127.0.0.1) or a same-machine page
# could hit them directly. This is a single choke point in front of every
# route (except /health, which returns nothing sensitive and takes no
# provider action) rather than a per-endpoint call that is easy to forget to
# add to the next new route.
@app.middleware("http")
async def _local_origin_gate(request: Request, call_next):  # type: ignore[no-untyped-def]
    if request.url.path != "/health" and not (
        _peer_is_loopback(request) and _is_local_origin(request)
    ):
        return JSONResponse(
            {"detail": "this endpoint only serves local clients"}, status_code=403
        )
    return await call_next(request)


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
    # order), so it doubles as the dedup key.
    # Codex cross-review finding #3, part 2 (round 3, 2026-09-12): using that
    # JSON string itself as the dict key meant _ANSWER_CACHE retained a full
    # copy of every distinct merged input it had ever seen (bounded in COUNT
    # by _MAX_ANSWER_CACHE_ENTRIES, not in per-entry size). Hashing it first
    # gives a fixed-size key with the same dedup property.
    cache_key = (
        assessment_id,
        hashlib.sha256(new_input.model_dump_json().encode("utf-8")).hexdigest(),
    )

    # Codex cross-review finding #6 (round 4, 2026-09-12): the cache lookup
    # and the run-and-store below used to have no synchronization between
    # them, so two concurrent requests for the same (assessment_id,
    # new_input) could both miss the cache and both re-run the assessment.
    # A lock per cache key serializes this section; the second thread to
    # acquire it re-checks the cache (now populated by the first) before
    # deciding to run anything itself.
    with _answer_lock_for(cache_key):
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

    # Codex cross-review finding #2 (round 3, 2026-09-12): unbounded - the
    # real DoS vector was the YAML parser (fixed with a merge-key ban and its
    # own size cap in app/ingestion/parser.py), but bounding the whole
    # request body too is a cheap, independent second layer. Real Knowledge
    # Unit files are a few KB; this leaves generous headroom.
    content: str = Field(max_length=200_000)
    # Codex cross-review finding #4, part 2 (round 4, 2026-09-12), reproduced
    # exactly as reported: `source` is echoed back verbatim in EVERY returned
    # validation issue (see validate_knowledge_doc() below), so an unbounded
    # `source` turns one request into a response amplified by the number of
    # issues found - a one-million-character `source` produced a ~12 MB
    # response from a tiny request.
    source: str = Field(default="<api>", max_length=500)


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
def reindex() -> ReindexReport:
    """Re-derive the FTS index from the existing verified read-only knowledge root.

    This does not accept or change knowledge content. classification + integrity
    are verified before the atomic swap; on failure the existing index is kept.
    The Host/Origin check is now the global `_local_origin_gate` middleware
    (round 4, 2026-09-12), not a per-endpoint call - see its definition."""
    settings = _settings()
    report = reindex_atomic(settings.knowledge_root, settings.db_path)
    if not report.ok:
        raise HTTPException(status_code=422, detail=report.model_dump(mode="json"))
    return report
