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

from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel

from app.config import Settings
from app.ingestion.validator import Level, validate_markdown
from app.llm.factory import get_client
from app.models.assessment import AssessmentInput
from app.models.report import AssessmentReport, ReportStatus
from app.policy.safe_test import load_safe_test_templates
from app.retrieval.index import ReindexReport, reindex_atomic
from app.reviewer.report import build_report, render_text
from app.reviewer.rule_loader import load_rules
from app.storage.db import connect

app = FastAPI(title="Security Knowledge OS", version="0.1.0")

_STORE: dict[str, tuple[AssessmentInput, AssessmentReport]] = {}


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
        _STORE[report.result.assessment_id] = (inp, report)
    return _respond(report)


@app.get("/v1/assessments/{assessment_id}", response_model=AssessmentReport)
def get_assessment(assessment_id: str) -> AssessmentReport:
    entry = _STORE.get(assessment_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    return entry[1]


class Answers(BaseModel):
    answers: dict[str, Any]


_ANSWER_FIELDS = {
    "system_prompt": lambda inp, v: inp.model_copy(update={"system_prompt": v}),
}


@app.post("/v1/assessments/{assessment_id}/answers", response_model=AssessmentReport)
def submit_answers(assessment_id: str, payload: Answers) -> AssessmentReport:
    entry = _STORE.get(assessment_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    original, _ = entry
    updated = original.model_dump()
    for key, value in payload.answers.items():
        if key in AssessmentInput.model_fields:
            updated[key] = value
    new_input = AssessmentInput.model_validate(updated)
    settings = _settings()
    report = _run(new_input, settings)
    if report.result is not None:
        _STORE[report.result.assessment_id] = (new_input, report)
        _STORE[assessment_id] = (new_input, report)
    return _respond(report)


@app.get("/v1/assessments/{assessment_id}/report")
def get_assessment_report(assessment_id: str) -> Response:
    entry = _STORE.get(assessment_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    return Response(content=render_text(entry[1]), media_type="text/plain")


class KnowledgeDoc(BaseModel):
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
def reindex() -> ReindexReport:
    """Re-derive the FTS index from the existing verified read-only knowledge root.

    This does not accept or change knowledge content. classification + integrity
    are verified before the atomic swap; on failure the existing index is kept."""
    settings = _settings()
    report = reindex_atomic(settings.knowledge_root, settings.db_path)
    if not report.ok:
        raise HTTPException(status_code=422, detail=report.model_dump(mode="json"))
    return report
