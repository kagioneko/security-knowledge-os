"""M6: PolicyStop becomes a POLICY_BLOCKED report, never a silent empty result."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from app.config import Mode, Settings
from app.models.assessment import AssessmentInput
from app.models.policy_outcome import PolicyOutcome
from app.models.report import AssessmentReport, ReportStatus
from app.retrieval.index import build_index
from app.reviewer.report import build_report, render_text
from app.reviewer.rule_loader import RuleCatalogue
from app.storage.db import connect

Loader = Callable[[str], AssessmentInput]


def test_completed_report_carries_a_result(
    load_assessment: Loader, catalogue: RuleCatalogue
) -> None:
    report = build_report(load_assessment("V-001-indirect-injection-auto-email"), catalogue)
    assert report.status is ReportStatus.COMPLETED
    assert report.result is not None
    assert report.policy_decision is None


def test_tampered_index_produces_a_policy_blocked_report_not_empty_findings(
    tmp_path: Path, corpus_root: Path, catalogue: RuleCatalogue, load_assessment: Loader
) -> None:
    db = tmp_path / "idx.sqlite"
    build_index(corpus_root, db)
    conn = connect(db)
    try:
        conn.execute("UPDATE chunks SET text = 'tampered' WHERE rowid = 1")
        conn.commit()
        report = build_report(
            load_assessment("S-001-prompt-only"),
            catalogue,
            settings=Settings(mode=Mode.PRIVATE),
            index_conn=conn,
        )
    finally:
        conn.close()

    assert report.status is ReportStatus.POLICY_BLOCKED
    assert report.result is None  # NOT a 200-with-empty-findings
    assert report.policy_decision is not None
    assert report.policy_decision.outcome is PolicyOutcome.POLICY_BLOCKED


def test_report_shape_is_enforced() -> None:
    with pytest.raises(ValueError):
        AssessmentReport(status=ReportStatus.COMPLETED)
    with pytest.raises(ValueError):
        AssessmentReport(status=ReportStatus.POLICY_BLOCKED)


def test_render_text_covers_both_shapes(
    load_assessment: Loader, catalogue: RuleCatalogue
) -> None:
    ok = build_report(load_assessment("V-002-rag-delete-tool-no-approval"), catalogue)
    text = render_text(ok)
    assert "overall_status:" in text
    assert "human_review_required:" in text
    assert "knowledge_revision:" in text


def test_human_review_required_is_not_a_report_status(
    load_assessment: Loader, catalogue: RuleCatalogue
) -> None:
    # a completed assessment that needs human review is still COMPLETED
    report = build_report(load_assessment("V-001-indirect-injection-auto-email"), catalogue)
    assert report.status is ReportStatus.COMPLETED
    assert report.result is not None and report.result.human_review_required is True
