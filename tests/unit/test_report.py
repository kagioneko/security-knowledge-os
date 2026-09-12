"""M6: PolicyStop becomes a POLICY_BLOCKED report, never a silent empty result."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pydantic
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


def test_report_shape_xor_is_enforced(
    load_assessment: Loader, catalogue: RuleCatalogue
) -> None:
    """Regression for Codex cross-review finding #14 (2026-09-11): the
    validator only checked the required side of each case, so a COMPLETED
    report could also carry a policy_decision, and a POLICY_BLOCKED report
    could also carry a result or an ALLOWED-outcome decision - all
    contradicting the module's own documented "status determines exactly one
    of the two payloads" contract."""
    from app.models.policy_outcome import PolicyDecision, PolicyOutcome

    completed = build_report(load_assessment("S-001-prompt-only"), catalogue)
    assert completed.result is not None
    blocked_decision = PolicyDecision(
        outcome=PolicyOutcome.POLICY_BLOCKED, subject="test", reasons=["r"]
    )
    allowed_decision = PolicyDecision(outcome=PolicyOutcome.ALLOWED, subject="test", reasons=[])

    with pytest.raises(ValueError, match="must not carry a policy_decision"):
        AssessmentReport(
            status=ReportStatus.COMPLETED, result=completed.result, policy_decision=blocked_decision
        )
    with pytest.raises(ValueError, match="must not carry a result"):
        AssessmentReport(
            status=ReportStatus.POLICY_BLOCKED,
            result=completed.result,
            policy_decision=blocked_decision,
        )
    with pytest.raises(ValueError, match="must not be an allowed outcome"):
        AssessmentReport(status=ReportStatus.POLICY_BLOCKED, policy_decision=allowed_decision)


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


def test_a_result_claiming_pass_despite_a_fail_finding_is_rejected(
    load_assessment: Loader, catalogue: RuleCatalogue
) -> None:
    """Regression for Codex#4 (round 9, 2026-09-12), reproduced exactly as
    reported: AssessmentResult did not validate overall_status or
    human_review_required against its own findings - a tampered saved
    report could claim overall_status="PASS" and
    human_review_required=false while carrying a FAIL finding."""
    from app.models.assessment import AssessmentResult, OverallStatus

    report = build_report(load_assessment("V-001-indirect-injection-auto-email"), catalogue)
    assert report.result is not None
    result = report.result.model_copy(
        update={"overall_status": OverallStatus.PASS, "human_review_required": False}
    )
    dumped = result.model_dump(mode="json")
    assert any(
        f["status"] == "FAIL" for f in dumped["findings"]
    ), "test assumption: this fixture produces a FAIL finding"
    with pytest.raises(pydantic.ValidationError):
        AssessmentResult.model_validate(dumped)


def test_a_saved_report_with_an_extra_field_is_rejected(
    load_assessment: Loader, catalogue: RuleCatalogue
) -> None:
    """Regression for Codex#14 (round 8, 2026-09-12), reproduced exactly as
    reported: parsing a saved report containing an extra or misspelled
    property validated and silently discarded it, weakening schema-drift
    and tamper detection for externally loaded report data."""
    report = build_report(load_assessment("V-001-indirect-injection-auto-email"), catalogue)
    dumped = report.model_dump(mode="json")
    dumped["unexpected_field"] = "surprise"
    with pytest.raises(pydantic.ValidationError):
        AssessmentReport.model_validate(dumped)


def test_a_saved_report_with_an_extra_field_on_a_nested_finding_is_rejected(
    load_assessment: Loader, catalogue: RuleCatalogue
) -> None:
    """Regression for Codex#14 (round 8, 2026-09-12): the same gap applied
    one level deeper - AssessmentReport.model_config alone does not
    validate nested models' OWN configs; Finding needed extra="forbid"
    too, not just its container."""
    report = build_report(load_assessment("V-001-indirect-injection-auto-email"), catalogue)
    dumped = report.model_dump(mode="json")
    assert dumped["result"]["findings"], "test assumption: this fixture has at least one finding"
    dumped["result"]["findings"][0]["unexpected_field"] = "surprise"
    with pytest.raises(pydantic.ValidationError):
        AssessmentReport.model_validate(dumped)
