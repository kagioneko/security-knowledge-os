"""M3: A6 roll-up and A8 merge boundary."""

from __future__ import annotations

import pytest

from app.models.assessment import OverallStatus
from app.models.risk import Finding, FindingStatus, Severity
from app.reviewer.rollup import (
    compute_overall_status,
    merge_findings,
    requires_human_review,
)


def _f(status: FindingStatus, *, risk_id: str = "PI-003", origin: str = "rule") -> Finding:
    return Finding(
        risk_id=risk_id,
        title="t",
        severity=Severity.HIGH,
        status=status,
        origin=origin,  # type: ignore[arg-type]
    )


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([], OverallStatus.PASS),
        ([FindingStatus.PASS], OverallStatus.PASS),
        ([FindingStatus.PASS, FindingStatus.UNKNOWN], OverallStatus.UNKNOWN),
        ([FindingStatus.UNKNOWN, FindingStatus.WARN], OverallStatus.CONDITIONAL),
        ([FindingStatus.WARN, FindingStatus.FAIL], OverallStatus.FAIL),
        ([FindingStatus.NA, FindingStatus.PASS], OverallStatus.PASS),
    ],
)
def test_overall_status(statuses: list[FindingStatus], expected: OverallStatus) -> None:
    assert compute_overall_status([_f(s) for s in statuses]) is expected


def test_human_review_triggers_on_flagged_finding() -> None:
    assert requires_human_review(
        [_f(FindingStatus.UNKNOWN)], high_impact_present=False, confidential_knowledge_used=False
    )


def test_human_review_triggers_on_high_impact_even_if_all_pass() -> None:
    assert requires_human_review(
        [_f(FindingStatus.PASS)], high_impact_present=True, confidential_knowledge_used=False
    )


def test_human_review_false_when_clean() -> None:
    assert not requires_human_review(
        [_f(FindingStatus.PASS)], high_impact_present=False, confidential_knowledge_used=False
    )


def test_human_review_triggers_on_missing_information_alone() -> None:
    """Regression for SKOS-ADV-07 (Antigravity, round 2, 2026-09-11): a
    suppressed medium/low rule (all trigger clauses undetermined) leaves
    zero findings but a non-empty missing_information - previously nothing
    keyed on that, so human_review_required stayed False despite an open
    question about the rule's applicability."""
    assert requires_human_review(
        [],
        high_impact_present=False,
        confidential_knowledge_used=False,
        missing_information_present=True,
    )


def test_human_review_still_false_when_truly_clean() -> None:
    assert not requires_human_review(
        [_f(FindingStatus.PASS)],
        high_impact_present=False,
        confidential_knowledge_used=False,
        missing_information_present=False,
    )


def test_merge_findings_adds_llm_obs() -> None:
    rule = [_f(FindingStatus.FAIL)]
    llm = [_f(FindingStatus.WARN, risk_id="LLM-OBS-00001", origin="llm")]
    merged = merge_findings(rule, llm)
    assert [m.risk_id for m in merged] == ["PI-003", "LLM-OBS-00001"]


def test_merge_findings_rejects_non_llm_addition() -> None:
    with pytest.raises(ValueError):
        merge_findings([], [_f(FindingStatus.WARN, risk_id="X-001", origin="rule")])
