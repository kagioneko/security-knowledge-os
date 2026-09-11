"""M3 / AC-04, AC-05, AC-06, AC-07, AC-19: deterministic assessment over fixtures."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from app.config import Mode, Settings
from app.models.assessment import AssessmentInput, OverallStatus
from app.models.risk import FindingStatus
from app.reviewer.assess import assess_deterministic
from app.reviewer.rule_loader import RuleCatalogue

VULNERABLE = [
    "V-001-indirect-injection-auto-email",
    "V-002-rag-delete-tool-no-approval",
    "V-003-persistent-memory-untrusted",
    "V-004-env-secret-readable",
]
SAFE = [
    "S-001-prompt-only",
    "S-002-rag-trusted-no-actions",
    "S-003-readonly-tool-with-approval",
    "S-004-credential-proxy",
]
UNKNOWN = [
    "U-001-tool-permissions-missing",
    "U-002-memory-persistence-unspecified",
    "U-003-outbound-destination-unspecified",
    "U-004-credential-handling-unspecified",
    "U-005-tool-permission-unrecognized",
]
ALL = VULNERABLE + SAFE + UNKNOWN

Loader = Callable[[str], AssessmentInput]


@pytest.fixture
def settings() -> Settings:
    return Settings(mode=Mode.PRIVATE)


@pytest.mark.parametrize("name", ALL)
def test_ac04_every_fixture_completes(
    name: str, load_assessment: Loader, catalogue: RuleCatalogue, settings: Settings
) -> None:
    result = assess_deterministic(load_assessment(name), catalogue, settings=settings)
    assert result.assessment_id
    assert result.model_info.deterministic_only is True
    assert result.overall_status in set(OverallStatus)


@pytest.mark.parametrize("name", VULNERABLE)
def test_ac05_vulnerable_fixtures_are_flagged(
    name: str, load_assessment: Loader, catalogue: RuleCatalogue, settings: Settings
) -> None:
    result = assess_deterministic(load_assessment(name), catalogue, settings=settings)
    statuses = {f.status for f in result.findings}
    assert statuses & {FindingStatus.FAIL, FindingStatus.WARN}, result.findings
    assert result.overall_status in {OverallStatus.FAIL, OverallStatus.CONDITIONAL}
    assert result.human_review_required is True


@pytest.mark.parametrize("name", SAFE)
def test_ac06_safe_fixtures_not_severe_fail(
    name: str, load_assessment: Loader, catalogue: RuleCatalogue, settings: Settings
) -> None:
    result = assess_deterministic(load_assessment(name), catalogue, settings=settings)
    assert result.overall_status is not OverallStatus.FAIL
    assert not any(f.status is FindingStatus.FAIL for f in result.findings), result.findings


@pytest.mark.parametrize("name", UNKNOWN)
def test_ac07_and_ac19_unknown_fixtures_return_unknown(
    name: str, load_assessment: Loader, catalogue: RuleCatalogue, settings: Settings
) -> None:
    result = assess_deterministic(load_assessment(name), catalogue, settings=settings)
    assert any(f.status is FindingStatus.UNKNOWN for f in result.findings), result.findings
    # AC-19: a missing/unknown input never lets the assessment settle on PASS
    assert result.overall_status is OverallStatus.UNKNOWN


def test_ac19_no_rule_finding_is_pass_with_unknown_reasoning(
    load_assessment: Loader, catalogue: RuleCatalogue, settings: Settings
) -> None:
    for name in ALL:
        result = assess_deterministic(load_assessment(name), catalogue, settings=settings)
        for finding in result.findings:
            if finding.status is FindingStatus.PASS:
                assert "could not" not in finding.reasoning_summary
                assert "not provided" not in finding.reasoning_summary


def test_specific_findings_v001(
    load_assessment: Loader, catalogue: RuleCatalogue, settings: Settings
) -> None:
    result = assess_deterministic(
        load_assessment("V-001-indirect-injection-auto-email"), catalogue, settings=settings
    )
    by_id = {f.risk_id: f for f in result.findings}
    assert by_id["PI-003"].status is FindingStatus.FAIL
    assert by_id["TOOL-001"].status is FindingStatus.FAIL
    assert result.overall_status is OverallStatus.FAIL


def test_specific_findings_v004_credential(
    load_assessment: Loader, catalogue: RuleCatalogue, settings: Settings
) -> None:
    result = assess_deterministic(
        load_assessment("V-004-env-secret-readable"), catalogue, settings=settings
    )
    by_id = {f.risk_id: f for f in result.findings}
    assert by_id["CRED-001"].status is FindingStatus.FAIL


def test_findings_carry_evidence(
    load_assessment: Loader, catalogue: RuleCatalogue, settings: Settings
) -> None:
    result = assess_deterministic(
        load_assessment("V-002-rag-delete-tool-no-approval"), catalogue, settings=settings
    )
    for finding in result.findings:
        assert finding.evidence
        assert finding.reasoning_summary


def test_adv01_unrecognized_tool_permission_never_silently_passes(
    load_assessment: Loader, catalogue: RuleCatalogue, settings: Settings
) -> None:
    """Regression for cross-review finding SKOS-ADV-01 (Antigravity, 2026-09-11):
    an arbitrary/unrecognized ``permissions`` string used to satisfy
    ``tool_permissions_specified`` by truthiness alone, so TOOL-000's
    ``required_evidence`` check was vacuously met, TOOL-000 (``checks: []``)
    emitted no finding, and TOOL-001 didn't count the unknown permission as
    high-impact - the assessment settled on ``PASS`` with
    ``human_review_required=False``. Must instead be UNKNOWN + human review."""
    result = assess_deterministic(
        load_assessment("U-005-tool-permission-unrecognized"), catalogue, settings=settings
    )
    assert result.overall_status is OverallStatus.UNKNOWN
    assert result.human_review_required is True
    by_id = {f.risk_id: f for f in result.findings}
    assert by_id["TOOL-000"].status is FindingStatus.UNKNOWN
