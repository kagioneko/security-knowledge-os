"""M1: the Finding model enforces the LLM boundary (decision A8)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.models.risk import Finding, FindingStatus, Severity


def _finding(**kw: object) -> Finding:
    base: dict[str, object] = {
        "risk_id": "PI-003",
        "title": "Indirect prompt injection",
        "severity": Severity.HIGH,
        "status": FindingStatus.FAIL,
    }
    base.update(kw)
    return Finding.model_validate(base)


def test_rule_finding_can_be_fail() -> None:
    assert _finding().status is FindingStatus.FAIL


def test_llm_finding_cannot_be_fail() -> None:
    with pytest.raises(ValidationError):
        _finding(risk_id="LLM-OBS-00001", origin="llm", status=FindingStatus.FAIL)


def test_llm_finding_cannot_be_pass() -> None:
    with pytest.raises(ValidationError):
        _finding(risk_id="LLM-OBS-00001", origin="llm", status=FindingStatus.PASS)


@pytest.mark.parametrize("status", [FindingStatus.WARN, FindingStatus.UNKNOWN])
def test_llm_finding_allows_warn_and_unknown(status: FindingStatus) -> None:
    finding = _finding(risk_id="LLM-OBS-00042", origin="llm", status=status)
    assert finding.origin == "llm"


def test_llm_finding_requires_llm_obs_prefix() -> None:
    with pytest.raises(ValidationError):
        _finding(risk_id="PI-003", origin="llm", status=FindingStatus.WARN)


def test_rule_finding_cannot_borrow_llm_obs_prefix() -> None:
    with pytest.raises(ValidationError):
        _finding(risk_id="LLM-OBS-00001", origin="rule", status=FindingStatus.WARN)
