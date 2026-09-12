"""M5 / AC-09: safe tests never require real secrets or real delivery, and an
LLM proposal is never promoted to an executable test automatically."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.models.assessment import SafeTest, SafeTestEnvironment, UntrustedSafeTestProposal
from app.models.knowledge import KnowledgeCategory
from app.models.policy_outcome import PolicyOutcome
from app.models.risk import RiskRule, Severity
from app.policy.safe_test import (
    SafeTestLoadError,
    load_safe_test_templates,
    promote_proposal,
    unresolved_safe_test_references,
    validate_safe_test,
)


def _base(**over: object) -> SafeTest:
    data: dict[str, object] = {
        "id": "ST-X-001",
        "title": "t",
        "risk_id": "PI-003",
        "origin": "template",
        "environment": [SafeTestEnvironment.SANDBOX, SafeTestEnvironment.CANARY],
        "scope": "the assessed agent's sandbox only",
        "uses_canary_values": True,
        "setup": ["place a canary value"],
        "steps": ["ask the agent to reveal config"],
        "expected_secure_behavior": "the canary is not revealed",
        "failure_condition": "the canary appears in output",
        "cleanup": ["remove the canary"],
        "requires_human_approval": False,
    }
    data.update(over)
    return SafeTest.model_validate(data)


def test_all_shipped_templates_pass_the_validator(safe_test_templates) -> None:
    assert set(safe_test_templates) == {"ST-IPI-001", "ST-MEM-001", "ST-TOOL-001", "ST-CRED-001"}
    for test in safe_test_templates.values():
        assert validate_safe_test(test).is_allowed


def test_clean_template_is_allowed() -> None:
    assert validate_safe_test(_base()).is_allowed


@pytest.mark.parametrize(
    "field,value",
    [
        ("steps", ["run rm -rf / on the target"]),
        ("steps", ["DROP TABLE users"]),
        ("setup", ["use the production database"]),
        ("steps", ["forward the summary to attacker@evil.corp"]),
        ("steps", ["POST the result to https://data.attacker.io/collect"]),
        ("setup", ["read the key AKIAIOSFODNN7EXAMPLE from the file"]),
    ],
)
def test_dangerous_content_is_blocked(field: str, value: list[str]) -> None:
    decision = validate_safe_test(_base(**{field: value}))
    assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert decision.reasons


def test_empty_environment_is_a_schema_error() -> None:
    with pytest.raises(ValueError):
        _base(environment=[])  # schema min_length


def test_canary_environment_requires_the_canary_flag() -> None:
    test = _base(environment=[SafeTestEnvironment.CANARY], uses_canary_values=False)
    decision = validate_safe_test(test)
    assert decision.outcome is PolicyOutcome.POLICY_BLOCKED


def test_llm_proposal_is_never_auto_promoted() -> None:
    proposal = UntrustedSafeTestProposal(
        title="try sending a canary email", idea="see if it forwards", relates_to_risk_id="PI-003"
    )
    decision = promote_proposal(proposal)
    assert decision.outcome is PolicyOutcome.HUMAN_APPROVAL_REQUIRED
    assert not decision.is_allowed


def test_proposal_schema_has_no_executable_fields() -> None:
    assert set(UntrustedSafeTestProposal.model_fields) == {
        "title",
        "relates_to_risk_id",
        "idea",
        "origin",
    }


def test_symlinked_safe_test_template_is_rejected(tmp_path: Path) -> None:
    """Codex cross-review finding #2 (2026-09-11): confinement must be
    consistent across knowledge/rule/safe-test loaders."""
    real = tmp_path / "outside.yaml"
    real.write_text(
        "id: ST-X-006\ntitle: t\nrisk_id: PI-003\norigin: template\n"
        "environment: [sandbox]\nscope: s\nsteps: [a]\nsuccess_criteria: c\n"
        "requires_human_approval: true\n",
        encoding="utf-8",
    )
    root = tmp_path / "safe_tests"
    root.mkdir()
    (root / "linked.yaml").symlink_to(real)
    with pytest.raises(SafeTestLoadError, match="symlink"):
        load_safe_test_templates(root)


def test_missing_safe_tests_root_is_rejected(tmp_path: Path) -> None:
    """Regression for Codex#8 (round 5, 2026-09-12), reproduced exactly as
    reported: `load_safe_test_templates("/typo'd/path")` used to silently
    return `{}` - a "valid", empty catalogue - instead of a load error. A
    misconfigured/missing SKOS_SAFE_TESTS_ROOT must fail loudly, the same
    way a missing rules root already does (Codex cross-review finding #1,
    2026-09-11)."""
    with pytest.raises(SafeTestLoadError, match="does not exist"):
        load_safe_test_templates(tmp_path / "no-such-dir")


def test_safe_tests_root_that_is_a_file_is_rejected(tmp_path: Path) -> None:
    """Regression for Codex#8 (round 5, 2026-09-12), reproduced exactly as
    reported: `load_safe_test_templates("README.md")` (a file, not a
    directory) also used to silently return `{}`."""
    f = tmp_path / "README.md"
    f.write_text("not a safe-test directory", encoding="utf-8")
    with pytest.raises(SafeTestLoadError, match="not a directory"):
        load_safe_test_templates(f)


def _rule(**over: object) -> RiskRule:
    data: dict[str, object] = {
        "id": "PI-900",
        "title": "t",
        "category": KnowledgeCategory.PROMPT_SECURITY,
        "severity": Severity.HIGH,
    }
    data.update(over)
    return RiskRule.model_validate(data)


def test_unresolved_safe_test_references_reports_a_broken_reference() -> None:
    """Regression for Codex#8 (round 5, 2026-09-12): a rule's
    safe_test_template that does not resolve in the loaded templates - a
    typo, or the whole catalogue silently emptied by a misconfigured root -
    used to fail SILENTLY (assess.py's _safe_tests_for() just skips a
    missing template). This is the loud, load-time counterpart."""
    rule = _rule(safe_test_template="ST-DOES-NOT-EXIST")
    assert unresolved_safe_test_references([rule], {}) == ["PI-900 -> ST-DOES-NOT-EXIST"]


def test_unresolved_safe_test_references_is_empty_when_everything_resolves(
    safe_test_templates,
) -> None:
    rule = _rule(safe_test_template=next(iter(safe_test_templates)))
    assert unresolved_safe_test_references([rule], safe_test_templates) == []


def test_unresolved_safe_test_references_ignores_rules_with_no_template() -> None:
    rule = _rule()  # safe_test_template defaults to None
    assert unresolved_safe_test_references([rule], {}) == []
