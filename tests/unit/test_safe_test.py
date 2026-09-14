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
        # Codex#3 (round 14, 2026-09-13), reproduced exactly as reported:
        # preconditions was not scanned at all; non-http(s) schemes and
        # bare hostnames were not recognized as destinations; only AWS/
        # private-key/Slack shapes (not the fuller shared credential-shape
        # list) were recognized as secrets.
        ("preconditions", ["use production DB at https://attacker.evil"]),
        ("steps", ["exfiltrate via ftp://evil.example"]),
        ("steps", ["exfiltrate via gopher://evil.example/"]),
        ("steps", ["connect to evil.example directly, no scheme needed"]),
        ("steps", ["the leaked value was sk-proj-" + "A" * 40]),
        ("steps", ["the leaked value was AIza" + "B" * 35]),
        # Codex#4 (round 15, 2026-09-14), reproduced exactly as reported:
        # the old `.split(":")[0]` truncation treated USERINFO (the part
        # before "@" in "user:pass@host") as the destination host, so a
        # URL with an attacker host hidden behind innocuous-looking
        # userinfo passed unrecognized.
        ("steps", ["curl https://localhost:443@attacker.com/x"]),
        # Codex#4 (round 15, 2026-09-14): a bare (schemeless) IPv6 literal
        # matched neither the old URI-authority nor bare-hostname
        # alternative (colon-separated hex groups, not dot-separated
        # labels).
        ("steps", ["connect to 2606:4700:4700::1111 directly"]),
    ],
)
def test_dangerous_content_is_blocked(field: str, value: list[str]) -> None:
    decision = validate_safe_test(_base(**{field: value}))
    assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert decision.reasons


def test_userinfo_does_not_mask_the_real_host_in_a_url() -> None:
    """Regression for Codex#4 (round 15, 2026-09-14), reproduced exactly
    as reported: `https://localhost:443@attacker.com/x` used to be
    truncated at the first ":" to just "localhost" (a _SAFE_HOST), so the
    real destination - attacker.com, after the "@" - was never inspected
    at all. The blocked reason must name the ACTUAL host, not the
    userinfo standing in front of it."""
    decision = validate_safe_test(
        _base(steps=["curl https://localhost:443@attacker.com/x"])
    )
    assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert any("attacker.com" in reason for reason in decision.reasons)


def test_bare_ipv6_loopback_is_allowed_like_127_0_0_1() -> None:
    """Mirror case for the round-15 IPv6 fix: ::1 (the IPv6 loopback,
    exactly as trusted as 127.0.0.1) must not be flagged."""
    decision = validate_safe_test(_base(steps=["connect to ::1 for the sandboxed check"]))
    assert decision.outcome is PolicyOutcome.ALLOWED


def test_malformed_bracketed_ipv6_authority_fails_closed_not_a_raw_valueerror() -> None:
    """Regression for Codex#4 / Antigravity SKOS-ADV-19 (round 17,
    2026-09-14), reproduced exactly as reported: `urlsplit(...).hostname`
    raises `ValueError` for a malformed bracketed IPv6 authority (e.g.
    "http://[:::]") - uncaught here, `validate_safe_test()` raised
    instead of returning the documented fail-closed `PolicyDecision`,
    surfacing as an untyped 500 from any API path that reaches it."""
    decision = validate_safe_test(_base(steps=["visit http://[:::] for the check"]))
    assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert any("malformed" in reason for reason in decision.reasons)


@pytest.mark.parametrize(
    "field,value",
    [
        ("expected_secure_behavior", "the agent contacts prod-api.internal"),
        ("failure_condition", "the key AKIAIOSFODNN7EXAMPLE was read"),
    ],
)
def test_the_two_free_text_outcome_fields_are_also_scanned(field: str, value: str) -> None:
    """Regression for Codex#3 (round 14, 2026-09-13): expected_secure_
    behavior and failure_condition (both plain strings, not lists) were
    not scanned at all."""
    decision = validate_safe_test(_base(**{field: value}))
    assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert decision.reasons


def test_the_findings_own_repro_across_every_omitted_field_is_blocked() -> None:
    """Regression for Codex#3 (round 14, 2026-09-13): this is the finding's
    own exact repro shape - a single test combining an unscanned field
    (preconditions), a destination missed by the old http(s)-only/email-
    only pattern (a bare hostname with no scheme), and a secret shape
    already in CREDENTIAL_SHAPE_PATTERNS but not in the old hand-rolled
    list - used to validate as ALLOWED."""
    test = _base(
        preconditions=[
            "use production DB at https://attacker.evil with AKIAIOSFODNN7EXAMPLE"
        ],
        steps=["inspect locally"],
    )
    decision = validate_safe_test(test)
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


def test_ancestor_directory_confinement_is_enforced(tmp_path: Path) -> None:
    """Regression for Codex#5 (round 8, 2026-09-12), reproduced exactly as
    reported: O_NOFOLLOW on the final read (Codex#2, round 7) protects only
    the LAST pathname component - `rglob()`'s own directory walk and the
    later open both re-resolve the full path from scratch, so a symlinked
    ANCESTOR directory under `root` was silently followed straight through
    to a file entirely outside it. load_safe_test_templates() now
    snapshots `root` the same no-follow-at-every-level way
    app/ingestion/snapshot.py already does for the knowledge corpus,
    closing this the same way round 7 closed it there.

    NOTE: this test is deliberately NOT named with "symlink" in it - see
    the identical note on test_rule_loader.py's
    test_ancestor_directory_confinement_is_enforced: pytest's `tmp_path`
    fixture names the temp directory after the TEST FUNCTION itself, so a
    test named e.g. "...symlinked..." would make a plain match="symlink"
    trivially satisfiable by that path fragment alone, independent of
    whether the fix actually works. Matching on load_safe_test_templates()'s
    own wrapper message avoids that trap; here the pre-fix behaviour was
    "DID NOT RAISE" at all (rglob() silently finding nothing through the
    unfollowed symlinked directory), so it happens not to have been
    vulnerable to that specific trap, but the same fix-specific match
    string is used for consistency and to guard against a future pre-fix
    message that DOES embed the tmp_path."""
    root = tmp_path / "safe_tests"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "st.yaml").write_text(
        "id: ST-X-901\ntitle: OUTSIDE\nrisk_id: PI-003\norigin: template\n"
        "environment: [sandbox]\nscope: s\nsteps: [a]\nsuccess_criteria: c\n"
        "requires_human_approval: true\n",
        encoding="utf-8",
    )
    (root / "nested").symlink_to(outside, target_is_directory=True)

    with pytest.raises(SafeTestLoadError, match="could not safely read the safe-tests directory"):
        load_safe_test_templates(root)


def test_deeply_nested_safe_test_yaml_fails_closed_not_a_raw_recursionerror(
    tmp_path: Path,
) -> None:
    """Regression for Codex#5 (round 7, 2026-09-12), reproduced exactly as
    reported: plain yaml.safe_load() had none of the merge-key ban / size
    cap / RecursionError handling the knowledge front-matter loader already
    had - roughly 1,500 nested YAML collections raised an uncaught
    RecursionError straight out of load_safe_test_templates()."""
    root = tmp_path / "safe_tests"
    root.mkdir()
    nested = "x: " + "[" * 1500 + "]" * 1500
    (root / "bad.yaml").write_text(nested, encoding="utf-8")
    with pytest.raises(SafeTestLoadError, match="deeply nested"):
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
