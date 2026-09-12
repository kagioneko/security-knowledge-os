"""M3: rule catalogue loading and validation (fail-closed)."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.models.rule_clause import Operator
from app.reviewer.rule_loader import RuleCatalogue, RuleLoadError, load_rules, parse_clause


def test_real_catalogue_loads(catalogue: RuleCatalogue) -> None:
    ids = sorted(rule.id for rule in catalogue.rules)
    assert ids == ["CRED-001", "GOV-001", "MEM-001", "OUT-001", "PI-003", "TOOL-000", "TOOL-001"]


def test_every_rule_clause_is_data_only(catalogue: RuleCatalogue) -> None:
    for rule in catalogue.rules:
        for clause in rule.clauses():
            assert clause.op in set(Operator)
            assert isinstance(clause.field, str)


def test_shorthand_clause_becomes_eq() -> None:
    clause = parse_clause({"external_content_ingestion": True})
    assert clause.field == "external_content_ingestion"
    assert clause.op is Operator.EQ
    assert clause.value is True


def test_explicit_clause_form() -> None:
    clause = parse_clause({"field": "credential_storage", "op": "in", "value": ["env"]})
    assert clause.op is Operator.IN


def _write_rule(tmp_path: Path, body: str) -> Path:
    root = tmp_path / "rules"
    root.mkdir()
    (root / "r.yaml").write_text(body, encoding="utf-8")
    return root


def test_unknown_fact_is_rejected(tmp_path: Path) -> None:
    root = _write_rule(
        tmp_path,
        "id: X-001\ntitle: t\ncategory: agent-security\nseverity: low\n"
        "conditions:\n  all:\n    - made_up_fact: true\n",
    )
    with pytest.raises(RuleLoadError, match="unknown fact"):
        load_rules(root)


def test_unknown_evidence_key_is_rejected(tmp_path: Path) -> None:
    root = _write_rule(
        tmp_path,
        "id: X-002\ntitle: t\ncategory: agent-security\nseverity: low\n"
        "checks: [{outbound_enabled: true}]\n"
        "required_evidence: [not_a_real_key]\n",
    )
    with pytest.raises(RuleLoadError, match="required_evidence"):
        load_rules(root)


def test_a_rule_with_no_conditions_or_checks_is_rejected(tmp_path: Path) -> None:
    """Regression for Codex#3 (round 7, 2026-09-12), reproduced exactly as
    reported: a rule with empty conditions, checks, and manual_review=False
    satisfies the non-empty-catalogue check but can never produce a
    finding - assessing against a catalogue containing only such a rule
    returned 0 findings, 0 missing-information, indistinguishable from
    "nothing worth reporting" rather than "this rule is a no-op"."""
    root = _write_rule(
        tmp_path,
        "id: NOOP-001\ntitle: No-op rule\ncategory: governance\nseverity: high\n",
    )
    with pytest.raises(RuleLoadError, match="can never produce a finding"):
        load_rules(root)


def test_a_manual_review_rule_with_no_checks_is_allowed(tmp_path: Path) -> None:
    """An always-flag-for-human-review rule with no automated checks is a
    legitimate, intentional pattern - not the same inert no-op as above."""
    root = _write_rule(
        tmp_path,
        "id: MANUAL-001\ntitle: Always flag for review\ncategory: governance\n"
        "severity: high\nmanual_review: true\n",
    )
    catalogue = load_rules(root)
    assert catalogue.by_id("MANUAL-001").manual_review is True


def test_a_rule_id_using_the_reserved_llm_obs_prefix_is_rejected(tmp_path: Path) -> None:
    """Regression for Codex#3 (round 7, 2026-09-12), reproduced exactly as
    reported: `id: LLM-OBS-00001` matches RiskRule's id pattern and loaded
    successfully, but later crashed with an unhandled ValidationError the
    moment this rule actually fired and a Finding(origin="rule",
    risk_id="LLM-OBS-00001") was constructed - Finding._enforce_llm_boundary
    reserves that prefix for origin='llm' findings. Reject it at load time."""
    root = _write_rule(
        tmp_path,
        "id: LLM-OBS-00001\ntitle: t\ncategory: governance\nseverity: high\n"
        "checks: [{outbound_enabled: true}]\n",
    )
    with pytest.raises(RuleLoadError, match="reserved"):
        load_rules(root)


def test_bad_operator_is_rejected(tmp_path: Path) -> None:
    root = _write_rule(
        tmp_path,
        "id: X-003\ntitle: t\ncategory: agent-security\nseverity: low\n"
        "checks:\n  - field: external_content_ingestion\n    op: regex\n    value: x\n",
    )
    with pytest.raises(RuleLoadError):
        load_rules(root)


def test_conditions_false_is_rejected_not_silently_emptied(tmp_path: Path) -> None:
    """Regression for Codex cross-review finding #1 (round 4, 2026-09-12),
    reproduced exactly as reported: `payload.get("conditions", {}) or {}`
    treated an explicit `conditions: false` the same as "conditions absent"
    (both falsy to `or`), silently normalizing it into an empty - vacuously
    TRUE, since an empty 'all' list always matches - condition set instead
    of rejecting the malformed value. Omitting `conditions` entirely stays
    legal (see other tests in this file); an explicit wrong-typed value must
    not be."""
    root = _write_rule(
        tmp_path,
        "id: X-010\ntitle: t\ncategory: agent-security\nseverity: low\nconditions: false\n",
    )
    with pytest.raises(RuleLoadError, match="conditions"):
        load_rules(root)


def test_checks_wrong_type_is_rejected_not_silently_emptied(tmp_path: Path) -> None:
    """Regression for Codex cross-review finding #1, part 2 (round 4,
    2026-09-12), reproduced exactly as reported: `checks: {}` iterates an
    empty dict (zero key/value pairs) instead of being rejected as "not a
    list" - silently normalizing a malformed `checks` into no checks at
    all."""
    root = _write_rule(
        tmp_path,
        "id: X-011\ntitle: t\ncategory: agent-security\nseverity: low\nchecks: {}\n",
    )
    with pytest.raises(RuleLoadError, match="checks"):
        load_rules(root)


def test_duplicate_rule_id_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "rules"
    root.mkdir()
    text = "id: X-004\ntitle: t\ncategory: agent-security\nseverity: low\n"
    (root / "a.yaml").write_text(text, encoding="utf-8")
    (root / "b.yaml").write_text(text, encoding="utf-8")
    with pytest.raises(RuleLoadError, match="duplicate"):
        load_rules(root)


def test_missing_rules_root_is_rejected(tmp_path: Path) -> None:
    """Regression for Codex cross-review finding #1 (2026-09-11): a rule root
    that does not exist used to silently load an empty catalogue -> every
    assessment evaluated zero rules and settled on a false PASS. Must be a hard
    load error instead."""
    with pytest.raises(RuleLoadError, match="does not exist"):
        load_rules(tmp_path / "no-such-dir")


def test_rules_root_that_is_a_file_is_rejected(tmp_path: Path) -> None:
    f = tmp_path / "not-a-dir.yaml"
    f.write_text("id: X-005\n", encoding="utf-8")
    with pytest.raises(RuleLoadError, match="not a directory"):
        load_rules(f)


def test_empty_rules_root_is_rejected(tmp_path: Path) -> None:
    """A directory that exists but contains no rule YAML files must also be a
    hard error - the same false-PASS risk as a missing directory."""
    root = tmp_path / "rules"
    root.mkdir()
    with pytest.raises(RuleLoadError, match="no rule files"):
        load_rules(root)


def test_unknown_key_under_conditions_is_rejected(tmp_path: Path) -> None:
    """Regression for Codex cross-review finding #9 (2026-09-11): a misspelled
    key under 'conditions' (e.g. 'alll' instead of 'all') used to be silently
    dropped by the shorthand-conversion step, leaving the rule with an empty
    'all'/'any' - which is vacuously TRIGGERED for every assessment - instead
    of raising, even though RuleConditions itself has extra='forbid'."""
    root = _write_rule(
        tmp_path,
        "id: X-007\ntitle: t\ncategory: agent-security\nseverity: low\n"
        "conditions:\n  alll:\n    - tools_present: true\n",
    )
    with pytest.raises(RuleLoadError, match="conditions"):
        load_rules(root)


def test_symlinked_rule_file_is_rejected(tmp_path: Path) -> None:
    """Codex cross-review finding #2 (2026-09-11): confinement must be
    consistent across knowledge/rule/safe-test loaders."""
    real = tmp_path / "outside.yaml"
    real.write_text(
        "id: X-006\ntitle: t\ncategory: agent-security\nseverity: low\n", encoding="utf-8"
    )
    root = tmp_path / "rules"
    root.mkdir()
    (root / "linked.yaml").symlink_to(real)
    with pytest.raises(RuleLoadError, match="symlink"):
        load_rules(root)
