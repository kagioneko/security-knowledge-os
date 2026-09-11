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
        "required_evidence: [not_a_real_key]\n",
    )
    with pytest.raises(RuleLoadError, match="required_evidence"):
        load_rules(root)


def test_bad_operator_is_rejected(tmp_path: Path) -> None:
    root = _write_rule(
        tmp_path,
        "id: X-003\ntitle: t\ncategory: agent-security\nseverity: low\n"
        "checks:\n  - field: external_content_ingestion\n    op: regex\n    value: x\n",
    )
    with pytest.raises(RuleLoadError):
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
