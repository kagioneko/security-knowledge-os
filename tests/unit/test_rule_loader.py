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
