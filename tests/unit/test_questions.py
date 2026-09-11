"""app/reviewer/questions.py::build_missing_information.

Regression for SKOS-ADV-02 (Antigravity cross-review, 2026-09-11): a medium/low
rule whose trigger clauses are ALL undetermined is intentionally suppressed
(rule_engine._emit_indeterminate - no finding is worth emitting when there is no
signal at all). But the operator must still be able to resolve the ambiguity:
skipping the whole evaluation (instead of skipping only the truly
NOT_APPLICABLE ones) silently dropped the clarifying question too.
"""

from __future__ import annotations

from app.models.knowledge import KnowledgeCategory
from app.models.risk import RiskRule, RuleConditions, Severity
from app.models.rule_clause import Clause, Operator
from app.reviewer.questions import build_missing_information
from app.reviewer.rule_engine import evaluate_rule


def _medium_rule() -> RiskRule:
    return RiskRule(
        id="TST-002",
        title="test rule",
        category=KnowledgeCategory.AGENT_SECURITY,
        severity=Severity.MEDIUM,
        conditions=RuleConditions(
            all=[
                Clause(field="tools_present", op=Operator.EQ, value=True),
                Clause(field="external_content_ingestion", op=Operator.EQ, value=True),
            ]
        ),
    )


def test_suppressed_medium_rule_still_asks_its_clarifying_question() -> None:
    facts = {"tools_present": None, "external_content_ingestion": None}
    ev = evaluate_rule(_medium_rule(), facts, available_evidence=set())
    assert ev.finding is None  # confirms the suppression path (see test_rule_engine.py)

    missing = build_missing_information([ev])
    fields = {m.field for m in missing}
    assert "tools_present" in fields
    assert "external_content_ingestion" in fields
    for item in missing:
        assert "TST-002" in item.related_rule_ids


def test_not_applicable_rule_asks_nothing() -> None:
    facts = {"tools_present": False, "external_content_ingestion": None}
    ev = evaluate_rule(_medium_rule(), facts, available_evidence=set())
    assert ev.finding is None
    assert build_missing_information([ev]) == []
