"""M3: rule engine unit behaviour, including the applicability-unknown policy."""

from __future__ import annotations

from app.models.knowledge import KnowledgeCategory
from app.models.risk import FindingStatus, RiskRule, RuleConditions, Severity
from app.models.rule_clause import Clause, Operator
from app.reviewer.rule_engine import Applicability, evaluate_conditions, evaluate_rule


def _rule(
    severity: Severity,
    all_clauses: list[Clause],
    checks: list[Clause] | None = None,
) -> RiskRule:
    return RiskRule(
        id="TST-001",
        title="test rule",
        category=KnowledgeCategory.AGENT_SECURITY,
        severity=severity,
        conditions=RuleConditions(all=all_clauses),
        checks=checks or [],
    )


C_TRUE = Clause(field="tools_present", op=Operator.EQ, value=True)
C_UNKNOWN = Clause(field="external_content_ingestion", op=Operator.EQ, value=True)


def test_conditions_not_applicable_on_false() -> None:
    facts = {"tools_present": False}
    rule = _rule(Severity.HIGH, [C_TRUE])
    assert evaluate_conditions(rule.conditions, facts) is Applicability.NOT_APPLICABLE


def test_conditions_indeterminate_on_unknown() -> None:
    facts = {"tools_present": True, "external_content_ingestion": None}
    rule = _rule(Severity.HIGH, [C_TRUE, C_UNKNOWN])
    assert evaluate_conditions(rule.conditions, facts) is Applicability.INDETERMINATE


def test_high_rule_emits_unknown_when_applicability_indeterminate() -> None:
    facts = {"tools_present": True, "external_content_ingestion": None}
    rule = _rule(Severity.HIGH, [C_TRUE, C_UNKNOWN])
    finding = evaluate_rule(rule, facts, available_evidence=set()).finding
    assert finding is not None and finding.status is FindingStatus.UNKNOWN


def test_medium_rule_emits_unknown_when_a_trigger_clause_is_true() -> None:
    facts = {"tools_present": True, "external_content_ingestion": None}
    rule = _rule(Severity.MEDIUM, [C_TRUE, C_UNKNOWN])
    finding = evaluate_rule(rule, facts, available_evidence=set()).finding
    assert finding is not None and finding.status is FindingStatus.UNKNOWN


def test_medium_rule_suppressed_when_every_trigger_is_undetermined() -> None:
    facts = {"tools_present": None, "external_content_ingestion": None}
    rule = _rule(
        Severity.MEDIUM,
        [C_UNKNOWN, Clause(field="tools_present", op=Operator.EQ, value=True)],
    )
    assert evaluate_rule(rule, facts, available_evidence=set()).finding is None


def test_check_unknown_never_becomes_pass() -> None:
    facts = {"tools_present": True, "has_delete_tool": None}
    rule = _rule(
        Severity.HIGH,
        [C_TRUE],
        checks=[Clause(field="has_delete_tool", op=Operator.EQ, value=False)],
    )
    finding = evaluate_rule(rule, facts, available_evidence=set()).finding
    assert finding is not None and finding.status is FindingStatus.UNKNOWN


def test_condition_only_rule_with_no_checks_fails_closed_not_silent() -> None:
    """Regression for Codex#1 (round 8, 2026-09-12), reproduced exactly as
    reported: a rule with a matched trigger condition, no checks, and
    manual_review=False used to produce `finding is None` here (a silent,
    unlogged PASS - this test used to be named
    `test_vacuous_pass_is_suppressed` and asserted exactly that). No
    required_evidence is missing (there is none declared), so this is
    genuinely the "conditions matched, nothing left to check" state, not a
    missing-evidence case. `rule_loader.py` now rejects this shape at load
    time, but `RiskRule` can still be constructed directly (as this test
    does), so the engine itself must also fail closed rather than stay
    silent."""
    facts = {"tools_present": True}

    high_rule = _rule(Severity.HIGH, [C_TRUE], checks=[])
    finding = evaluate_rule(high_rule, facts, available_evidence=set()).finding
    assert finding is not None and finding.status is FindingStatus.FAIL

    low_rule = _rule(Severity.LOW, [C_TRUE], checks=[])
    warn_finding = evaluate_rule(low_rule, facts, available_evidence=set()).finding
    assert warn_finding is not None and warn_finding.status is FindingStatus.WARN
