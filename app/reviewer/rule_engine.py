"""Deterministic rule evaluation (spec Section 12, step 6).

No LLM, no ``eval``: every decision is a fixed comparison over the fact dict.

Verdict ordering guarantees AC-19 - a rule is never ``PASS`` while any check was
UNKNOWN or any required evidence was missing:

    missing evidence            -> UNKNOWN
    cannot tell if rule applies  -> UNKNOWN  (high/critical only)
    a safety check is FALSE      -> FAIL (high/critical) or WARN
    a safety check is UNKNOWN    -> UNKNOWN
    all checks TRUE + manual_review -> WARN
    all checks TRUE             -> PASS  (suppressed if the rule has no checks)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, auto

from app.models.risk import Evidence, Finding, FindingStatus, RiskRule, RuleConditions, Severity
from app.models.rule_clause import Clause
from app.reviewer.clause_eval import evaluate_clause
from app.reviewer.facts import Fact

_SEVERE = {Severity.HIGH, Severity.CRITICAL}


class Applicability(StrEnum):
    TRIGGERED = auto()
    NOT_APPLICABLE = auto()
    INDETERMINATE = auto()


def _outcomes(clauses: list[Clause], facts: dict[str, Fact]) -> list[str]:
    return [evaluate_clause(clause, facts).value for clause in clauses]


def evaluate_conditions(conditions: RuleConditions, facts: dict[str, Fact]) -> Applicability:
    all_outcomes = _outcomes(conditions.all, facts)
    if "false" in all_outcomes:
        return Applicability.NOT_APPLICABLE

    if conditions.any:
        any_outcomes = _outcomes(conditions.any, facts)
        if "true" in any_outcomes:
            any_ok = True
        elif all(outcome == "false" for outcome in any_outcomes):
            return Applicability.NOT_APPLICABLE
        else:
            any_ok = False
    else:
        any_ok = True

    if all(outcome == "true" for outcome in all_outcomes) and any_ok:
        return Applicability.TRIGGERED
    return Applicability.INDETERMINATE


def _emit_indeterminate(rule: RiskRule, facts: dict[str, Fact]) -> bool:
    """Applicability-unknown policy.

    high / critical: always surface an UNKNOWN - never let missing evidence read
    as "not applicable".
    medium / low: surface an UNKNOWN only when at least one trigger clause is
    already TRUE (a relevant attack surface is present); if every trigger clause
    is itself undetermined there is no signal to report and we suppress.
    """
    if rule.severity in _SEVERE:
        return True
    return "true" in _outcomes([*rule.conditions.all, *rule.conditions.any], facts)


def _evidence(rule: RiskRule) -> list[Evidence]:
    seen: list[str] = []
    for clause in rule.clauses():
        if clause.field not in seen:
            seen.append(clause.field)
    return [Evidence(field=name) for name in seen]


@dataclass
class RuleEvaluation:
    rule: RiskRule
    applicability: Applicability
    missing_evidence: list[str] = field(default_factory=list)
    undetermined_fields: list[str] = field(default_factory=list)
    finding: Finding | None = None


def evaluate_rule(
    rule: RiskRule, facts: dict[str, Fact], available_evidence: set[str]
) -> RuleEvaluation:
    applicability = evaluate_conditions(rule.conditions, facts)
    missing = [key for key in rule.required_evidence if key not in available_evidence]
    ev = RuleEvaluation(rule=rule, applicability=applicability, missing_evidence=missing)

    if applicability is Applicability.NOT_APPLICABLE:
        return ev

    if applicability is Applicability.INDETERMINATE:
        trigger_clauses = [*rule.conditions.all, *rule.conditions.any]
        ev.undetermined_fields = [
            clause.field
            for clause, outcome in zip(
                trigger_clauses, _outcomes(trigger_clauses, facts), strict=True
            )
            if outcome == "unknown"
        ]
        if _emit_indeterminate(rule, facts):
            ev.finding = _finding(
                rule,
                FindingStatus.UNKNOWN,
                "cannot determine whether this rule applies; undetermined: "
                f"{ev.undetermined_fields}",
                limitations=["applicability could not be established from the input"],
            )
        return ev

    if missing:
        ev.finding = _finding(
            rule,
            FindingStatus.UNKNOWN,
            f"required evidence not provided: {sorted(missing)}",
            limitations=[f"cannot evaluate without: {sorted(missing)}"],
        )
        return ev

    paired = list(zip(rule.checks, _outcomes(rule.checks, facts), strict=True))
    failed = [clause.describe() for clause, outcome in paired if outcome == "false"]
    unknown = [clause.describe() for clause, outcome in paired if outcome == "unknown"]

    if failed:
        status = FindingStatus.FAIL if rule.severity in _SEVERE else FindingStatus.WARN
        ev.finding = _finding(
            rule,
            status,
            f"safety check failed: {failed}",
            residual_risk="the checked mitigation is absent",
        )
    elif unknown:
        ev.finding = _finding(
            rule,
            FindingStatus.UNKNOWN,
            f"safety check could not be determined: {unknown}",
            limitations=[f"undetermined checks: {unknown}"],
        )
    elif rule.manual_review:
        ev.finding = _finding(
            rule,
            FindingStatus.WARN,
            "structural risk is present; the mitigating controls cannot be verified "
            "deterministically and need manual review",
            limitations=["mitigation effectiveness not verified by the deterministic engine"],
            residual_risk="depends on controls this engine cannot inspect",
        )
    elif rule.checks:
        ev.finding = _finding(rule, FindingStatus.PASS, "all deterministic safety checks passed")

    return ev


def _finding(
    rule: RiskRule,
    status: FindingStatus,
    reasoning: str,
    *,
    limitations: list[str] | None = None,
    residual_risk: str | None = None,
) -> Finding:
    return Finding(
        risk_id=rule.id,
        title=rule.title,
        severity=rule.severity,
        status=status,
        origin="rule",
        evidence=_evidence(rule),
        reasoning_summary=reasoning,
        limitations=limitations or [],
        residual_risk=residual_risk,
    )


def evaluate_rules_detailed(
    rules: list[RiskRule], facts: dict[str, Fact], available_evidence: set[str]
) -> list[RuleEvaluation]:
    return [evaluate_rule(rule, facts, available_evidence) for rule in rules]


def evaluate_rules(
    rules: list[RiskRule], facts: dict[str, Fact], available_evidence: set[str]
) -> list[Finding]:
    return [
        ev.finding
        for ev in evaluate_rules_detailed(rules, facts, available_evidence)
        if ev.finding is not None
    ]
