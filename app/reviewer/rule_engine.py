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


def _evidence(rule: RiskRule) -> list[Evidence]:
    seen: list[str] = []
    for clause in rule.clauses():
        if clause.field not in seen:
            seen.append(clause.field)
    return [Evidence(field=name) for name in seen]


def evaluate_rule(
    rule: RiskRule, facts: dict[str, Fact], available_evidence: set[str]
) -> Finding | None:
    applicability = evaluate_conditions(rule.conditions, facts)
    if applicability is Applicability.NOT_APPLICABLE:
        return None

    missing = [key for key in rule.required_evidence if key not in available_evidence]

    if applicability is Applicability.INDETERMINATE:
        if rule.severity not in _SEVERE:
            return None
        return _finding(
            rule,
            FindingStatus.UNKNOWN,
            "cannot determine whether this rule applies; "
            f"undetermined: {[c.describe() for c in rule.conditions.all + rule.conditions.any]}",
            limitations=["applicability of this rule could not be established from the input"],
        )

    if missing:
        return _finding(
            rule,
            FindingStatus.UNKNOWN,
            f"required evidence not provided: {sorted(missing)}",
            limitations=[f"cannot evaluate without: {sorted(missing)}"],
        )

    paired = list(zip(rule.checks, _outcomes(rule.checks, facts), strict=True))
    failed = [clause.describe() for clause, outcome in paired if outcome == "false"]
    unknown = [clause.describe() for clause, outcome in paired if outcome == "unknown"]

    if failed:
        status = FindingStatus.FAIL if rule.severity in _SEVERE else FindingStatus.WARN
        return _finding(
            rule,
            status,
            f"safety check failed: {failed}",
            residual_risk="the checked mitigation is absent",
        )

    if unknown:
        return _finding(
            rule,
            FindingStatus.UNKNOWN,
            f"safety check could not be determined: {unknown}",
            limitations=[f"undetermined checks: {unknown}"],
        )

    if rule.manual_review:
        return _finding(
            rule,
            FindingStatus.WARN,
            "structural risk is present; the mitigating controls cannot be verified "
            "deterministically and need manual review",
            limitations=["mitigation effectiveness not verified by the deterministic engine"],
            residual_risk="depends on controls this engine cannot inspect",
        )

    if not rule.checks:
        return None  # nothing to assert, nothing to report

    return _finding(rule, FindingStatus.PASS, "all deterministic safety checks passed")


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


def evaluate_rules(
    rules: list[RiskRule], facts: dict[str, Fact], available_evidence: set[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules:
        finding = evaluate_rule(rule, facts, available_evidence)
        if finding is not None:
            findings.append(finding)
    return findings
