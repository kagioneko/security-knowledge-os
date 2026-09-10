"""Finding roll-up and the LLM merge boundary (decisions A6 and A8)."""

from __future__ import annotations

from app.models.assessment import OverallStatus
from app.models.risk import Finding, FindingStatus

# Decision A6: FAIL > CONDITIONAL(WARN) > UNKNOWN > PASS
_STATUS_TO_OVERALL = {
    FindingStatus.FAIL: OverallStatus.FAIL,
    FindingStatus.WARN: OverallStatus.CONDITIONAL,
    FindingStatus.UNKNOWN: OverallStatus.UNKNOWN,
}
_OVERALL_ORDER = [
    OverallStatus.FAIL,
    OverallStatus.CONDITIONAL,
    OverallStatus.UNKNOWN,
    OverallStatus.PASS,
]


def compute_overall_status(findings: list[Finding]) -> OverallStatus:
    worst = OverallStatus.PASS
    for finding in findings:
        candidate = _STATUS_TO_OVERALL.get(finding.status, OverallStatus.PASS)
        if _OVERALL_ORDER.index(candidate) < _OVERALL_ORDER.index(worst):
            worst = candidate
    return worst


def requires_human_review(
    findings: list[Finding],
    *,
    high_impact_present: bool,
    confidential_knowledge_used: bool,
) -> bool:
    if high_impact_present or confidential_knowledge_used:
        return True
    flagged = {FindingStatus.FAIL, FindingStatus.WARN, FindingStatus.UNKNOWN}
    return any(
        finding.status in flagged or finding.origin == "llm" for finding in findings
    )


def merge_findings(
    rule_findings: list[Finding], llm_findings: list[Finding]
) -> list[Finding]:
    """Decision A8: the LLM layer may only *add* ``LLM-OBS-*`` observations. It can
    never modify, remove, or shadow a deterministic finding.

    (The ``Finding`` model already caps LLM findings at WARN/UNKNOWN; this function
    additionally refuses any LLM finding that collides with a rule ``risk_id``.)
    """
    rule_ids = {finding.risk_id for finding in rule_findings}
    merged = list(rule_findings)
    for finding in llm_findings:
        if finding.origin != "llm":
            raise ValueError("merge_findings only accepts origin='llm' findings as additions")
        if finding.risk_id in rule_ids:
            raise ValueError(
                f"LLM finding {finding.risk_id} collides with a deterministic finding"
            )
        merged.append(finding)
    return merged
