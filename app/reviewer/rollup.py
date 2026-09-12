"""Finding roll-up and the LLM merge boundary (decisions A6 and A8)."""

from __future__ import annotations

from app.models.assessment import OverallStatus
from app.models.risk import LLM_OBS_PREFIX, Finding, FindingStatus

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
    missing_information_present: bool = False,
) -> bool:
    # SKOS-ADV-07 (Antigravity, round 2, 2026-09-11): a medium/low rule whose
    # trigger clauses are ALL undetermined is deliberately left with no
    # Finding (rule_engine._emit_indeterminate - no signal worth a finding),
    # but questions.py::build_missing_information() still surfaces the
    # clarifying question in `missing_information` (fix for the round-1
    # ADV-02 gap). With zero findings, this function previously had nothing
    # to key on and returned False: an automated consumer reading only
    # overall_status/human_review_required would see a clean PASS despite an
    # open question about the rule's applicability. Unanswered
    # missing_information is itself a reason a human should look.
    if high_impact_present or confidential_knowledge_used or missing_information_present:
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
        # Codex#11 (round 7, 2026-09-12): Finding._enforce_llm_boundary
        # already caps this at construction time, but `model_copy(update=
        # ...)` bypasses pydantic validators regardless of `frozen=True`
        # (a documented, accepted library-level limitation) - independently
        # re-verifying the A8 invariant HERE, at the merge boundary, means
        # it holds regardless of how an LLM-origin Finding was constructed,
        # not only for the one construction path this app's own code uses.
        if finding.status not in (FindingStatus.WARN, FindingStatus.UNKNOWN):
            raise ValueError(
                f"LLM finding {finding.risk_id} has status {finding.status} - "
                "LLM-origin findings must be capped at WARN or UNKNOWN (decision A8)"
            )
        if not finding.risk_id.startswith(LLM_OBS_PREFIX):
            raise ValueError(
                f"LLM finding {finding.risk_id!r} must use the {LLM_OBS_PREFIX!r} prefix"
            )
        if finding.risk_id in rule_ids:
            raise ValueError(
                f"LLM finding {finding.risk_id} collides with a deterministic finding"
            )
        merged.append(finding)
    return merged
