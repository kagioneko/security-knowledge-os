"""Initial evaluation metrics (spec Section 24).

Each fixture is labelled by its folder: ``vulnerable`` / ``safe`` / ``unknown``.
The metrics say whether the deterministic engine (plus whatever knowledge is
indexed) separates those three the way it should, and whether every finding is
grounded and every attached safe test is safe.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.models.assessment import AssessmentResult, OverallStatus
from app.policy.safe_test import validate_safe_test
from app.reviewer.rule_loader import RuleCatalogue


@dataclass
class LabelledResult:
    label: str  # "vulnerable" | "safe" | "unknown"
    result: AssessmentResult


@dataclass
class EvalMetrics:
    n_vulnerable: int = 0
    n_safe: int = 0
    n_unknown: int = 0
    known_risk_recall: float = 0.0
    false_positive_rate: float = 0.0
    unknown_appropriateness: float = 0.0
    evidence_coverage: float = 0.0
    citation_source_match: float | None = None
    safe_test_safety_violations: int = 0
    human_review_correction_rate: float | None = None  # needs human labels; not in MVP
    notes: list[str] = field(default_factory=list)

    @property
    def gates_pass(self) -> bool:
        # Codex#6 (round 12, 2026-09-13), reproduced exactly as reported:
        # this checked only false_positive_rate and
        # safe_test_safety_violations - known_risk_recall,
        # unknown_appropriateness, and evidence_coverage were computed but
        # never gated on, so an engine that missed every vulnerable
        # fixture, or answered UNKNOWN inappropriately, or attached
        # ungrounded findings, still reported gates_pass=True as long as
        # it happened not to flag any SAFE fixture. Worse: `_ratio(x, 0)`
        # returns 0.0 for an EMPTY class, which trivially satisfies
        # `== 0.0` - `compute_metrics([], RuleCatalogue()).gates_pass` was
        # `True` for zero fixtures of any kind (this is the finding's own
        # repro). Requiring at least one fixture of each label, and gating
        # every ratio this evaluation computes (not just two of five),
        # closes both: an empty or partial evaluation cannot pass, and a
        # partially-correct engine cannot pass by only avoiding the one
        # gated failure mode.
        if self.n_vulnerable == 0 or self.n_safe == 0 or self.n_unknown == 0:
            return False
        return (
            self.known_risk_recall == 1.0
            and self.false_positive_rate == 0.0
            and self.unknown_appropriateness == 1.0
            and self.evidence_coverage == 1.0
            and self.safe_test_safety_violations == 0
        )


def _detected(result: AssessmentResult) -> bool:
    return result.overall_status in (OverallStatus.FAIL, OverallStatus.CONDITIONAL)


def compute_metrics(
    labelled: list[LabelledResult], catalogue: RuleCatalogue
) -> EvalMetrics:
    m = EvalMetrics()
    refs_by_rule = {rule.id: set(rule.knowledge_refs) for rule in catalogue.rules}

    findings_total = 0
    findings_with_evidence = 0
    ref_checks = 0
    ref_matches = 0

    for item in labelled:
        r = item.result
        if item.label == "vulnerable":
            m.n_vulnerable += 1
            m.known_risk_recall += 1.0 if _detected(r) else 0.0
        elif item.label == "safe":
            m.n_safe += 1
            m.false_positive_rate += (
                1.0 if r.overall_status is OverallStatus.FAIL else 0.0
            )
        elif item.label == "unknown":
            m.n_unknown += 1
            m.unknown_appropriateness += (
                1.0 if r.overall_status is OverallStatus.UNKNOWN else 0.0
            )

        for f in r.findings:
            findings_total += 1
            if f.evidence:
                findings_with_evidence += 1
            expected_refs = refs_by_rule.get(f.risk_id, set()) if f.origin == "rule" else set()
            if expected_refs:
                ref_checks += 1
                if expected_refs & set(r.retrieved_knowledge_ids):
                    ref_matches += 1

        for test in r.safe_tests:
            if not validate_safe_test(test).is_allowed:
                m.safe_test_safety_violations += 1

    m.known_risk_recall = _ratio(m.known_risk_recall, m.n_vulnerable)
    m.false_positive_rate = _ratio(m.false_positive_rate, m.n_safe)
    m.unknown_appropriateness = _ratio(m.unknown_appropriateness, m.n_unknown)
    m.evidence_coverage = _ratio(findings_with_evidence, findings_total)
    m.citation_source_match = _ratio(ref_matches, ref_checks) if ref_checks else None
    if ref_checks == 0:
        m.notes.append("citation_source_match: no rule findings had knowledge_refs to check")
    return m


def _ratio(num: float, den: int) -> float:
    return num / den if den else 0.0
