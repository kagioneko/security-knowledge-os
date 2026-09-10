"""Deterministic assessment core (spec Section 12, LLM-free subset).

    input -> normalize -> facts -> attack surface -> evidence -> rules -> rollup

Milestone 3 produces findings, an attack surface, an overall status, and the
human-review flag. Retrieval-backed knowledge citations (M2 index), LLM-assisted
review, questions, safe tests and mitigations arrive in later milestones.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from app.config import Settings
from app.models.assessment import AssessmentInput, AssessmentResult, ModelInfo
from app.reviewer.attack_surface import extract_attack_surface
from app.reviewer.evidence import available_evidence
from app.reviewer.facts import build_facts
from app.reviewer.normalize import to_context
from app.reviewer.rollup import compute_overall_status, requires_human_review
from app.reviewer.rule_engine import evaluate_rules
from app.reviewer.rule_loader import RuleCatalogue


def assess_deterministic(
    inp: AssessmentInput,
    catalogue: RuleCatalogue,
    *,
    settings: Settings | None = None,
    knowledge_revision: str | None = None,
) -> AssessmentResult:
    settings = settings or Settings.from_env()

    context = to_context(inp)
    facts = build_facts(context)
    surface = extract_attack_surface(context)
    evidence = available_evidence(inp)

    findings = evaluate_rules(catalogue.rules, facts, evidence)

    return AssessmentResult(
        assessment_id=f"asmt_{uuid4().hex[:12]}",
        created_at=datetime.now(UTC),
        mode=settings.mode.value,
        scope=inp.name,
        attack_surface=surface,
        findings=findings,
        overall_status=compute_overall_status(findings),
        human_review_required=requires_human_review(
            findings,
            high_impact_present=bool(surface.high_impact_actions),
            confidential_knowledge_used=False,
        ),
        knowledge_revision=knowledge_revision,
        model_info=ModelInfo(
            llm_provider=settings.llm_provider.value,
            llm_model=settings.llm_model,
            deterministic_only=True,
        ),
    )
