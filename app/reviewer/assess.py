"""Assessment orchestration (spec Section 12).

    input -> normalize -> facts -> attack surface -> evidence
          -> deterministic rules
          -> knowledge retrieval (revision + context for the LLM)
          -> LLM-assisted review (optional; observations only)
          -> merge (LLM may only add LLM-OBS-*)
          -> questions / missing info / mitigations
          -> roll-up

``provider=None`` (the default) skips the LLM entirely and the assessment still
completes. A retrieval connection is optional; without it ``knowledge_revision``
is ``None``.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from uuid import uuid4

from app.config import Settings
from app.llm.base import LLMClient
from app.models.assessment import (
    AssessmentInput,
    AssessmentResult,
    Mitigation,
    ModelInfo,
)
from app.models.knowledge import Classification
from app.models.retrieval import RetrievedChunk
from app.models.risk import Finding, FindingStatus
from app.retrieval.bm25 import Bm25Retriever
from app.reviewer.attack_surface import extract_attack_surface
from app.reviewer.evidence import available_evidence
from app.reviewer.facts import build_facts
from app.reviewer.llm_review import (
    LLMReviewResult,
    observations_to_findings,
    run_llm_review,
)
from app.reviewer.normalize import to_context
from app.reviewer.questions import build_missing_information, build_questions
from app.reviewer.rollup import compute_overall_status, merge_findings, requires_human_review
from app.reviewer.rule_engine import evaluate_rules_detailed
from app.reviewer.rule_loader import RuleCatalogue

_FLAGGED = {FindingStatus.FAIL, FindingStatus.WARN, FindingStatus.UNKNOWN}


def _knowledge_query(catalogue: RuleCatalogue, findings: list[Finding]) -> str:
    finding_ids = {f.risk_id for f in findings}
    parts: list[str] = []
    for rule in catalogue.rules:
        if rule.id in finding_ids:
            parts.append(rule.category.value.replace("-", " "))
            parts.append(rule.title)
    return " ".join(parts) or "prompt injection tool abuse credential exposure memory"


def assess(
    inp: AssessmentInput,
    catalogue: RuleCatalogue,
    *,
    settings: Settings | None = None,
    client: LLMClient | None = None,
    index_conn: sqlite3.Connection | None = None,
) -> AssessmentResult:
    settings = settings or Settings.from_env()

    context = to_context(inp)
    facts = build_facts(context)
    surface = extract_attack_surface(context)
    evidence = available_evidence(inp)

    evaluations = evaluate_rules_detailed(catalogue.rules, facts, evidence)
    rule_findings = [ev.finding for ev in evaluations if ev.finding is not None]

    retrieved: list[RetrievedChunk] = []
    knowledge_revision: str | None = None
    if index_conn is not None:
        response = Bm25Retriever(index_conn, settings).retrieve(
            _knowledge_query(catalogue, rule_findings)
        )
        retrieved = response.results
        knowledge_revision = response.knowledge_revision or None

    review: LLMReviewResult = run_llm_review(
        client,
        context=context,
        attack_surface=surface,
        rule_findings=rule_findings,
        retrieved=retrieved,
    )
    llm_findings = observations_to_findings(review.observations)
    findings = merge_findings(rule_findings, llm_findings)

    missing = build_missing_information(evaluations)
    questions = build_questions(missing, review.observations)
    mitigations = _mitigations(catalogue, rule_findings)

    confidential_used = any(
        item.chunk.classification is Classification.CONFIDENTIAL for item in retrieved
    )

    return AssessmentResult(
        assessment_id=f"asmt_{uuid4().hex[:12]}",
        created_at=datetime.now(UTC),
        mode=settings.mode.value,
        scope=inp.name,
        attack_surface=surface,
        findings=findings,
        missing_information=missing,
        questions=questions,
        mitigations=mitigations,
        overall_status=compute_overall_status(findings),
        human_review_required=requires_human_review(
            findings,
            high_impact_present=bool(surface.high_impact_actions),
            confidential_knowledge_used=confidential_used,
        ),
        knowledge_revision=knowledge_revision,
        model_info=ModelInfo(
            llm_provider=settings.llm_provider.value,
            llm_model=settings.llm_model,
            deterministic_only=client is None,
        ),
    )


def assess_deterministic(
    inp: AssessmentInput,
    catalogue: RuleCatalogue,
    *,
    settings: Settings | None = None,
    knowledge_revision: str | None = None,
) -> AssessmentResult:
    result = assess(inp, catalogue, settings=settings)
    if knowledge_revision is not None:
        result.knowledge_revision = knowledge_revision
    return result


def _mitigations(catalogue: RuleCatalogue, findings: list[Finding]) -> list[Mitigation]:
    flagged = {f.risk_id for f in findings if f.status in _FLAGGED and f.origin == "rule"}
    out: list[Mitigation] = []
    for rule in catalogue.rules:
        if rule.id in flagged:
            out.extend(
                Mitigation(risk_id=rule.id, recommendation=text, priority=rule.severity)
                for text in rule.mitigations
            )
    return out
