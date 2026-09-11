"""LLM-assisted review (spec Section 12 step 7, Section 16).

Boundary (decision A8):

    Rule Engine  --immutable findings-->  LLM Reviewer  --observations only-->  merge

The deterministic findings are passed to the LLM as a read-only view. The LLM's
output schema has no field for a status or an overall verdict, so it structurally
cannot change one. Malformed output is repaired once, then the result is
``LLM_PARSE_ERROR`` and no observations are produced (fail-closed).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum

from pydantic import ValidationError

from app.llm.base import LLMClient, LLMError, Message
from app.models.assessment import AttackSurface
from app.models.context import AssessmentContext
from app.models.llm_io import (
    DeterministicFindingView,
    RetrievedKnowledgeView,
    ReviewPayload,
)
from app.models.retrieval import RetrievedChunk
from app.models.reviewer_output import ObservationLevel, ReviewerObservations
from app.models.risk import Finding, FindingStatus, Severity

_SYSTEM_PROMPT = """You are a security review assistant. You are given a JSON object with four
separate fields: assessment_context, attack_surface, deterministic_findings (already decided
by a deterministic engine - you cannot change them), and retrieved_knowledge.

Your job is to ADD, not to decide:
- observations: things a human reviewer should check that the engine could not determine.
- questions: specific missing information.
- evidence_notes, limitations, safe_test_suggestions.

You must NOT restate a deterministic finding as your own verdict, and you must NOT output an
overall status. Every observation is capped at level WARN or UNKNOWN.

Reply with ONLY a JSON object matching this schema:
"""


class ParseStatus(StrEnum):
    SKIPPED = "skipped"
    OK = "ok"
    REPAIRED = "repaired"
    LLM_PARSE_ERROR = "LLM_PARSE_ERROR"


@dataclass
class LLMReviewResult:
    observations: ReviewerObservations = field(default_factory=ReviewerObservations)
    parse_status: ParseStatus = ParseStatus.SKIPPED
    error: str | None = None
    repairs: int = 0


def _finding_view(finding: Finding) -> DeterministicFindingView:
    return DeterministicFindingView(
        risk_id=finding.risk_id,
        title=finding.title,
        severity=finding.severity.value,
        status=finding.status.value,
        reasoning=finding.reasoning_summary,
    )


def _chunk_view(item: RetrievedChunk) -> RetrievedKnowledgeView:
    return RetrievedKnowledgeView(
        knowledge_id=item.chunk.knowledge_id,
        title=item.chunk.title,
        source_ref=item.chunk.source_ref,
        section=item.chunk.section,
        text=item.chunk.text,
    )


def build_payload(
    context: AssessmentContext,
    attack_surface: AttackSurface,
    rule_findings: list[Finding],
    retrieved: list[RetrievedChunk],
) -> ReviewPayload:
    return ReviewPayload(
        assessment_context=context.model_dump(mode="json"),
        attack_surface=attack_surface.model_dump(mode="json"),
        deterministic_findings=[_finding_view(f) for f in rule_findings],
        retrieved_knowledge=[_chunk_view(c) for c in retrieved],
    )


def _extract_json(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.split("```", 2)[1]
        if stripped.startswith("json"):
            stripped = stripped[4:]
    start, end = stripped.find("{"), stripped.rfind("}")
    return stripped[start : end + 1] if start != -1 and end != -1 else stripped


def _try_parse(raw: str) -> tuple[ReviewerObservations | None, str | None]:
    try:
        return ReviewerObservations.model_validate_json(_extract_json(raw)), None
    except (ValidationError, json.JSONDecodeError, ValueError) as exc:
        return None, str(exc)


def run_llm_review(
    client: LLMClient | None,
    *,
    context: AssessmentContext,
    attack_surface: AttackSurface,
    rule_findings: list[Finding],
    retrieved: list[RetrievedChunk],
) -> LLMReviewResult:
    if client is None:
        return LLMReviewResult(parse_status=ParseStatus.SKIPPED)

    payload = build_payload(context, attack_surface, rule_findings, retrieved)
    schema = json.dumps(ReviewerObservations.model_json_schema())
    messages = [
        Message("system", _SYSTEM_PROMPT + schema),
        Message("user", payload.model_dump_json(indent=2)),
    ]

    try:
        raw = client.complete(messages)
    except LLMError as exc:
        return LLMReviewResult(parse_status=ParseStatus.LLM_PARSE_ERROR, error=str(exc))

    parsed, err = _try_parse(raw)
    if parsed is not None:
        return LLMReviewResult(observations=_sanitize(parsed), parse_status=ParseStatus.OK)

    messages += [
        Message("assistant", raw),
        Message(
            "user",
            f"That was not valid JSON for the schema ({err}). "
            "Reply with ONLY a JSON object matching the schema, nothing else.",
        ),
    ]
    try:
        raw2 = client.complete(messages)
    except LLMError as exc:
        return LLMReviewResult(parse_status=ParseStatus.LLM_PARSE_ERROR, error=str(exc), repairs=1)

    parsed, err = _try_parse(raw2)
    if parsed is not None:
        return LLMReviewResult(
            observations=_sanitize(parsed), parse_status=ParseStatus.REPAIRED, repairs=1
        )
    return LLMReviewResult(parse_status=ParseStatus.LLM_PARSE_ERROR, error=err, repairs=1)


def _sanitize(observations: ReviewerObservations) -> ReviewerObservations:
    # The schema already caps observation level; this is a belt-and-braces clamp.
    for obs in observations.observations:
        if obs.level not in (ObservationLevel.WARN, ObservationLevel.UNKNOWN):
            obs.level = ObservationLevel.UNKNOWN
    return observations


def observations_to_findings(observations: ReviewerObservations) -> list[Finding]:
    findings: list[Finding] = []
    for index, obs in enumerate(observations.observations, start=1):
        status = (
            FindingStatus.WARN
            if obs.level is ObservationLevel.WARN
            else FindingStatus.UNKNOWN
        )
        note = f" (context: {obs.relates_to_risk_id})" if obs.relates_to_risk_id else ""
        findings.append(
            Finding(
                risk_id=f"LLM-OBS-{index:05d}",
                title=obs.title,
                severity=Severity.MEDIUM,
                status=status,
                origin="llm",
                reasoning_summary=obs.detail + note,
                limitations=["LLM observation - not a deterministic finding"],
            )
        )
    return findings


def degraded_review_finding(result: LLMReviewResult) -> Finding | None:
    """Codex cross-review finding #8 (2026-09-11): a requested-but-failed LLM
    review (``LLM_PARSE_ERROR``, after the repair attempt) used to vanish -
    ``review.observations`` stayed empty, so no ``LLM-OBS-*`` finding was added
    and nothing else in the result recorded that assistance was requested and
    did not happen. An assessment that completed on rule findings alone (e.g.
    an all-PASS fixture) could therefore report ``PASS`` /
    ``human_review_required=False`` with zero trace of the failure.

    Surfaced as a normal ``LLM-OBS-00000`` finding (origin='llm', capped at
    UNKNOWN by the same A8 boundary as any other LLM observation) so it flows
    through the existing merge / roll-up / human-review machinery instead of
    needing new plumbing: it pulls ``overall_status`` to at least UNKNOWN and
    ``human_review_required`` to True, same as any other unresolved finding.

    Returns ``None`` when there was nothing to report (LLM skipped entirely, or
    it answered successfully) - that is a normal configuration, not a failure.
    """
    if result.parse_status is not ParseStatus.LLM_PARSE_ERROR:
        return None
    detail = f": {result.error}" if result.error else ""
    return Finding(
        risk_id="LLM-OBS-00000",
        title="LLM-assisted review did not complete",
        severity=Severity.MEDIUM,
        status=FindingStatus.UNKNOWN,
        origin="llm",
        reasoning_summary=(
            "an LLM reviewer was configured and invoked, but its output could not be "
            f"parsed after one repair attempt (LLM_PARSE_ERROR){detail}"
        ),
        limitations=[
            "no LLM observations were produced for this assessment; only the "
            "deterministic rule findings below were evaluated"
        ],
    )
