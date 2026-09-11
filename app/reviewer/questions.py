"""Turn undetermined results into missing-information records and questions
(spec Section 12 steps 8-9, AC-07)."""

from __future__ import annotations

from app.models.assessment import MissingInformation, Question
from app.models.reviewer_output import ReviewerObservations
from app.reviewer.rule_engine import Applicability, RuleEvaluation

_EVIDENCE_PROMPT = {
    "system_prompt": "Provide the system prompt (or confirm there is none).",
    "developer_prompt": "Provide the developer prompt if one is used.",
    "rag_pipeline": "Describe the RAG configuration: is retrieval enabled, and from which sources?",
    "tool_policy": "List the tools available to the agent.",
    "tool_permissions_specified": "State each tool's permission (read/write/delete/send/shell).",
    "memory_spec": "Describe memory: enabled? persistent? what scope?",
    "outbound_spec": "State whether the agent can send data to external systems.",
    "outbound_destinations": "List the allowed outbound destinations.",
    "credential_storage": "Describe credential storage and whether the model can read secrets.",
    "human_approval_policy": "List which actions require human approval.",
}

# Prompts for undetermined AssessmentContext facts (applicability could not be decided).
_FACT_PROMPT = {
    "external_content_ingestion": "Does the system ingest external or user-supplied content?",
    "memory_persistent": "Is memory persistent across sessions?",
    "memory_enabled": "Does the system keep any memory?",
    "outbound_enabled": "Can the system send data to external destinations?",
    "credential_exposed_to_model": "Can the model or its tools read raw secrets?",
    "credential_storage": "How are credentials stored (env, vault, proxy, none)?",
}


def build_missing_information(
    evaluations: list[RuleEvaluation],
) -> list[MissingInformation]:
    by_field: dict[str, list[str]] = {}
    prompts: dict[str, str] = {}
    for ev in evaluations:
        # SKOS-ADV-02 (Antigravity, 2026-09-11): gating on "no finding" used to
        # drop a rule's undetermined_fields whenever _emit_indeterminate
        # suppressed the finding for a medium/low rule whose trigger clauses
        # were ALL undetermined - the operator was then never asked the
        # clarifying question that could resolve it. NOT_APPLICABLE is the
        # only case that should be skipped: a rule that definitely does not
        # apply has nothing useful to ask about, regardless of whether a
        # finding happened to be emitted.
        if ev.applicability is Applicability.NOT_APPLICABLE:
            continue
        for key in ev.missing_evidence:
            by_field.setdefault(key, []).append(ev.rule.id)
            prompts.setdefault(key, _EVIDENCE_PROMPT.get(key, f"needed to evaluate {ev.rule.id}"))
        for key in ev.undetermined_fields:
            by_field.setdefault(key, []).append(ev.rule.id)
            prompts.setdefault(key, _FACT_PROMPT.get(key, f"needed to evaluate {ev.rule.id}"))
    return [
        MissingInformation(
            field=key,
            why_needed=prompts[key],
            related_rule_ids=sorted(set(rule_ids)),
        )
        for key, rule_ids in sorted(by_field.items())
    ]


def build_questions(
    missing: list[MissingInformation], observations: ReviewerObservations
) -> list[Question]:
    questions = [
        Question(text=item.why_needed, field=item.field, related_rule_ids=item.related_rule_ids)
        for item in missing
    ]
    for question in observations.questions:
        questions.append(Question(text=question.text, field=question.field))
    return questions
