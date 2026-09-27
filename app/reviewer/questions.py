"""Turn undetermined results into missing-information records and questions
(spec Section 12 steps 8-9, AC-07)."""

from __future__ import annotations

from app.models.assessment import MissingInformation, Question
from app.models.reviewer_output import ReviewerObservations
from app.reviewer.rule_engine import Applicability, RuleEvaluation
from app.reviewer.vocabulary import CORE_VOCABULARY, Vocabulary


def build_missing_information(
    evaluations: list[RuleEvaluation],
    vocabulary: Vocabulary = CORE_VOCABULARY,
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
            prompts.setdefault(
                key, vocabulary.evidence_prompts.get(key, f"needed to evaluate {ev.rule.id}")
            )
        for key in ev.undetermined_fields:
            by_field.setdefault(key, []).append(ev.rule.id)
            prompts.setdefault(
                key, vocabulary.fact_prompts.get(key, f"needed to evaluate {ev.rule.id}")
            )
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
