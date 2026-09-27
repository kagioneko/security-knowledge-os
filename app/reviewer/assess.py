"""Assessment orchestration (spec Section 12).

    input -> normalize -> facts -> attack surface -> evidence
          -> deterministic rules
          -> knowledge retrieval (integrity-checked; revision + LLM context)
          -> LLM-assisted review (optional; observations only)
          -> merge (LLM may only add LLM-OBS-*)
          -> questions / missing info / mitigations
          -> vetted safe tests (templates) + untrusted proposals (LLM, not executable)
          -> roll-up

``client=None`` (the default) skips the LLM entirely and the assessment still
completes. ``index_conn`` is optional; when given, the index is integrity-checked
before use (fail-closed) and ``knowledge_revision`` is recorded.
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
    SafeTest,
    UntrustedSafeTestProposal,
)
from app.models.knowledge import Classification
from app.models.pack import GroupSummary
from app.models.policy_outcome import PolicyOutcome, PolicyStop, stop
from app.models.retrieval import RetrievedChunk
from app.models.risk import Finding, FindingStatus
from app.policy.safe_test import (
    load_safe_test_templates,
    unresolved_safe_test_references,
    validate_safe_test,
)
from app.retrieval.bm25 import Bm25Retriever
from app.reviewer.attack_surface import extract_attack_surface
from app.reviewer.evidence import available_evidence
from app.reviewer.extensions import extension_evidence, extension_facts, extension_problems
from app.reviewer.facts import build_facts
from app.reviewer.llm_review import (
    LLMReviewResult,
    degraded_review_finding,
    observations_to_findings,
    run_llm_review,
)
from app.reviewer.normalize import to_context
from app.reviewer.questions import build_missing_information, build_questions
from app.reviewer.rollup import compute_overall_status, merge_findings, requires_human_review
from app.reviewer.rule_engine import evaluate_rules_detailed
from app.reviewer.rule_loader import RuleCatalogue, validate_rule_catalogue
from app.storage.integrity import verify_chunk_hashes

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
    safe_tests: dict[str, SafeTest] | None = None,
) -> AssessmentResult:
    settings = settings or Settings.from_env()
    if safe_tests is None:
        safe_tests = load_safe_test_templates(settings.safe_tests_root)

    # SKOS-ADV-06 / Codex#1 (2026-09-11, round 2): load_rules() rejects an
    # empty/missing rules root, but a caller using this library API directly
    # (RuleCatalogue() with no rules loaded - a config/wiring mistake) bypassed
    # that gate entirely: zero findings -> false PASS, human_review_required
    # False. Fail closed the same way a tampered index does (PolicyStop),
    # rather than silently evaluating against nothing.
    if not catalogue.rules:
        raise PolicyStop(
            stop(
                PolicyOutcome.POLICY_BLOCKED,
                "rule-catalogue",
                "rule catalogue is empty - refusing to assess against zero rules",
            )
        )

    # Codex#2 (round 11, 2026-09-13), reproduced exactly as reported:
    # load_rules() enforces the fact whitelist, operator/type compatibility,
    # evidence keys, reserved LLM-OBS- ids, duplicate ids, and rule shape
    # (checks or manual_review) - but this public library entry point only
    # ever checked the catalogue was non-empty. A RuleCatalogue built
    # directly in Python (bypassing load_rules() entirely) with a clause
    # referencing a nonexistent fact loaded fine (an unknown fact makes
    # is_unknown always evaluate true) and produced a deterministic, silent
    # false PASS. validate_rule_catalogue() is the same validation
    # load_rules() already applies to every YAML-sourced rule; calling it
    # here means a directly-constructed catalogue gets it too.
    problems = validate_rule_catalogue(catalogue)
    if problems:
        raise PolicyStop(
            stop(
                PolicyOutcome.POLICY_BLOCKED,
                "rule-catalogue",
                f"rule catalogue failed validation: {'; '.join(problems)}",
            )
        )

    # Codex#6 (round 7, 2026-09-12), reproduced exactly as reported: an
    # existing but EMPTY (or otherwise incomplete) safe-test catalogue
    # returns {} - `unresolved_safe_test_references()` (round 5, Codex#8)
    # exists precisely to catch a rule referencing a missing template, but
    # nothing on the assess()/API path ever called it.
    # `_safe_tests_for()` below intentionally does not raise on a missing
    # template mid-assessment (a rule still fires; it just loses its
    # attached safe-test recommendation), so a broken reference used to
    # fail SILENTLY - assessing V-001 against an empty safe-test root
    # returned a normal FAIL with safe_tests=[], no policy/configuration
    # error at all. Fail closed the same way an empty rule catalogue does.
    unresolved = unresolved_safe_test_references(catalogue.rules, safe_tests)
    if unresolved:
        raise PolicyStop(
            stop(
                PolicyOutcome.POLICY_BLOCKED,
                "safe-test-catalogue",
                f"{len(unresolved)} rule(s) reference a safe-test template that does "
                f"not exist: {unresolved}",
            )
        )

    vocabulary = catalogue.vocabulary
    extensions_ignored = bool(inp.extensions) and catalogue.ignore_extensions
    if not catalogue.ignore_extensions:
        ext_problems = extension_problems(inp, vocabulary)
        if ext_problems:
            raise PolicyStop(
                stop(
                    PolicyOutcome.POLICY_BLOCKED,
                    "extensions",
                    f"assessment input extensions are not assessable: {'; '.join(ext_problems)}",
                )
            )

    context = to_context(inp)
    facts = build_facts(context)
    surface = extract_attack_surface(context)
    evidence = available_evidence(inp)
    if not catalogue.ignore_extensions:
        facts.update(extension_facts(inp, vocabulary))
        evidence |= extension_evidence(inp, vocabulary)

    evaluations = evaluate_rules_detailed(catalogue.rules, facts, evidence)
    rule_findings = [ev.finding for ev in evaluations if ev.finding is not None]

    retrieved: list[RetrievedChunk] = []
    knowledge_revision: str | None = None
    if index_conn is not None:
        integrity = verify_chunk_hashes(index_conn)
        if integrity.is_stop:  # fail-closed: a tampered index is not used
            raise PolicyStop(integrity)
        response = Bm25Retriever(index_conn, settings).retrieve(
            _knowledge_query(catalogue, rule_findings)
        )
        retrieved = response.results
        knowledge_revision = response.knowledge_revision or None

    retrieved_ids: list[str] = []
    for item in retrieved:
        if item.chunk.knowledge_id not in retrieved_ids:
            retrieved_ids.append(item.chunk.knowledge_id)

    review: LLMReviewResult = run_llm_review(
        client,
        context=context,
        attack_surface=surface,
        rule_findings=rule_findings,
        retrieved=retrieved,
    )
    llm_findings = observations_to_findings(review.observations)
    degraded = degraded_review_finding(review)
    if degraded is not None:
        llm_findings.append(degraded)
    findings = merge_findings(rule_findings, llm_findings)

    missing = build_missing_information(evaluations, vocabulary)
    questions = build_questions(missing, review.observations)
    mitigations = _mitigations(catalogue, rule_findings)
    attached_tests = _safe_tests_for(catalogue, rule_findings, safe_tests)
    proposals = _proposals(review)

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
        safe_tests=attached_tests,
        safe_test_proposals=proposals,
        mitigations=mitigations,
        overall_status=compute_overall_status(findings),
        human_review_required=requires_human_review(
            findings,
            high_impact_present=bool(surface.high_impact_actions),
            confidential_knowledge_used=confidential_used,
            missing_information_present=bool(missing),
        ),
        knowledge_revision=knowledge_revision,
        retrieved_knowledge_ids=retrieved_ids,
        packs_applied=list(catalogue.packs_applied),
        extensions_ignored=extensions_ignored,
        group_summaries=_group_summaries(catalogue, findings),
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
    safe_tests: dict[str, SafeTest] | None = None,
    knowledge_revision: str | None = None,
) -> AssessmentResult:
    result = assess(inp, catalogue, settings=settings, safe_tests=safe_tests)
    if knowledge_revision is not None:
        result.knowledge_revision = knowledge_revision
    return result


_STATUS_RANK = {
    FindingStatus.FAIL: 0,
    FindingStatus.WARN: 1,
    FindingStatus.UNKNOWN: 2,
    FindingStatus.PASS: 3,
    FindingStatus.NA: 4,
}


def _group_summaries(catalogue: RuleCatalogue, findings: list[Finding]) -> list[GroupSummary]:
    by_id: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.origin == "rule":
            by_id.setdefault(finding.risk_id, []).append(finding)
    out: list[GroupSummary] = []
    for group in catalogue.report_groups:
        members = [f for rule_id in group.rule_ids for f in by_id.get(rule_id, [])]
        worst = min((f.status for f in members), key=_STATUS_RANK.__getitem__, default=None)
        out.append(
            GroupSummary(
                pack=group.pack, group=group.group, worst_status=worst, finding_count=len(members)
            )
        )
    return out


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


def _safe_tests_for(
    catalogue: RuleCatalogue,
    findings: list[Finding],
    templates: dict[str, SafeTest],
) -> list[SafeTest]:
    flagged = {
        f.risk_id
        for f in findings
        if f.origin == "rule" and f.status in {FindingStatus.FAIL, FindingStatus.WARN}
    }
    attached: list[SafeTest] = []
    for rule in catalogue.rules:
        if rule.id not in flagged or not rule.safe_test_template:
            continue
        test = templates.get(rule.safe_test_template)
        if test is None:
            continue
        # re-validate before attaching (defence in depth, AC-09)
        if validate_safe_test(test).is_allowed:
            attached.append(test)
    return attached


def _proposals(review: LLMReviewResult) -> list[UntrustedSafeTestProposal]:
    return [
        UntrustedSafeTestProposal(
            title=item.title,
            relates_to_risk_id=item.relates_to_risk_id,
            idea=item.idea,
        )
        for item in review.observations.safe_test_suggestions
    ]
