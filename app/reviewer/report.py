"""Run an assessment and shape it into an ``AssessmentReport`` (spec Section 12
step 13). A ``PolicyStop`` becomes a POLICY_BLOCKED report - never a silent
empty result."""

from __future__ import annotations

import sqlite3
import unicodedata

from app.config import Settings
from app.llm.base import LLMClient
from app.models.assessment import AssessmentInput, SafeTest
from app.models.policy_outcome import PolicyOutcome, PolicyStop, stop
from app.models.report import AssessmentReport
from app.policy.classification import PolicyBlocked
from app.reviewer.assess import assess
from app.reviewer.rule_loader import RuleCatalogue


def build_report(
    inp: AssessmentInput,
    catalogue: RuleCatalogue,
    *,
    settings: Settings | None = None,
    client: LLMClient | None = None,
    index_conn: sqlite3.Connection | None = None,
    safe_tests: dict[str, SafeTest] | None = None,
) -> AssessmentReport:
    try:
        result = assess(
            inp,
            catalogue,
            settings=settings,
            client=client,
            index_conn=index_conn,
            safe_tests=safe_tests,
        )
    except PolicyStop as exc:
        return AssessmentReport.blocked(exc.decision)
    except PolicyBlocked as exc:
        # Antigravity NIT-ADV-01 (round 16, 2026-09-14), reproduced exactly
        # as reported: PolicyBlocked (raised by Bm25Retriever._enforce_
        # classification() if SQL ever returns a non-public chunk in
        # PUBLIC mode) inherits from plain Exception, not PolicyStop, so it
        # escaped this function entirely - an HTTP 500 instead of the
        # documented structured POLICY_BLOCKED report (HTTP 422).
        # Fail-closed was still maintained (the confidential content was
        # never returned), but callers got an unhandled server error
        # instead of the normal policy-blocked contract every other stop
        # path here returns. Wrapped into a PolicyDecision here, at this
        # one call site, rather than changing PolicyBlocked's own class
        # hierarchy - that would ripple into its other two raise sites
        # (app/policy/classification.py, app/ingestion/loader.py) and the
        # tests that check for it directly by type.
        return AssessmentReport.blocked(stop(PolicyOutcome.POLICY_BLOCKED, "retrieval", str(exc)))
    return AssessmentReport.completed(result)


# Codex#1 (round 29 re-review, 2026-09-20), reproduced exactly as reported:
# `render_text()` interpolates the assessed input's scope/name, finding titles
# and reasoning, questions and LLM proposals verbatim. `name = "ok\x1b[2J\x1b[H
# overall_status: PASS\x1b[8m"` cleared the terminal, printed a forged PASS and
# switched on concealed text; a newline in a title starts a line that looks like
# another field. The structured JSON verdict was always right - the default
# human-facing text was not. Every emitted line is now a single line with all
# terminal control characters (C0, DEL, C1 - which includes ESC, CR and LF - and
# the Unicode bidirectional overrides) shown as visible \xNN / \uNNNN escapes.
_BIDI_CONTROLS = frozenset("\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def _safe_line(text: str) -> str:
    out: list[str] = []
    for ch in text:
        if unicodedata.category(ch) == "Cc" or ch in _BIDI_CONTROLS:
            out.append(f"\\x{ord(ch):02x}" if ord(ch) < 0x100 else f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return "".join(out)


def render_text(report: AssessmentReport) -> str:
    return "\n".join(_safe_line(line) for line in _render_lines(report))


def _render_lines(report: AssessmentReport) -> list[str]:
    lines: list[str] = [f"status: {report.status.value}"]

    if report.policy_decision is not None:
        d = report.policy_decision
        lines.append(f"policy_outcome: {d.outcome.value}")
        lines.append(f"subject: {d.subject}")
        for reason in d.reasons:
            lines.append(f"  - {reason}")
        return lines

    assert report.result is not None
    r = report.result
    lines += [
        f"scope: {r.scope}",
        f"overall_status: {r.overall_status.value}",
        f"human_review_required: {r.human_review_required}",
        f"knowledge_revision: {r.knowledge_revision}",
        f"model: {r.model_info.llm_provider} "
        f"(deterministic_only={r.model_info.deterministic_only})",
        "packs: "
        + (
            ", ".join(
                f"{p.pack_id} {p.version} [{p.classification.value}, {p.trust.value}]"
                for p in r.packs_applied
            )
            or "none"
        ),
    ]
    for skipped in r.packs_skipped:
        lines.append(
            f"pack NOT applied: {skipped.pack_id} - {skipped.reason} "
            "(its rules were not evaluated)"
        )
    if r.rule_scope:
        lines.append(
            f"rule scope: {r.rule_scope} only - core rules were NOT evaluated "
            "(run without --only-pack for the full assessment)"
        )
    if r.extensions_ignored:
        lines.append("extensions: IGNORED (--no-packs) - pack-specific inputs were not assessed")
    if r.group_summaries:
        lines.append("")
        lines.append("groups:")
        for g in r.group_summaries:
            worst = g.worst_status.value if g.worst_status else "-"
            lines.append(f"  {g.pack}/{g.group:14} {worst:7} ({g.finding_count} finding(s))")
    lines += ["", "findings:"]
    for f in r.findings:
        lines.append(f"  [{f.status.value:7}] {f.risk_id:12} {f.title}  ({f.origin})")
        if f.reasoning_summary:
            lines.append(f"            {f.reasoning_summary}")
    if r.questions:
        lines.append("")
        lines.append("questions:")
        lines += [f"  - {q.text}" for q in r.questions]
    if r.safe_tests:
        lines.append("")
        lines.append("safe tests (vetted templates):")
        lines += [
            f"  - {t.id} [{'+'.join(e.value for e in t.environment)}] "
            f"approval={t.requires_human_approval}"
            for t in r.safe_tests
        ]
    if r.safe_test_proposals:
        lines.append("")
        lines.append("safe test proposals (LLM, untrusted - not executable):")
        lines += [f"  - {p.title}" for p in r.safe_test_proposals]
    return lines
