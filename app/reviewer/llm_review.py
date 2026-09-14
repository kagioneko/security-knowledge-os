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
from collections.abc import Iterable
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


def _label_map(values: Iterable[str], prefix: str) -> dict[str, str]:
    """A stable (sorted-then-numbered), deterministic real-name -> local
    label mapping, e.g. {"internal_wiki": "rag_source_1", "web":
    "rag_source_2"}. Sorted so the same input always maps to the same
    labels across calls (reproducibility for debugging/logs), not for any
    security property."""
    return {name: f"{prefix}_{i}" for i, name in enumerate(sorted(set(values)), start=1)}


def _anonymize_for_llm(
    context: AssessmentContext, attack_surface: AttackSurface
) -> tuple[AssessmentContext, AttackSurface]:
    """Codex#1 (rounds 9, 11, 12, 13, 14, 2026-09-12 -- 2026-09-13),
    reproduced exactly as reported across FIVE rounds: every attempt to
    FILTER a user-supplied identifier value before it reached the LLM
    payload (a credential-shape denylist, then also an identifier-shape
    allowlist) was defeated by a differently-shaped real secret - most
    recently a UUID-form token, whose hyphen-separated segments are all
    individually short enough to pass the allowlist. No filter over the
    RAW VALUE can give an unconditional "never sends a raw secret"
    guarantee, because the field is free text by construction.

    This closes the class outright by never constructing the LLM payload
    from the raw values at all: `retrieval_sources`, `outbound_
    destinations`, tool names, and human_approval/action keys are
    replaced with stable local labels (`rag_source_1`, `destination_1`,
    `tool_1`, `action_1`, ...) before `build_payload()` ever serializes
    anything. The LLM can still reason about STRUCTURE (how many
    destinations, which tools have which permission, whether a
    particular tool needs approval) and refer to a specific one
    consistently across its own observations/questions - it just never
    sees the actual business-context string, so no value the field could
    ever hold (known credential shape, unknown future shape, or a
    genuine business secret that merely LOOKS like an ordinary name) can
    reach an external provider through these fields.

    The ORIGINAL, non-anonymized `context`/`attack_surface` objects are
    unaffected by this function (a new, separate pair of objects is
    returned) - the deterministic rule engine (which never leaves this
    process) and `AssessmentResult.attack_surface` (returned to the
    calling human, who is entitled to see their own real data) both keep
    using the real values everywhere else in app/reviewer/assess.py; only
    the LLM request-building path in this module goes through this.

    The remaining denylist (`reject_credential_shapes`) and allowlist
    (`reject_non_identifier_shapes`) checks on these fields
    (app/models/_credential_shapes.py) are kept as defense in depth, not
    as this boundary - matching Codex's own repeated recommendation
    ("keep deny-list detection only as defense in depth, not as the
    security boundary").
    """
    tool_map = _label_map((t.name for t in context.tools), "tool")
    rag_map = _label_map(context.retrieval_sources, "rag_source")
    dest_map = _label_map(context.outbound_destinations or [], "destination")
    action_map = _label_map(context.human_approval, "action")

    def _tool_label(name: str) -> str:
        return tool_map.get(name, "unlabeled_tool")

    def _rag_label(name: str) -> str:
        return rag_map.get(name, "unlabeled_source")

    def _dest_label(name: str) -> str:
        return dest_map.get(name, "unlabeled_destination")

    def _action_label(name: str) -> str:
        return action_map.get(name, "unlabeled_action")

    def _anon_high_impact(actions: list[str]) -> list[str]:
        # Each entry is exactly "outbound_send" or "tool:<name>" (see
        # app/reviewer/normalize.py / app/reviewer/attack_surface.py) -
        # relabeling here rather than re-deriving keeps this in sync with
        # that logic automatically instead of duplicating it.
        return [
            f"tool:{_tool_label(action.removeprefix('tool:'))}"
            if action.startswith("tool:")
            else action
            for action in actions
        ]

    anon_context = context.model_copy(
        update={
            "retrieval_sources": [_rag_label(s) for s in context.retrieval_sources],
            "tools": [t.model_copy(update={"name": _tool_label(t.name)}) for t in context.tools],
            "outbound_destinations": (
                [_dest_label(d) for d in context.outbound_destinations]
                if context.outbound_destinations is not None
                else None
            ),
            "human_approval": {_action_label(k): v for k, v in context.human_approval.items()},
            "high_impact_actions": _anon_high_impact(context.high_impact_actions),
        }
    )
    anon_attack_surface = attack_surface.model_copy(
        update={
            "external_content_sources": [
                _rag_label(s) for s in attack_surface.external_content_sources
            ],
            "retrieval_sources": [_rag_label(s) for s in attack_surface.retrieval_sources],
            "tools": [_tool_label(name) for name in attack_surface.tools],
            "tool_permissions": {
                _tool_label(name): perm for name, perm in attack_surface.tool_permissions.items()
            },
            "outbound_channels": [_dest_label(d) for d in attack_surface.outbound_channels],
            "human_approval_points": [
                _action_label(a) for a in attack_surface.human_approval_points
            ],
            "high_impact_actions": _anon_high_impact(attack_surface.high_impact_actions),
        }
    )
    return anon_context, anon_attack_surface


def build_payload(
    context: AssessmentContext,
    attack_surface: AttackSurface,
    rule_findings: list[Finding],
    retrieved: list[RetrievedChunk],
) -> ReviewPayload:
    # Codex#1 (rounds 9-14, 2026-09-12 -- 2026-09-13): see
    # _anonymize_for_llm()'s own docstring - this is the single choke
    # point every external-LLM request is built from, so anonymizing here
    # (rather than in the caller) means no future caller of build_payload
    # can forget it.
    anon_context, anon_attack_surface = _anonymize_for_llm(context, attack_surface)
    return ReviewPayload(
        assessment_context=anon_context.model_dump(mode="json"),
        attack_surface=anon_attack_surface.model_dump(mode="json"),
        deterministic_findings=[_finding_view(f) for f in rule_findings],
        retrieved_knowledge=[_chunk_view(c) for c in retrieved],
    )


# Codex#11 (round 5, 2026-09-12): the per-field/per-list bounds on
# ReviewerObservations (app/models/reviewer_output.py) only apply AFTER the
# raw text has already been fully parsed into Python objects - a
# pathologically large raw response (a custom or misbehaving LLMClient, not
# just the vetted AnthropicClient with its max_tokens=2048) would still pay
# the full JSON-parse cost before that rejection ever triggers. Capping the
# raw byte count first bounds that cost regardless of what the response
# contains.
_MAX_RAW_RESPONSE_BYTES = 200_000


def _extract_json(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.split("```", 2)[1]
        if stripped.startswith("json"):
            stripped = stripped[4:]
    start, end = stripped.find("{"), stripped.rfind("}")
    return stripped[start : end + 1] if start != -1 and end != -1 else stripped


_UNTRUSTED_LOC_ERROR_TYPES = frozenset({"extra_forbidden"})


def _sanitize_pydantic_errors(exc: ValidationError) -> str:
    """See the call site's own comment (Codex#4 / Antigravity SKOS-ADV-22,
    round 18, 2026-09-14) for the full story: `exc.errors(include_input=
    False, ...)` hides the rejected VALUE but not the rejected KEY - for
    an `extra_forbidden` violation, `loc` IS the untrusted extra property
    name an attacker-influenced LLM response supplied. Replaces `loc`
    with a fixed placeholder for exactly that error type; every other
    type's `loc` names a fixed path in this project's own schema and is
    left as-is."""
    sanitized = [
        {**error, "loc": ("<unexpected field>",)}
        if error.get("type") in _UNTRUSTED_LOC_ERROR_TYPES
        else error
        for error in exc.errors(include_input=False, include_url=False)
    ]
    return str(sanitized)


def _try_parse(raw: str) -> tuple[ReviewerObservations | None, str | None]:
    # Codex#2 (round 16, 2026-09-14), reproduced exactly as reported: this
    # assumed `raw` was always a `str` - a custom/misbehaving LLMClient
    # returning `None` (or any non-str) made `raw.encode("utf-8")` raise a
    # raw AttributeError, escaping the LLM_PARSE_ERROR contract entirely
    # (an API 500 instead of the documented fail-closed result). Callers
    # now route every `client.complete()` result through `_safe_complete()`
    # below, which already guarantees a `str` here - this check is
    # defense in depth, matching this module's existing posture of never
    # relying on a single boundary.
    if not isinstance(raw, str):
        return None, f"adapter returned {type(raw).__name__}, not str"
    try:
        # Codex#7 (round 7, 2026-09-12), reproduced exactly as reported:
        # this size check used to run BEFORE the try block - a provider
        # returning a Python string containing an unpaired surrogate (e.g.
        # "\ud800") made raw.encode("utf-8") itself raise a raw
        # UnicodeEncodeError, bypassing the normal LLM_PARSE_ERROR /
        # one-repair-attempt flow entirely. Moved inside the same try/except
        # boundary as parsing - UnicodeEncodeError is a ValueError subclass,
        # already handled below.
        size = len(raw.encode("utf-8"))
        if size > _MAX_RAW_RESPONSE_BYTES:
            return (
                None,
                f"response is {size} bytes, over the {_MAX_RAW_RESPONSE_BYTES}-byte limit",
            )
        return ReviewerObservations.model_validate_json(_extract_json(raw)), None
    except ValidationError as exc:
        # Codex#6 (round 6, 2026-09-12), reproduced exactly as reported:
        # str(ValidationError) includes pydantic's own `input_value=...` -
        # the REJECTED RAW VALUE, verbatim - which is exactly the untrusted
        # LLM output this error is ABOUT. A response containing
        # {"extra": "SUPERSECRET..."} put the secret straight into this
        # return value, then (after the repair attempt also failed) into
        # the public LLM-OBS-00000 finding via degraded_review_finding().
        # errors(include_input=False, include_url=False) gives the same
        # loc/type/msg diagnostic with the rejected value itself omitted.
        #
        # Codex#4 / Antigravity SKOS-ADV-22 (round 18, 2026-09-14),
        # reproduced exactly as reported: hiding the rejected VALUE is not
        # enough - for an `extra_forbidden` violation (this schema uses
        # extra="forbid" throughout), `loc` IS the untrusted extra
        # property NAME itself. A response like
        # {"LEAKED_INTERNAL_SECRET": 1} makes pydantic's own `loc` read
        # ("LEAKED_INTERNAL_SECRET",) - an attacker controlling the LLM's
        # output (via prompt injection) can put anything there, and it
        # flowed into the repair prompt and, if repair also failed, into
        # the public LLM-OBS-00000 finding verbatim, unlike every OTHER
        # error type's `loc`, which names a fixed field path in this
        # project's own ReviewerObservations schema (e.g.
        # "observations.0.level") and is safe to disclose.
        return None, _sanitize_pydantic_errors(exc)
    except (json.JSONDecodeError, ValueError) as exc:
        # a JSON/extraction failure's message is about the STRUCTURE of
        # `raw` (an unterminated string, a stray comma, "not JSON at all")
        # - it does not echo an arbitrary field's value back the way
        # pydantic's input_value does, so str(exc) here stays as it was.
        return None, str(exc)


def _error_category(exc: LLMError) -> str:
    """Codex#6 (round 5, 2026-09-12), reproduced exactly as reported: a
    provider's exception message can carry a response body, an internal
    endpoint, or credential-bearing diagnostic text (the review's repro: a
    message containing "token=SUPERSECRET"). `LLMReviewResult.error` flows
    straight into a public `LLM-OBS-00000` Finding
    (`degraded_review_finding` below), so only a stable, safe CATEGORY - the
    exception's type name, never `str(exc)` - may end up there, regardless
    of which `LLMClient` implementation raised it. Prefers the chained
    cause's type name (e.g. "AuthenticationError", "RateLimitError") when a
    client raised `LLMError(...) from exc` (`AnthropicClient` does); falls
    back to `LLMError`'s own type name otherwise."""
    cause = exc.__cause__
    return type(cause).__name__ if cause is not None else type(exc).__name__


def _safe_complete(
    client: LLMClient, messages: list[Message], *, repairs: int
) -> tuple[str | None, LLMReviewResult | None]:
    """Call `client.complete()`, converting ANY exception - not just
    `LLMError` - and a non-`str` return value into a safe, type-name-only
    `LLM_PARSE_ERROR` result. Codex#2 (round 16, 2026-09-14), reproduced
    exactly as reported: a pluggable `LLMClient` is untrusted code from
    this app's own trust-boundary perspective - `except LLMError` alone
    let an unexpected exception (or `None`/non-str return) from a
    custom/misbehaving adapter escape `run_llm_review()` as a raw
    exception (an API 500) instead of the documented fail-closed
    contract. Reuses `_error_category()`'s own reasoning for exceptions:
    only the exception's TYPE NAME is safe to surface, never `str(exc)`,
    which could carry a response body or credential-bearing diagnostic
    text from the provider.

    Returns `(raw, None)` on success (`raw` is guaranteed `str`) or
    `(None, result)` with a ready-to-return `LLMReviewResult` on failure.
    """
    try:
        raw = client.complete(messages)
    except LLMError as exc:
        return None, LLMReviewResult(
            parse_status=ParseStatus.LLM_PARSE_ERROR, error=_error_category(exc), repairs=repairs
        )
    except Exception as exc:  # noqa: BLE001 - untrusted adapter call, must never escape
        return None, LLMReviewResult(
            parse_status=ParseStatus.LLM_PARSE_ERROR, error=type(exc).__name__, repairs=repairs
        )
    if not isinstance(raw, str):
        return None, LLMReviewResult(
            parse_status=ParseStatus.LLM_PARSE_ERROR,
            error=f"adapter returned {type(raw).__name__}, not str",
            repairs=repairs,
        )
    return raw, None


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

    raw, err_result = _safe_complete(client, messages, repairs=0)
    if err_result is not None:
        return err_result
    assert raw is not None  # guaranteed by _safe_complete's (raw, err) contract

    parsed, err = _try_parse(raw)
    if parsed is not None:
        return LLMReviewResult(observations=_sanitize(parsed), parse_status=ParseStatus.OK)

    # Codex#7 (round 6, 2026-09-12), reproduced exactly as reported: the
    # 200KB check in _try_parse() prevents PARSING an oversized response,
    # but the oversized `raw` text itself was still appended as an
    # assistant message and sent through in full on the repair call -
    # preserving the exact provider-cost/memory-amplification path the cap
    # exists to close, just delayed by one round trip.
    # Codex#7 (round 7, 2026-09-12): the same unguarded raw.encode("utf-8")
    # this function's OWN 200KB check (round 6) used - an unpaired
    # surrogate would raise UnicodeEncodeError here too, uncaught, escaping
    # run_llm_review() entirely instead of the normal repair flow.
    try:
        raw_is_oversized = len(raw.encode("utf-8")) > _MAX_RAW_RESPONSE_BYTES
    except UnicodeEncodeError:
        raw_is_oversized = True  # unencodable is treated the same as oversized: omit it
    raw_for_repair = "[response omitted: exceeded the size limit]" if raw_is_oversized else raw
    messages += [
        Message("assistant", raw_for_repair),
        Message(
            "user",
            f"That was not valid JSON for the schema ({err}). "
            "Reply with ONLY a JSON object matching the schema, nothing else.",
        ),
    ]
    raw2, err_result = _safe_complete(client, messages, repairs=1)
    if err_result is not None:
        return err_result
    assert raw2 is not None  # guaranteed by _safe_complete's (raw, err) contract

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
