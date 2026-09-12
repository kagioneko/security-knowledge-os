"""M4: LLM review parse / repair / fail-closed and payload separation."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.llm.base import LLMError, Message
from app.llm.mock import DEFAULT_MOCK_RESPONSE, MockClient
from app.models.assessment import AttackSurface
from app.models.context import AssessmentContext
from app.models.reviewer_output import ReviewerObservations
from app.models.risk import Finding, FindingStatus, Severity
from app.reviewer.llm_review import (
    ParseStatus,
    build_payload,
    degraded_review_finding,
    observations_to_findings,
    run_llm_review,
)

_CTX = AssessmentContext()
_SURFACE = AttackSurface()
_RULE_FINDINGS = [
    Finding(risk_id="PI-003", title="t", severity=Severity.HIGH, status=FindingStatus.FAIL)
]


def _review(client):
    return run_llm_review(
        client,
        context=_CTX,
        attack_surface=_SURFACE,
        rule_findings=_RULE_FINDINGS,
        retrieved=[],
    )


def test_no_client_is_skipped() -> None:
    result = _review(None)
    assert result.parse_status is ParseStatus.SKIPPED
    assert result.observations.observations == []


def test_valid_output_parses_ok() -> None:
    result = _review(MockClient([DEFAULT_MOCK_RESPONSE]))
    assert result.parse_status is ParseStatus.OK
    assert result.observations.observations


def test_malformed_then_valid_is_repaired_once() -> None:
    client = MockClient(["not json at all", DEFAULT_MOCK_RESPONSE])
    result = _review(client)
    assert result.parse_status is ParseStatus.REPAIRED
    assert result.repairs == 1
    assert client.calls == 2


def test_malformed_twice_fails_closed() -> None:
    client = MockClient(["nope", "still nope"])
    result = _review(client)
    assert result.parse_status is ParseStatus.LLM_PARSE_ERROR
    assert result.repairs == 1
    assert result.observations.observations == []  # no fabricated observations
    assert client.calls == 2


def test_extra_field_in_output_triggers_repair() -> None:
    bad = '{"observations": [], "questions": [], "overall_status": "PASS"}'
    result = _review(MockClient([bad, DEFAULT_MOCK_RESPONSE]))
    assert result.parse_status is ParseStatus.REPAIRED


def test_payload_keeps_sections_separate() -> None:
    payload = build_payload(_CTX, _SURFACE, _RULE_FINDINGS, [])
    assert set(payload.model_dump()) == {
        "assessment_context",
        "attack_surface",
        "deterministic_findings",
        "retrieved_knowledge",
    }
    assert payload.deterministic_findings[0].status == "FAIL"


class _RaisingClient:
    """The review's exact repro: a provider error containing secret-shaped
    diagnostic text."""

    name = "x"

    def complete(self, messages: list[Message]) -> str:
        raise LLMError("Authorization failed for token=SUPERSECRET")


def test_llm_error_message_never_reaches_the_reported_finding() -> None:
    """Regression for Codex#6 (round 5, 2026-09-12), reproduced exactly as
    reported: a provider exception's message (which can carry a response
    body, an internal endpoint, or credential-bearing diagnostic text) used
    to be copied verbatim into LLMReviewResult.error and then into the
    public LLM-OBS-00000 finding. Only a stable error category (the
    exception's type name) may appear there now."""
    result = _review(_RaisingClient())
    assert result.parse_status is ParseStatus.LLM_PARSE_ERROR
    assert result.error == "LLMError"  # category only, never the message
    assert result.error is not None
    assert "SUPERSECRET" not in result.error

    finding = degraded_review_finding(result)
    assert finding is not None
    assert "SUPERSECRET" not in finding.reasoning_summary


def test_llm_error_category_prefers_the_chained_causes_type_name() -> None:
    """AnthropicClient chains `raise LLMError(...) from exc` - the ORIGINAL
    provider exception's type name (e.g. "AuthenticationError") is a more
    useful category than the generic "LLMError" wrapper, and is still safe
    (never the message)."""

    class _AuthenticationError(Exception):
        pass

    class _ChainedRaisingClient:
        name = "x"

        def complete(self, messages: list[Message]) -> str:
            try:
                raise _AuthenticationError("token=SUPERSECRET")
            except _AuthenticationError as exc:
                raise LLMError("anthropic request failed: _AuthenticationError") from exc

    result = _review(_ChainedRaisingClient())
    assert result.error == "_AuthenticationError"


def test_oversized_first_response_is_rejected_without_ever_being_parsed() -> None:
    """Regression for Codex#11 (round 5, 2026-09-12), reproduced exactly as
    reported: valid JSON containing tens of thousands of observations used
    to be fully parsed, converted to findings, and retained in the API's
    in-memory _STORE. An oversized raw response must be treated as a parse
    failure BEFORE that parse ever runs - triggering the same one-repair
    flow as any other malformed response (see
    test_malformed_then_valid_is_repaired_once), not a crash and not the
    20,000 fabricated observations."""
    huge = json.dumps(
        {
            "observations": [
                {
                    "title": "x",
                    "detail": "y",
                    "level": "WARN",
                    "relates_to_risk_id": None,
                    "evidence_refs": [],
                }
                for _ in range(20_000)
            ],
            "questions": [],
            "evidence_notes": [],
            "limitations": [],
            "safe_test_suggestions": [],
        }
    )
    assert len(huge.encode("utf-8")) > 200_000  # sanity: this really is oversized

    client = MockClient([huge, DEFAULT_MOCK_RESPONSE])
    result = _review(client)
    assert result.parse_status is ParseStatus.REPAIRED
    assert result.repairs == 1
    # came from the small repair response, never the huge first one
    assert len(result.observations.observations) == 1


def test_oversized_repair_response_also_fails_closed() -> None:
    """The repair round-trip is bounded the same way as the first call."""
    huge = json.dumps({"observations": [{"title": "x"} for _ in range(20_000)]})
    client = MockClient(["not json at all", huge])
    result = _review(client)
    assert result.parse_status is ParseStatus.LLM_PARSE_ERROR
    assert result.repairs == 1
    assert result.observations.observations == []


def test_reviewer_observations_rejects_too_many_items() -> None:
    """Regression for Codex#11 (round 5, 2026-09-12): ReviewerObservations'
    lists (observations/questions/evidence_notes/limitations/
    safe_test_suggestions) were unbounded."""
    with pytest.raises(ValidationError):
        ReviewerObservations.model_validate({"limitations": ["x"] * 201})


def test_reviewer_observations_rejects_an_oversized_free_text_field() -> None:
    with pytest.raises(ValidationError):
        ReviewerObservations.model_validate(
            {
                "observations": [
                    {
                        "title": "x",
                        "detail": "y" * 20_001,
                        "level": "WARN",
                    }
                ]
            }
        )


def test_pydantic_parse_error_never_leaks_the_rejected_value() -> None:
    """Regression for Codex#6 (round 6, 2026-09-12), reproduced exactly as
    reported: str(ValidationError) includes pydantic's own
    `input_value=...` - the rejected raw value, verbatim. Two responses
    containing {"observations": [], "extra": "SUPERSECRET..."} used to put
    the secret into both LLMReviewResult.error and the reported finding's
    reasoning_summary after the repair attempt also failed."""
    bad = '{"observations": [], "extra": "SUPERSECRET_CANARY_987654321"}'
    client = MockClient([bad, bad])
    result = _review(client)
    assert result.parse_status is ParseStatus.LLM_PARSE_ERROR
    assert result.error is not None
    assert "SUPERSECRET_CANARY_987654321" not in result.error

    finding = degraded_review_finding(result)
    assert finding is not None
    assert "SUPERSECRET_CANARY_987654321" not in finding.reasoning_summary


def test_oversized_response_is_not_forwarded_intact_during_repair() -> None:
    """Regression for Codex#7 (round 6, 2026-09-12), reproduced exactly as
    reported: the 200KB check prevents PARSING an oversized response, but
    the oversized raw text itself was still sent through in full on the
    repair call - a custom client returning 500,000 characters on its
    first call observed a repair request containing the entire rejected
    response."""

    class _RecordingClient:
        name = "x"

        def __init__(self, responses: list[str]) -> None:
            self._responses = responses
            self.calls = 0
            self.seen_message_sizes: list[list[int]] = []

        def complete(self, messages: list[Message]) -> str:
            self.seen_message_sizes.append([len(m.content) for m in messages])
            response = self._responses[min(self.calls, len(self._responses) - 1)]
            self.calls += 1
            return response

    huge = "x" * 500_000
    client = _RecordingClient([huge, DEFAULT_MOCK_RESPONSE])
    result = _review(client)
    assert result.parse_status is ParseStatus.REPAIRED
    assert client.calls == 2

    second_call_sizes = client.seen_message_sizes[1]
    assert 500_000 not in second_call_sizes  # the huge response was not forwarded as-is
    assert max(second_call_sizes) < 10_000  # smallest of the 4 messages should dwarf 500,000


def test_an_unpaired_surrogate_response_fails_closed_not_a_raw_unicodeencodeerror() -> None:
    """Regression for Codex#7 (round 7, 2026-09-12), reproduced exactly as
    reported: the UTF-8 size check ran BEFORE the parsing try block - a
    provider returning a Python string containing an unpaired surrogate
    made raw.encode("utf-8") itself raise a raw UnicodeEncodeError,
    bypassing the normal LLM_PARSE_ERROR / one-repair-attempt flow."""

    class _SurrogateClient:
        name = "x"

        def complete(self, messages: list[Message]) -> str:
            return "\ud800"

    result = _review(_SurrogateClient())  # must not raise
    assert result.parse_status is ParseStatus.LLM_PARSE_ERROR
    assert result.observations.observations == []


def test_observations_to_findings_are_capped_llm_obs() -> None:
    result = _review(MockClient([DEFAULT_MOCK_RESPONSE]))
    findings = observations_to_findings(result.observations)
    assert findings
    for finding in findings:
        assert finding.origin == "llm"
        assert finding.risk_id.startswith("LLM-OBS-")
        assert finding.status in (FindingStatus.WARN, FindingStatus.UNKNOWN)
