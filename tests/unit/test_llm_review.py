"""M4: LLM review parse / repair / fail-closed and payload separation."""

from __future__ import annotations

from app.llm.base import LLMError, Message
from app.llm.mock import DEFAULT_MOCK_RESPONSE, MockClient
from app.models.assessment import AttackSurface
from app.models.context import AssessmentContext
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


def test_observations_to_findings_are_capped_llm_obs() -> None:
    result = _review(MockClient([DEFAULT_MOCK_RESPONSE]))
    findings = observations_to_findings(result.observations)
    assert findings
    for finding in findings:
        assert finding.origin == "llm"
        assert finding.risk_id.startswith("LLM-OBS-")
        assert finding.status in (FindingStatus.WARN, FindingStatus.UNKNOWN)
