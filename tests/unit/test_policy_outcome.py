"""M5: typed policy outcomes (enum, not strings)."""

from __future__ import annotations

from app.models.policy_outcome import PolicyDecision, PolicyOutcome, PolicyStop, allow, stop


def test_outcome_is_a_closed_enum() -> None:
    assert {o.value for o in PolicyOutcome} == {
        "ALLOWED",
        "HUMAN_APPROVAL_REQUIRED",
        "POLICY_BLOCKED",
        "READ_ONLY_VIOLATION",
    }


def test_allow_and_stop_helpers() -> None:
    a = allow("x")
    assert a.is_allowed and not a.is_stop
    s = stop(PolicyOutcome.POLICY_BLOCKED, "y", "because")
    assert s.is_stop and not s.is_allowed
    assert s.reasons == ["because"]


def test_policy_stop_carries_the_decision() -> None:
    decision = stop(PolicyOutcome.READ_ONLY_VIOLATION, "knowledge", "no writes")
    exc = PolicyStop(decision)
    assert exc.decision is decision
    assert "READ_ONLY_VIOLATION" in str(exc)


def test_decision_serialises_with_enum_value() -> None:
    decision = PolicyDecision(outcome=PolicyOutcome.HUMAN_APPROVAL_REQUIRED, subject="send")
    assert decision.model_dump()["outcome"] == "HUMAN_APPROVAL_REQUIRED"
