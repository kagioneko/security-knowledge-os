"""M5 / AC-08: the Human Gate never auto-allows a high-impact action."""

from __future__ import annotations

import pytest

from app.models.policy_outcome import PolicyOutcome
from app.policy.human_gate import GATED_ACTIONS, SAFE_ACTIONS, evaluate_action


@pytest.mark.parametrize("kind", sorted(GATED_ACTIONS))
def test_gated_actions_require_human_approval(kind: str) -> None:
    decision = evaluate_action(kind)
    assert decision.outcome is PolicyOutcome.HUMAN_APPROVAL_REQUIRED
    assert decision.is_stop


@pytest.mark.parametrize(
    "alias", ["send", "email", "outbound_send", "delete", "shell", "payment", "get_credential"]
)
def test_aliases_are_gated(alias: str) -> None:
    assert evaluate_action(alias).outcome is PolicyOutcome.HUMAN_APPROVAL_REQUIRED


@pytest.mark.parametrize("kind", sorted(SAFE_ACTIONS))
def test_safe_actions_are_allowed(kind: str) -> None:
    assert evaluate_action(kind).is_allowed


def test_unknown_action_fails_closed() -> None:
    decision = evaluate_action("frobnicate_the_widgets")
    assert decision.outcome is PolicyOutcome.HUMAN_APPROVAL_REQUIRED
    assert "not on the safe allow-list" in " ".join(decision.reasons)


def test_no_action_ever_returns_a_bare_string() -> None:
    for kind in [*GATED_ACTIONS, *SAFE_ACTIONS, "???"]:
        assert isinstance(evaluate_action(kind).outcome, PolicyOutcome)
