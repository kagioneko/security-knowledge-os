"""M5 / AC-13: the Knowledge Repository is read-only during assessment."""

from __future__ import annotations

import pytest

from app.models.policy_outcome import PolicyOutcome, PolicyStop
from app.policy.knowledge_guard import (
    KnowledgeOperation,
    evaluate_knowledge_operation,
    guard_knowledge_operation,
)


@pytest.mark.parametrize("op", ["read", "list", "search"])
def test_read_operations_are_allowed(op: str) -> None:
    assert evaluate_knowledge_operation(op).is_allowed


@pytest.mark.parametrize(
    "op", ["write", "update", "delete", "create", "ingest", "reindex", "apply_pack"]
)
def test_write_operations_are_read_only_violations(op: str) -> None:
    decision = evaluate_knowledge_operation(op)
    assert decision.outcome is PolicyOutcome.READ_ONLY_VIOLATION


def test_unknown_operation_is_read_only_violation() -> None:
    assert (
        evaluate_knowledge_operation("exfiltrate").outcome
        is PolicyOutcome.READ_ONLY_VIOLATION
    )


def test_guard_raises_policy_stop_on_write() -> None:
    with pytest.raises(PolicyStop) as excinfo:
        guard_knowledge_operation(KnowledgeOperation.WRITE)
    assert excinfo.value.decision.outcome is PolicyOutcome.READ_ONLY_VIOLATION


def test_guard_returns_decision_on_read() -> None:
    assert guard_knowledge_operation(KnowledgeOperation.READ).is_allowed
