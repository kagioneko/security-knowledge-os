"""Read-only Knowledge guard (spec Section 32, AC-13/AC-14).

During assessment the Knowledge Repository is read-only. Any mutating operation
returns a ``READ_ONLY_VIOLATION`` decision; ``guard_knowledge_operation`` raises
``PolicyStop`` so a caller cannot ignore it by accident.
"""

from __future__ import annotations

from enum import StrEnum

from app.models.policy_outcome import (
    PolicyDecision,
    PolicyOutcome,
    PolicyStop,
    allow,
    stop,
)


class KnowledgeOperation(StrEnum):
    READ = "read"
    LIST = "list"
    SEARCH = "search"
    WRITE = "write"
    UPDATE = "update"
    DELETE = "delete"
    CREATE = "create"
    INGEST = "ingest"
    REINDEX = "reindex"
    APPLY_PACK = "apply_pack"


_READ_OPS = {KnowledgeOperation.READ, KnowledgeOperation.LIST, KnowledgeOperation.SEARCH}


def evaluate_knowledge_operation(op: KnowledgeOperation | str) -> PolicyDecision:
    try:
        op = KnowledgeOperation(op)
    except ValueError:
        return stop(
            PolicyOutcome.READ_ONLY_VIOLATION,
            str(op),
            f"unknown knowledge operation '{op}'",
        )
    if op in _READ_OPS:
        return allow(op.value)
    return stop(
        PolicyOutcome.READ_ONLY_VIOLATION,
        op.value,
        "the knowledge repository is read-only during assessment; "
        "changes go through a separate review and maintenance workflow",
    )


def guard_knowledge_operation(op: KnowledgeOperation | str) -> PolicyDecision:
    decision = evaluate_knowledge_operation(op)
    if decision.is_stop:
        raise PolicyStop(decision)
    return decision
