"""M3: data-only clause evaluation and load-time validation."""

from __future__ import annotations

import pytest

from app.models.rule_clause import Clause, ClauseOutcome, Operator
from app.reviewer.clause_eval import ClauseError, evaluate_clause, validate_clause

FACTS = {
    "external_content_ingestion": True,
    "memory_persistent": None,
    "memory_scope": "unknown",
    "credential_storage": "env",
    "tool_permissions": ["read", "send"],
    "has_delete_tool": False,
}


def _c(field: str, op: Operator, value: object = None) -> Clause:
    return Clause(field=field, op=op, value=value)


@pytest.mark.parametrize(
    ("clause", "expected"),
    [
        (_c("external_content_ingestion", Operator.EQ, True), ClauseOutcome.TRUE),
        (_c("external_content_ingestion", Operator.NE, True), ClauseOutcome.FALSE),
        (_c("has_delete_tool", Operator.EQ, True), ClauseOutcome.FALSE),
        (_c("credential_storage", Operator.IN, ["env", "none"]), ClauseOutcome.TRUE),
        (_c("credential_storage", Operator.IN, ["vault"]), ClauseOutcome.FALSE),
        (_c("tool_permissions", Operator.CONTAINS, "send"), ClauseOutcome.TRUE),
        (_c("tool_permissions", Operator.CONTAINS, "delete"), ClauseOutcome.FALSE),
        (_c("memory_persistent", Operator.EQ, True), ClauseOutcome.UNKNOWN),
        (_c("memory_persistent", Operator.IS_UNKNOWN), ClauseOutcome.TRUE),
        (_c("memory_scope", Operator.EQ, "session"), ClauseOutcome.UNKNOWN),
        (_c("memory_scope", Operator.IS_UNKNOWN), ClauseOutcome.TRUE),
        (_c("credential_storage", Operator.IS_UNKNOWN), ClauseOutcome.FALSE),
    ],
)
def test_evaluate_clause_truth_table(clause: Clause, expected: ClauseOutcome) -> None:
    assert evaluate_clause(clause, FACTS) is expected


def test_string_value_is_never_executed() -> None:
    clause = _c("memory_scope", Operator.EQ, "__import__('os').system('true')")
    assert evaluate_clause(clause, {"memory_scope": "session"}) is ClauseOutcome.FALSE


def test_validate_clause_rejects_unknown_field() -> None:
    with pytest.raises(ClauseError):
        validate_clause(_c("totally_made_up", Operator.EQ, True))


def test_validate_clause_rejects_operator_type_mismatch() -> None:
    with pytest.raises(ClauseError):  # eq on a list fact
        validate_clause(_c("tool_permissions", Operator.EQ, "read"))
    with pytest.raises(ClauseError):  # contains on a bool fact
        validate_clause(_c("external_content_ingestion", Operator.CONTAINS, "x"))
    with pytest.raises(ClauseError):  # is_unknown on a list fact
        validate_clause(_c("tool_permissions", Operator.IS_UNKNOWN))


def test_validate_clause_rejects_bad_value_type() -> None:
    with pytest.raises(ClauseError):  # str value for a bool fact
        validate_clause(_c("external_content_ingestion", Operator.EQ, "true"))


def test_validate_clause_accepts_the_real_operators() -> None:
    validate_clause(_c("external_content_ingestion", Operator.EQ, True))
    validate_clause(_c("credential_storage", Operator.IN, ["env"]))
    validate_clause(_c("tool_permissions", Operator.CONTAINS, "delete"))
    validate_clause(_c("memory_persistent", Operator.IS_UNKNOWN))


def test_operator_set_is_closed() -> None:
    assert {op.value for op in Operator} == {"eq", "ne", "in", "contains", "is_unknown"}
