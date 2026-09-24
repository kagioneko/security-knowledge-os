"""Interpret a data-only clause against a fact dict. No code execution.

``evaluate_clause`` is a pure function: dict lookup plus a fixed set of typed
comparisons. ``validate_clause`` rejects a clause whose field is not whitelisted
or whose operator does not match the field's type (used at rule-load time).
"""

from __future__ import annotations

from app.models.rule_clause import Clause, ClauseOutcome, Operator
from app.reviewer.facts import FACT_SPEC, Fact, FactType

_UNKNOWN_STR = "unknown"


class ClauseError(ValueError):
    """A clause is not evaluable: unknown field or operator/type mismatch."""


def validate_clause(clause: Clause) -> None:
    fact_type = FACT_SPEC.get(clause.field)
    if fact_type is None:
        # Codex round-31 (2026-09-25): Clause.field is an unconstrained str
        # (no format validation), so echoing it here put arbitrary
        # rule-authored content into a ClauseError message that
        # rule_problems() folds into RuleLoadError's own message. The fixed,
        # known-safe allowed-fact list is kept; the offending value is not.
        raise ClauseError(f"unknown fact (not in the allowed set: {sorted(FACT_SPEC)})")

    op = clause.op
    if op is Operator.IS_UNKNOWN:
        if fact_type is FactType.STR_LIST:
            raise ClauseError("is_unknown is not valid for a list fact")
        if clause.value is not None:
            raise ClauseError("is_unknown takes no value")
        return

    if op in (Operator.EQ, Operator.NE):
        if fact_type is FactType.STR_LIST:
            raise ClauseError(f"{op.value} is not valid for a list fact")
        _require_scalar(clause, fact_type)
        return

    if op is Operator.IN:
        if fact_type is FactType.STR_LIST:
            raise ClauseError("in is not valid for a list fact")
        if not isinstance(clause.value, list) or not clause.value:
            raise ClauseError("in requires a non-empty list value")
        for item in clause.value:
            _require_scalar_value(item, fact_type)
        return

    if op is Operator.CONTAINS:
        if fact_type is not FactType.STR_LIST:
            raise ClauseError("contains is only valid for a list fact")
        if not isinstance(clause.value, str):
            raise ClauseError("contains requires a string value")
        return


def _require_scalar(clause: Clause, fact_type: FactType) -> None:
    if isinstance(clause.value, list) or clause.value is None:
        raise ClauseError(f"{clause.op.value} requires a scalar value")
    _require_scalar_value(clause.value, fact_type)


def _require_scalar_value(value: object, fact_type: FactType) -> None:
    if fact_type is FactType.BOOL and not isinstance(value, bool):
        raise ClauseError("a bool fact takes a bool value")
    if fact_type is FactType.STR and not isinstance(value, str):
        raise ClauseError("a str fact takes a str value")


def evaluate_clause(clause: Clause, facts: dict[str, Fact]) -> ClauseOutcome:
    value = facts.get(clause.field)

    if clause.op is Operator.IS_UNKNOWN:
        is_unknown = value is None or value == _UNKNOWN_STR
        return ClauseOutcome.TRUE if is_unknown else ClauseOutcome.FALSE

    if value is None or value == _UNKNOWN_STR:
        return ClauseOutcome.UNKNOWN

    if clause.op is Operator.EQ:
        return _bool(value == clause.value)
    if clause.op is Operator.NE:
        return _bool(value != clause.value)
    if clause.op is Operator.IN:
        assert isinstance(clause.value, list)
        return _bool(value in clause.value)
    if clause.op is Operator.CONTAINS:
        assert isinstance(value, list)
        return _bool(clause.value in value)

    raise ClauseError(f"unhandled operator {clause.op}")  # pragma: no cover


def _bool(result: bool) -> ClauseOutcome:
    return ClauseOutcome.TRUE if result else ClauseOutcome.FALSE
