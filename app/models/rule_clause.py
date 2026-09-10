"""Data-only rule clause schema.

A clause is a single comparison between one whitelisted fact key and a literal,
using one whitelisted operator. There is no expression language, no ``eval``, no
dynamic dispatch: a clause is inert data that the engine interprets.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

Scalar = str | bool | int


class Operator(StrEnum):
    EQ = "eq"
    NE = "ne"
    IN = "in"
    CONTAINS = "contains"
    IS_UNKNOWN = "is_unknown"


class ClauseOutcome(StrEnum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


class Clause(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    field: str
    op: Operator
    value: Scalar | list[Scalar] | None = None

    def describe(self) -> str:
        if self.op is Operator.IS_UNKNOWN:
            return f"{self.field} is_unknown"
        return f"{self.field} {self.op.value} {self.value!r}"
