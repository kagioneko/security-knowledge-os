"""M3 additional requirement: rules are data, never code.

No eval / exec / compile / __import__ / getattr-dispatch anywhere on the rule
evaluation path, and the operator set is a closed enum.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.models.rule_clause import Clause, Operator
from app.reviewer import (
    assess,
    attack_surface,
    clause_eval,
    facts,
    normalize,
    rollup,
    rule_engine,
    rule_loader,
)
from app.reviewer.clause_eval import evaluate_clause

_FORBIDDEN = ("eval(", "exec(", "compile(", "__import__", "os.system", "subprocess")
_EVAL_PATH_MODULES = [
    clause_eval,
    rule_engine,
    rule_loader,
    facts,
    normalize,
    attack_surface,
    rollup,
    assess,
]


@pytest.mark.parametrize("module", _EVAL_PATH_MODULES, ids=lambda m: m.__name__)
def test_no_dynamic_execution_primitives_in_source(module: object) -> None:
    source = Path(module.__file__).read_text(encoding="utf-8")  # type: ignore[attr-defined]
    for token in _FORBIDDEN:
        assert token not in source, f"{module.__name__} contains {token!r}"


def test_operator_enum_is_closed() -> None:
    assert {op.value for op in Operator} == {"eq", "ne", "in", "contains", "is_unknown"}


def test_clause_with_unlisted_operator_fails_validation() -> None:
    with pytest.raises(ValueError):
        Clause.model_validate({"field": "memory_scope", "op": "shell", "value": "x"})


def test_malicious_looking_literal_is_inert() -> None:
    # A value that looks like code is compared as a plain string, nothing runs.
    clause = Clause(field="credential_storage", op=Operator.EQ, value="; rm -rf /")
    assert evaluate_clause(clause, {"credential_storage": "env"}).value == "false"


def test_unknown_field_at_eval_time_is_unknown_not_error() -> None:
    clause = Clause(field="not_a_fact", op=Operator.EQ, value=True)
    assert evaluate_clause(clause, {}).value == "unknown"
