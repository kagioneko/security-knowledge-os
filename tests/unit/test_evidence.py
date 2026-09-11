"""app/reviewer/evidence.py::available_evidence - decision A7.

Regression for SKOS-ADV-01 (Antigravity cross-review, 2026-09-11): an
unrecognized tool-permission string must not count as "specified".
"""

from __future__ import annotations

from app.models.assessment import AssessmentInput, ToolInput
from app.reviewer.evidence import available_evidence


def _input(**tool_kwargs: object) -> AssessmentInput:
    return AssessmentInput(name="t", tools=[ToolInput(name="mystery", **tool_kwargs)])


def test_known_permission_counts_as_specified() -> None:
    evidence = available_evidence(_input(permissions="write"))
    assert "tool_permissions_specified" in evidence


def test_missing_permission_does_not_count_as_specified() -> None:
    evidence = available_evidence(_input())
    assert "tool_permissions_specified" not in evidence


def test_unrecognized_permission_string_does_not_count_as_specified() -> None:
    """ADV-01: a non-empty but unrecognized string (e.g. "custom_permission" or
    "execute_root") must not satisfy tool_permissions_specified - it is not a
    known permission, so the rule engine must still see it as missing evidence
    (-> UNKNOWN), never as a validated, evaluable permission."""
    evidence = available_evidence(_input(permissions="custom_permission"))
    assert "tool_permissions_specified" not in evidence


def test_tool_policy_present_regardless_of_permission_validity() -> None:
    evidence = available_evidence(_input(permissions="custom_permission"))
    assert "tool_policy" in evidence
