"""Apply a typed AnswerPatch to an AssessmentInput (M6.1 / M6.2).

The patched input is re-assessed from the start (normalize -> rules -> retrieval ->
LLM -> roll-up). Findings are never edited in place, so a partially-answered
assessment cannot end up internally inconsistent.

What is rejected: an unknown patch field (schema ``extra="forbid"``), a permission
value outside the closed enum, or a type mismatch (all handled by ``AnswerPatch``
itself). **Tool names are not a fixed vocabulary** - a diagnosed system can have
any tool name - so:

  * ``tool_permissions[<existing tool>]``  -> replace that tool's permission
  * ``tool_permissions[<new name>]``       -> add the tool to the assessment
  * ``human_approval[<action>]``           -> merged as-is (an action key is a name)

A high-impact permission (write / delete / send / shell) that a patch introduces
is a first-class re-evaluation target: the rule engine sees the new tool.
"""

from __future__ import annotations

from pydantic import ValidationError

from app.models.answer import AnswerPatch
from app.models.assessment import AssessmentInput
from app.safe_errors import format_loc


class AnswerValidationError(ValueError):
    """Kept for the API layer; structural rejection is done by the AnswerPatch schema."""

    def __init__(self, reasons: list[str]) -> None:
        super().__init__("; ".join(reasons))
        self.reasons = reasons


def apply_patch(original: AssessmentInput, patch: AnswerPatch) -> AssessmentInput:
    data = original.model_dump()

    if patch.system_prompt is not None:
        data["system_prompt"] = patch.system_prompt
    if patch.developer_prompt is not None:
        data["developer_prompt"] = patch.developer_prompt

    if patch.rag_enabled is not None:
        data["rag"]["enabled"] = patch.rag_enabled
    if patch.rag_sources is not None:
        data["rag"]["sources"] = list(patch.rag_sources)

    if patch.memory_enabled is not None:
        data["memory"]["enabled"] = patch.memory_enabled
    if patch.memory_persistent is not None:
        data["memory"]["persistent"] = patch.memory_persistent
    if patch.memory_scope is not None:
        data["memory"]["scope"] = patch.memory_scope

    if patch.outbound_enabled is not None:
        data["outbound"]["enabled"] = patch.outbound_enabled
    if patch.outbound_destinations is not None:
        data["outbound"]["destinations"] = list(patch.outbound_destinations)

    if patch.credential_storage is not None:
        data["credentials"]["storage"] = patch.credential_storage
    if patch.credential_exposed_to_model is not None:
        data["credentials"]["exposed_to_model"] = (
            "true" if patch.credential_exposed_to_model else "false"
        )

    if patch.tool_permissions is not None:
        by_name = {tool["name"]: tool for tool in data["tools"]}
        for name, perm in patch.tool_permissions.items():
            if name in by_name:
                by_name[name]["permissions"] = perm  # replace an existing tool's permission
            else:
                data["tools"].append(
                    {"name": name, "permissions": perm, "requires_approval": None}
                )

    if patch.human_approval is not None:
        data["human_approval"].update(patch.human_approval)

    try:
        return AssessmentInput.model_validate(data)
    except ValidationError as exc:
        # Codex cross-review finding #6 (round 3, 2026-09-12): AnswerPatch's
        # own per-field bounds catch an oversized single field, but a merge
        # can still exceed AssessmentInput's bounds even when every patched
        # field is individually within limits - e.g. tool_permissions adding
        # names to an already-near-the-cap `tools` list, or the merged total
        # size exceeding AssessmentInput's own total-size guard. That raised
        # pydantic's ValidationError here, uncaught - the API layer only
        # catches AnswerValidationError, so this escaped as an HTTP 500
        # instead of the controlled 422 every other rejection in this module
        # produces.
        reasons = [
            f"{format_loc(err['loc'])}: {err['msg']}"
            for err in exc.errors(include_input=False, include_url=False)
        ]
        raise AnswerValidationError(reasons) from exc
