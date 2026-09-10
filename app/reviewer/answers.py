"""Apply a typed AnswerPatch to an AssessmentInput (M6.1).

The patched input is re-assessed from the start (normalize -> rules -> retrieval ->
LLM -> roll-up). Findings are never edited in place, so a partially-answered
assessment cannot end up internally inconsistent.
"""

from __future__ import annotations

from app.models.answer import AnswerPatch
from app.models.assessment import AssessmentInput

_OUTBOUND_ACTIONS = {"outbound_send", "outbound"}


class AnswerValidationError(ValueError):
    def __init__(self, reasons: list[str]) -> None:
        super().__init__("; ".join(reasons))
        self.reasons = reasons


def apply_patch(original: AssessmentInput, patch: AnswerPatch) -> AssessmentInput:
    data = original.model_dump()
    reasons: list[str] = []

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

    known_tools = {tool["name"] for tool in data["tools"]}

    if patch.tool_permissions is not None:
        for name, perm in patch.tool_permissions.items():
            if name not in known_tools:
                reasons.append(f"unknown tool '{name}'")
                continue
            for tool in data["tools"]:
                if tool["name"] == name:
                    tool["permissions"] = perm

    if patch.human_approval is not None:
        allowed = known_tools | _OUTBOUND_ACTIONS | set(data["human_approval"])
        for action, granted in patch.human_approval.items():
            if action not in allowed:
                reasons.append(f"unknown approval action '{action}'")
                continue
            data["human_approval"][action] = granted

    if reasons:
        raise AnswerValidationError(reasons)

    return AssessmentInput.model_validate(data)
