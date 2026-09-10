"""The whitelist of facts a rule may reference, and how to derive them.

``FACT_SPEC`` is the single source of truth for what a rule clause's ``field`` may
be. ``build_facts`` turns a normalized ``AssessmentContext`` into a flat dict of
inert values. ``None`` means "not stated"; the string ``"unknown"`` is the same
for the enum-backed string facts.
"""

from __future__ import annotations

from enum import StrEnum

from app.models.context import AssessmentContext, ToolPermission

_HIGH_IMPACT = {
    ToolPermission.WRITE,
    ToolPermission.DELETE,
    ToolPermission.SEND,
    ToolPermission.SHELL,
}


class FactType(StrEnum):
    BOOL = "bool"        # bool | None
    STR = "str"          # str (may be the literal "unknown")
    STR_LIST = "str_list"  # list[str], always concrete (possibly empty)


FACT_SPEC: dict[str, FactType] = {
    "external_content_ingestion": FactType.BOOL,
    "retrieval_sources": FactType.STR_LIST,
    "input_channels": FactType.STR_LIST,
    "tool_names": FactType.STR_LIST,
    "tool_permissions": FactType.STR_LIST,
    "tools_present": FactType.BOOL,
    "tools_with_unknown_permission": FactType.BOOL,
    "has_write_tool": FactType.BOOL,
    "has_delete_tool": FactType.BOOL,
    "has_send_tool": FactType.BOOL,
    "has_shell_tool": FactType.BOOL,
    "has_any_high_impact_tool": FactType.BOOL,
    "has_unapproved_high_impact_tool": FactType.BOOL,
    "memory_enabled": FactType.BOOL,
    "memory_persistent": FactType.BOOL,
    "memory_scope": FactType.STR,
    "outbound_enabled": FactType.BOOL,
    "outbound_destinations": FactType.STR_LIST,
    "outbound_destinations_specified": FactType.BOOL,
    "outbound_without_approval": FactType.BOOL,
    "credential_storage": FactType.STR,
    "credential_exposed_to_model": FactType.BOOL,
    "human_approval_actions": FactType.STR_LIST,
    "high_impact_actions": FactType.STR_LIST,
    "high_impact_actions_present": FactType.BOOL,
    "high_impact_actions_all_approved": FactType.BOOL,
}

Fact = bool | str | list[str] | None


def _approved_actions(ctx: AssessmentContext) -> set[str]:
    return {action for action, granted in ctx.human_approval.items() if granted}


def _tool_is_approved(name: str, approved: set[str]) -> bool:
    return name in approved or f"tool:{name}" in approved


def _action_approved(action: str, approved: set[str]) -> bool:
    if action in approved:
        return True
    return action.startswith("tool:") and action[len("tool:") :] in approved


def build_facts(ctx: AssessmentContext) -> dict[str, Fact]:
    approved = _approved_actions(ctx)
    high_impact_tools = [t for t in ctx.tools if t.permission in _HIGH_IMPACT]
    unapproved = [
        t.name
        for t in high_impact_tools
        if not (t.requires_approval or _tool_is_approved(t.name, approved))
    ]
    permissions = sorted(
        {t.permission.value for t in ctx.tools if t.permission is not ToolPermission.UNKNOWN}
    )
    unknown_perm = any(t.permission is ToolPermission.UNKNOWN for t in ctx.tools)

    if ctx.outbound_enabled is None:
        outbound_without_approval: bool | None = None
    else:
        outbound_without_approval = ctx.outbound_enabled and not (
            "outbound_send" in approved or "outbound" in approved
        )

    if ctx.human_approval:
        all_approved: bool | None = all(
            _action_approved(action, approved) for action in ctx.high_impact_actions
        )
    else:
        all_approved = None if ctx.high_impact_actions else True

    return {
        "external_content_ingestion": ctx.external_content_ingestion,
        "retrieval_sources": sorted(ctx.retrieval_sources),
        "input_channels": sorted(ctx.input_channels),
        "tool_names": sorted(t.name for t in ctx.tools),
        "tool_permissions": permissions,
        "tools_present": bool(ctx.tools),
        "tools_with_unknown_permission": unknown_perm,
        "has_write_tool": any(t.permission is ToolPermission.WRITE for t in ctx.tools),
        "has_delete_tool": any(t.permission is ToolPermission.DELETE for t in ctx.tools),
        "has_send_tool": any(t.permission is ToolPermission.SEND for t in ctx.tools),
        "has_shell_tool": any(t.permission is ToolPermission.SHELL for t in ctx.tools),
        "has_any_high_impact_tool": bool(high_impact_tools),
        "has_unapproved_high_impact_tool": bool(unapproved),
        "memory_enabled": ctx.memory_enabled,
        "memory_persistent": ctx.memory_persistent,
        "memory_scope": ctx.memory_scope.value,
        "outbound_enabled": ctx.outbound_enabled,
        "outbound_destinations": sorted(ctx.outbound_destinations or []),
        "outbound_destinations_specified": ctx.outbound_destinations is not None,
        "outbound_without_approval": outbound_without_approval,
        "credential_storage": ctx.credential_storage.value,
        "credential_exposed_to_model": ctx.credential_exposed_to_model,
        "human_approval_actions": sorted(approved),
        "high_impact_actions": sorted(ctx.high_impact_actions),
        "high_impact_actions_present": bool(ctx.high_impact_actions),
        "high_impact_actions_all_approved": all_approved,
    }
