"""Input Normalization (spec Section 12, step 1): AssessmentInput -> AssessmentContext.

Deterministic and conservative. Anything not stated in the input becomes ``None``
or ``unknown`` in the context, never an assumed value (decision A4 / A7).
"""

from __future__ import annotations

from app.models.assessment import AssessmentInput
from app.models.context import (
    AssessmentContext,
    CredentialStorage,
    MemoryScope,
    ToolPermission,
    ToolSpec,
)

# Retrieval sources that carry untrusted, externally-authored content.
_UNTRUSTED_SOURCES = {
    "web",
    "internet",
    "uploaded_documents",
    "uploads",
    "user_uploads",
    "email",
    "pdf",
    "external",
    "external_documents",
    "attachments",
}

_PERMISSION_ALIASES = {
    "read": ToolPermission.READ,
    "read-only": ToolPermission.READ,
    "readonly": ToolPermission.READ,
    "write": ToolPermission.WRITE,
    "delete": ToolPermission.DELETE,
    "send": ToolPermission.SEND,
    "email": ToolPermission.SEND,
    "shell": ToolPermission.SHELL,
    "exec": ToolPermission.SHELL,
    "execute": ToolPermission.SHELL,
}

_HIGH_IMPACT = {
    ToolPermission.WRITE,
    ToolPermission.DELETE,
    ToolPermission.SEND,
    ToolPermission.SHELL,
}

_TRUTHY = {"true", "yes", "1"}
_FALSY = {"false", "no", "0"}


def _parse_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.strip().casefold()
    if lowered in _TRUTHY:
        return True
    if lowered in _FALSY:
        return False
    return None  # "unknown" and anything unrecognised


def parse_permission(value: str | None) -> ToolPermission:
    if value is None:
        return ToolPermission.UNKNOWN
    return _PERMISSION_ALIASES.get(value.strip().casefold(), ToolPermission.UNKNOWN)


def _parse_memory_scope(value: str | None) -> MemoryScope:
    if value is None:
        return MemoryScope.UNKNOWN
    try:
        return MemoryScope(value.strip().casefold())
    except ValueError:
        return MemoryScope.UNKNOWN


def _parse_credential_storage(value: str | None) -> CredentialStorage:
    if value is None:
        return CredentialStorage.UNKNOWN
    try:
        return CredentialStorage(value.strip().casefold())
    except ValueError:
        return CredentialStorage.UNKNOWN


def _external_content_ingestion(inp: AssessmentInput) -> bool | None:
    if inp.rag.enabled is None:
        return None
    if inp.rag.enabled is False:
        return False
    return any(source.strip().casefold() in _UNTRUSTED_SOURCES for source in inp.rag.sources)


def to_context(inp: AssessmentInput) -> AssessmentContext:
    tools = [
        ToolSpec(
            name=tool.name,
            permission=parse_permission(tool.permissions),
            requires_approval=(
                tool.requires_approval
                if tool.requires_approval is not None
                else inp.human_approval.get(tool.name)
            ),
        )
        for tool in inp.tools
    ]

    if inp.outbound.enabled and inp.outbound.destinations:
        outbound_destinations: list[str] | None = list(inp.outbound.destinations)
    else:
        outbound_destinations = None

    if inp.memory.enabled is False:
        memory_persistent: bool | None = False
    elif inp.memory.enabled is True:
        memory_persistent = inp.memory.persistent
    else:
        memory_persistent = None

    high_impact_actions: list[str] = [
        f"tool:{tool.name}" for tool in tools if tool.permission in _HIGH_IMPACT
    ]
    if inp.outbound.enabled:
        high_impact_actions.append("outbound_send")

    input_channels = ["user"]
    if inp.developer_prompt is not None:
        input_channels.append("developer")
    if inp.rag.enabled:
        input_channels.append("retrieval")

    return AssessmentContext(
        input_channels=input_channels,
        external_content_ingestion=_external_content_ingestion(inp),
        retrieval_sources=list(inp.rag.sources) if inp.rag.enabled else [],
        tools=tools,
        memory_enabled=inp.memory.enabled,
        memory_persistent=memory_persistent,
        memory_scope=_parse_memory_scope(inp.memory.scope),
        outbound_enabled=inp.outbound.enabled,
        outbound_destinations=outbound_destinations,
        credential_storage=_parse_credential_storage(inp.credentials.storage),
        credential_exposed_to_model=_parse_bool(inp.credentials.exposed_to_model),
        human_approval=dict(inp.human_approval),
        high_impact_actions=high_impact_actions,
    )
