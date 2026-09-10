"""AssessmentContext - the normalized, rule-bindable view of an assessment target.

Produced by Input Normalization (spec Section 12, step 1). This type does not exist
in the spec; it is decision A4 (2026-09-10): deterministic rules bind ONLY to these
explicit fields, never to free-form prompt text.

``None`` means "not stated in the input" and must drive an ``UNKNOWN`` verdict
(decision A7). It must never be treated as an assumed ``False``.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class ToolPermission(StrEnum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    SEND = "send"
    SHELL = "shell"
    UNKNOWN = "unknown"


class MemoryScope(StrEnum):
    SESSION = "session"
    USER = "user"
    GLOBAL = "global"
    UNKNOWN = "unknown"


class CredentialStorage(StrEnum):
    ENV = "env"
    VAULT = "vault"
    PROXY = "proxy"
    NONE = "none"
    UNKNOWN = "unknown"


class ToolSpec(BaseModel):
    name: str
    permission: ToolPermission = ToolPermission.UNKNOWN
    requires_approval: bool | None = None
    known: bool = True


class AssessmentContext(BaseModel):
    input_channels: list[str] = Field(default_factory=list)
    external_content_ingestion: bool | None = None
    retrieval_sources: list[str] = Field(default_factory=list)
    tools: list[ToolSpec] = Field(default_factory=list)
    memory_enabled: bool | None = None
    memory_persistent: bool | None = None
    memory_scope: MemoryScope = MemoryScope.UNKNOWN
    outbound_enabled: bool | None = None
    outbound_destinations: list[str] | None = None
    credential_storage: CredentialStorage = CredentialStorage.UNKNOWN
    credential_exposed_to_model: bool | None = None
    human_approval: dict[str, bool] = Field(default_factory=dict)
    high_impact_actions: list[str] = Field(default_factory=list)
