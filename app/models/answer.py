"""Typed answer patch for the ``/answers`` flow (M6.1).

A follow-up answer can only set fields on this allow-list. There is deliberately
**no generic / recursive merge** and **no field that carries a raw secret** - the
only credential-related answers are the storage *kind* and a boolean.

Unknown fields are rejected by the schema (``extra="forbid"``); unknown tool or
action names and type mismatches are rejected when the patch is applied.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

ToolPerm = Literal["read", "write", "delete", "send", "shell"]
MemoryScope = Literal["session", "user", "global"]
CredentialStorageKind = Literal["env", "vault", "proxy", "none"]


class AnswerPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    system_prompt: str | None = None
    developer_prompt: str | None = None

    rag_enabled: bool | None = None
    rag_sources: list[str] | None = None

    memory_enabled: bool | None = None
    memory_persistent: bool | None = None
    memory_scope: MemoryScope | None = None

    outbound_enabled: bool | None = None
    outbound_destinations: list[str] | None = None

    credential_storage: CredentialStorageKind | None = None
    credential_exposed_to_model: bool | None = None

    # {tool_name: permission} - the tool must already exist in the assessment
    tool_permissions: dict[str, ToolPerm] | None = None
    # {action: granted} - the action must be a known tool or outbound action
    human_approval: dict[str, bool] | None = None

    def is_empty(self) -> bool:
        return all(value is None for value in self.model_dump().values())
