"""Typed answer patch for the ``/answers`` flow (M6.1).

A follow-up answer can only set fields on this allow-list. There is deliberately
**no generic / recursive merge** and **no field that carries a raw secret** - the
only credential-related answers are the storage *kind* and a boolean.

Unknown fields are rejected by the schema (``extra="forbid"``); unknown tool or
action names and type mismatches are rejected when the patch is applied.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ToolPerm = Literal["read", "write", "delete", "send", "shell"]
MemoryScope = Literal["session", "user", "global"]
CredentialStorageKind = Literal["env", "vault", "proxy", "none"]

# Codex cross-review finding #6 (round 3, 2026-09-12): AnswerPatch had none of
# AssessmentInput's field-level bounds, so an oversized patch (e.g. a 50,001
# character system_prompt, 201 rag_sources, a 201-character tool name) passed
# this schema untouched and only failed later, when apply_patch() re-validates
# the merged AssessmentInput - see the try/except around that call below for
# why that used to be an HTTP 500. Mirroring AssessmentInput's bounds here
# rejects an oversized patch immediately, with FastAPI's normal 422.
_Short = Field(default=None, max_length=500)
_Text = Field(default=None, max_length=50_000)


class AnswerPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    system_prompt: str | None = _Text
    developer_prompt: str | None = _Text

    rag_enabled: bool | None = None
    rag_sources: list[str] | None = Field(default=None, max_length=200)

    memory_enabled: bool | None = None
    memory_persistent: bool | None = None
    memory_scope: MemoryScope | None = None

    outbound_enabled: bool | None = None
    outbound_destinations: list[str] | None = Field(default=None, max_length=200)

    credential_storage: CredentialStorageKind | None = None
    credential_exposed_to_model: bool | None = None

    # {tool_name: permission} - the tool must already exist in the assessment
    tool_permissions: dict[str, ToolPerm] | None = Field(default=None, max_length=200)
    # {action: granted} - the action must be a known tool or outbound action
    human_approval: dict[str, bool] | None = Field(default=None, max_length=200)

    def is_empty(self) -> bool:
        return all(value is None for value in self.model_dump().values())
