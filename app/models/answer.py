"""Typed answer patch for the ``/answers`` flow (M6.1).

A follow-up answer can only set fields on this allow-list. There is deliberately
**no generic / recursive merge** and **no DEDICATED raw-secret-value field** -
the only credential-related answers are the storage *kind* (a closed enum) and
a boolean, never a value.

Codex#12 (round 7, 2026-09-12), reproduced exactly as reported: this used to
read "no field that carries a raw secret", which a test only ever checked by
FIELD NAME. That is stronger than the schema actually provides: every free-text
field here (``system_prompt``, ``developer_prompt``, RAG/outbound strings, tool
names, approval keys) accepts arbitrary text, including a value that happens to
look like a credential - nothing in this schema detects or redacts one. The
narrower, accurate claim is the one above: no field is *dedicated* to holding a
credential value.

Codex#2 (round 9, 2026-09-12): the above became "does not satisfy the stated
boundary" once a credential-shaped free-text value was traced flowing into
AttackSurface and the ReviewPayload sent to an external LLM provider. Every
free-text field here now rejects the concrete, unambiguous credential SHAPES
``app/models/_credential_shapes.py`` recognizes (the same ones
``scripts/secret_scan.py`` / ``app/policy/safe_test.py`` already treat as
unambiguously secret-shaped). This still cannot catch every possible secret -
an arbitrary opaque string is indistinguishable from ordinary free text - so
storing a real secret anywhere in an assessment remains against this
project's Vault-only credential policy regardless of what this schema
happens to accept.

Unknown fields are rejected by the schema (``extra="forbid"``); unknown tool or
action names and type mismatches are rejected when the patch is applied.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from app.models._credential_shapes import reject_credential_shapes, reject_non_identifier_shapes

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
#
# Codex#2 (round 9, 2026-09-12): every free-text field here accepted
# arbitrary text, including a value shaped like a real credential, which
# then flowed unchanged into AttackSurface and the ReviewPayload sent to
# an external LLM provider. reject_credential_shapes rejects the same
# concrete, unambiguous secret SHAPES secret_scan.py / safe_test.py
# already recognize - see app/models/_credential_shapes.py.
_Text = Annotated[str, Field(max_length=50_000), AfterValidator(reject_credential_shapes)]
# Codex#12 (round 7, 2026-09-12): the two scalar bounds above were never
# applied to LIST ELEMENTS or MAPPING KEYS - rag_sources/outbound_destinations
# capped the number of entries (200) but not each entry's length, and
# tool_permissions/human_approval capped the number of keys but not each key's
# length. Mirrors AssessmentInput's identical `_Short = Annotated[str,
# Field(max_length=500)]` convention (app/models/assessment.py).
#
# Codex#1 (round 13, 2026-09-13): every field using `_ShortItem` (RAG
# sources, outbound destinations, tool/approval names) is identifier-
# shaped BY CONTRACT, unlike `_Text` above (actual prompt prose) - so it
# also gets `reject_non_identifier_shapes`, the allowlist half of the
# credential-shape defense (app/models/_credential_shapes.py's own
# docstring explains why both a denylist and an allowlist are applied).
_ShortItem = Annotated[
    str,
    Field(max_length=500),
    AfterValidator(reject_credential_shapes),
    AfterValidator(reject_non_identifier_shapes),
]


class AnswerPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    system_prompt: _Text | None = None
    developer_prompt: _Text | None = None

    rag_enabled: bool | None = None
    rag_sources: list[_ShortItem] | None = Field(default=None, max_length=200)

    memory_enabled: bool | None = None
    memory_persistent: bool | None = None
    memory_scope: MemoryScope | None = None

    outbound_enabled: bool | None = None
    outbound_destinations: list[_ShortItem] | None = Field(default=None, max_length=200)

    credential_storage: CredentialStorageKind | None = None
    credential_exposed_to_model: bool | None = None

    # {tool_name: permission} - the tool must already exist in the assessment
    tool_permissions: dict[_ShortItem, ToolPerm] | None = Field(default=None, max_length=200)
    # {action: granted} - the action must be a known tool or outbound action
    human_approval: dict[_ShortItem, bool] | None = Field(default=None, max_length=200)

    def is_empty(self) -> bool:
        return all(value is None for value in self.model_dump().values())
