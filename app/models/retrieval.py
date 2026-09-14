"""Retrieval-layer schemas: chunks and retrieval responses (spec Sections 10, 11)."""

from __future__ import annotations

import hashlib
from enum import StrEnum

from pydantic import BaseModel, Field

from app.models.knowledge import Classification, KnowledgeCategory


def chunk_content_hash(
    *,
    chunk_id: str,
    knowledge_id: str,
    title: str,
    source_ref: str,
    classification: str,
    category: str,
    version: str,
    section: str,
    text: str,
) -> str:
    """Codex#1 (round 6, 2026-09-12), reproduced exactly as reported: the
    stored per-chunk hash covered only `text` - `classification`,
    `source_ref`, `knowledge_id`, `title`, `section`, and `version` were all
    trusted independently. `UPDATE chunks SET classification='public' WHERE
    knowledge_id='KU-1020'` (a confidential unit) passed
    `verify_chunk_hashes()` as ALLOWED, and a PUBLIC-mode retrieval then
    returned the confidential content. Every security-relevant field is now
    covered by the one digest `text` alone used to be.

    Shared by `app/retrieval/index.py` (computes it when writing a chunk)
    and `app/storage/integrity.py` (recomputes it from the stored row to
    verify) so the two can never independently drift on what "covered"
    means - a field added to `Chunk` and forgotten in only one of the two
    call sites would silently narrow the check back down.

    Codex#3 / Antigravity SKOS-ADV-29 (round 21, 2026-09-15), reproduced
    exactly as reported: NUL-separating the fields (`value.encode() +
    b"\x00"` per field) is NOT injective - YAML front matter freely
    permits an embedded NUL byte in a quoted scalar (`source_ref:
    "x\0public\0rag-security"`), so a NUL inside one field's own content
    is indistinguishable, once hashed, from the field-separator NUL
    between two DIFFERENT fields. A chunk originally hashed as
    `(source_ref="x\0public\0rag-security", classification="confidential",
    category="agent-security", version="1")` produces the EXACT SAME byte
    stream - and therefore the exact same SHA-256 digest - as
    `(source_ref="x", classification="public", category="rag-security",
    version="confidential\0agent-security\0" + "1")`: a local attacker
    with write access to the index file (the same threat this hash exists
    to catch in the first place, per the round-6 comment above) could
    rewrite a CONFIDENTIAL row's classification to "public" while shifting
    the excess bytes into an adjacent field, and `verify_chunk_hashes()`
    would still report ALLOWED - a complete, silent bypass of the
    classification gate this hash is the sole integrity guard for.
    Length-prefixing each field (a netstring-style `<byte-length>:<bytes>`
    per field, all concatenated into one digest) is unambiguous regardless
    of what bytes a field contains: the byte length is read BEFORE the
    field's own content is consumed, so no content-internal byte -
    including a NUL, a digit, or a ':' - can ever be mistaken for a field
    boundary. Reading back byte-for-byte in the exact reverse order
    (length, then that many bytes, per field) always reconstructs exactly
    one (chunk_id, knowledge_id, ..., text) tuple - the encoding is
    injective by construction, closing this collision class entirely
    rather than just this one NUL-byte instance of it.
    """
    digest = hashlib.sha256()
    for value in (
        chunk_id,
        knowledge_id,
        title,
        source_ref,
        classification,
        category,
        version,
        section,
        text,
    ):
        encoded = value.encode("utf-8")
        digest.update(f"{len(encoded)}:".encode("ascii"))
        digest.update(encoded)
    return digest.hexdigest()


class QueryCategory(StrEnum):
    PROMPT = "prompt"
    RAG = "rag"
    AGENT = "agent"
    TOOL = "tool"
    MEMORY = "memory"
    CREDENTIAL = "credential"
    GOVERNANCE = "governance"
    INCIDENT = "incident"


class Chunk(BaseModel):
    """One retrievable section of a Knowledge Unit (spec Section 10)."""

    chunk_id: str
    knowledge_id: str
    title: str
    source_ref: str
    classification: Classification
    category: KnowledgeCategory
    version: str
    section: str
    text: str
    hash: str

    @property
    def search_text(self) -> str:
        return "\n".join(part for part in (self.title, self.section, self.text) if part).strip()


class RetrievedChunk(BaseModel):
    chunk: Chunk
    score: float
    rank: int


class RetrievalResponse(BaseModel):
    query: str
    query_categories: list[QueryCategory] = Field(default_factory=list)
    mode: str
    knowledge_revision: str
    results: list[RetrievedChunk] = Field(default_factory=list)
