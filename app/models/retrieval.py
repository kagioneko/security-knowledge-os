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
        digest.update(value.encode("utf-8"))
        digest.update(b"\x00")
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
