"""Retrieval-layer schemas: chunks and retrieval responses (spec Sections 10, 11)."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from app.models.knowledge import Classification, KnowledgeCategory


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
