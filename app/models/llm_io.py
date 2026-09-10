"""Structured input handed to the LLM Reviewer.

Each concern is a separate, named field - deterministic findings, retrieved
knowledge, and the assessment context are never flattened into one prose blob.
The deterministic findings are a read-only view: the LLM sees them for context
and cannot echo a status change back (the output schema has no such field).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class DeterministicFindingView(BaseModel):
    risk_id: str
    title: str
    severity: str
    status: str
    reasoning: str


class RetrievedKnowledgeView(BaseModel):
    knowledge_id: str
    title: str
    source_ref: str
    section: str
    text: str


class ReviewPayload(BaseModel):
    assessment_context: dict[str, Any] = Field(default_factory=dict)
    attack_surface: dict[str, Any] = Field(default_factory=dict)
    deterministic_findings: list[DeterministicFindingView] = Field(default_factory=list)
    retrieved_knowledge: list[RetrievedKnowledgeView] = Field(default_factory=list)
