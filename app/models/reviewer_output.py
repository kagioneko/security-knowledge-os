"""The LLM Reviewer's output schema (decision A8).

The LLM can only *add* observations, questions, notes and suggestions. There is
deliberately **no field** for an overall status or for changing an existing
finding's status - the safest way to stop the LLM changing a deterministic
verdict is to never give it a field that could.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

# Codex#11 (round 5, 2026-09-12): this is UNTRUSTED, externally-produced
# content (a custom or misbehaving LLMClient, not just the vetted
# AnthropicClient) - a repro returning tens of thousands of observations in
# otherwise-valid JSON was parsed, converted to findings, and retained in
# the API's in-memory `_STORE`. These mirror the bounds already used for
# untrusted request input (app/models/assessment.py's `_Short`/`_Text`,
# list `max_length=200`) - free text is capped per-field and every list is
# capped per-item-count, so no single field or collection can grow without
# bound regardless of how much the underlying provider call is trusted.
_Short = Annotated[str, Field(max_length=500)]
_Text = Annotated[str, Field(max_length=20_000)]
_MAX_ITEMS = 200


class ObservationLevel(StrEnum):
    WARN = "WARN"
    UNKNOWN = "UNKNOWN"


class LLMObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: _Short = Field(min_length=1)
    detail: _Text = Field(min_length=1)
    level: ObservationLevel
    relates_to_risk_id: _Short | None = None  # a pointer for the reader; changes nothing
    evidence_refs: list[_Short] = Field(default_factory=list, max_length=_MAX_ITEMS)


class LLMQuestion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: _Text = Field(min_length=1)
    field: _Short | None = None
    why: _Text = ""


class LLMEvidenceNote(BaseModel):
    model_config = ConfigDict(extra="forbid")

    about: _Short
    note: _Text


class LLMSafeTestSuggestion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: _Short
    relates_to_risk_id: _Short | None = None
    idea: _Text


class ReviewerObservations(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observations: list[LLMObservation] = Field(default_factory=list, max_length=_MAX_ITEMS)
    questions: list[LLMQuestion] = Field(default_factory=list, max_length=_MAX_ITEMS)
    evidence_notes: list[LLMEvidenceNote] = Field(default_factory=list, max_length=_MAX_ITEMS)
    limitations: list[_Text] = Field(default_factory=list, max_length=_MAX_ITEMS)
    safe_test_suggestions: list[LLMSafeTestSuggestion] = Field(
        default_factory=list, max_length=_MAX_ITEMS
    )
