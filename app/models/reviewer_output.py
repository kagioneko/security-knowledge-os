"""The LLM Reviewer's output schema (decision A8).

The LLM can only *add* observations, questions, notes and suggestions. There is
deliberately **no field** for an overall status or for changing an existing
finding's status - the safest way to stop the LLM changing a deterministic
verdict is to never give it a field that could.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ObservationLevel(StrEnum):
    WARN = "WARN"
    UNKNOWN = "UNKNOWN"


class LLMObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1)
    detail: str = Field(min_length=1)
    level: ObservationLevel
    relates_to_risk_id: str | None = None  # a pointer for the reader; changes nothing
    evidence_refs: list[str] = Field(default_factory=list)


class LLMQuestion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1)
    field: str | None = None
    why: str = ""


class LLMEvidenceNote(BaseModel):
    model_config = ConfigDict(extra="forbid")

    about: str
    note: str


class LLMSafeTestSuggestion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str
    relates_to_risk_id: str | None = None
    idea: str


class ReviewerObservations(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observations: list[LLMObservation] = Field(default_factory=list)
    questions: list[LLMQuestion] = Field(default_factory=list)
    evidence_notes: list[LLMEvidenceNote] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    safe_test_suggestions: list[LLMSafeTestSuggestion] = Field(default_factory=list)
