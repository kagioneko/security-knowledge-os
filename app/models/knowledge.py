"""Knowledge Unit schema (spec Section 7)."""

from __future__ import annotations

from datetime import date
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

KU_ID_PATTERN = r"^KU-\d{4}$"


class Classification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"


class KnowledgeCategory(StrEnum):
    PROMPT_SECURITY = "prompt-security"
    RAG_SECURITY = "rag-security"
    AGENT_SECURITY = "agent-security"
    MEMORY_SECURITY = "memory-security"
    CREDENTIAL_SECURITY = "credential-security"
    INCIDENT = "incident"
    METHODOLOGY = "methodology"
    GOVERNANCE = "governance"


class SourceType(StrEnum):
    NOTE = "note"
    GITHUB = "github"
    GDRIVE = "gdrive"
    EXPERIMENT = "experiment"
    INCIDENT = "incident"
    STANDARD = "standard"
    MANUAL = "manual"


class KnowledgeStatus(StrEnum):
    DRAFT = "draft"
    REVIEWED = "reviewed"
    APPROVED = "approved"
    DEPRECATED = "deprecated"


class KnowledgeUnitFrontMatter(BaseModel):
    """The YAML front matter block of a Knowledge Unit file."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=KU_ID_PATTERN)
    title: str = Field(min_length=1)
    category: KnowledgeCategory
    source_type: SourceType
    source_ref: str = Field(min_length=1)
    classification: Classification
    status: KnowledgeStatus
    risk_ids: list[str] = Field(default_factory=list)
    version: str = Field(min_length=1)
    last_reviewed: date
    requires_ip_review: bool

    @field_validator("title", "source_ref", "version")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("must not be blank")
        return stripped


class KnowledgeUnit(BaseModel):
    """A parsed Knowledge Unit: front matter + body + provenance."""

    front_matter: KnowledgeUnitFrontMatter
    body: str
    source_path: str

    @property
    def id(self) -> str:
        return self.front_matter.id

    @property
    def classification(self) -> Classification:
        return self.front_matter.classification
