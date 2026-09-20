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


class Derivation(StrEnum):
    """How this Knowledge Unit relates to its cited source."""

    ORIGINAL = "original"      # entirely our own analysis
    SUMMARY = "summary"        # our own prose summarising a publicly documented concept
    ADAPTATION = "adaptation"  # reworded / restructured from a specific source
    QUOTATION = "quotation"    # contains verbatim quoted material from the source


class Provenance(BaseModel):
    """Where a Knowledge Unit's content comes from and how it may be used
    (required before public release - see docs/attribution.md)."""

    model_config = ConfigDict(extra="forbid")

    source_title: str = Field(min_length=1)
    source_url: str | None = None
    source_version: str | None = None  # version or publication date of the source
    source_license: str = Field(min_length=1)  # licence / usage terms of the SOURCE
    derivation: Derivation
    last_verified: date
    usage_note: str | None = None


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
    # Codex nit (round 29, 2026-09-20), reproduced exactly as reported: an
    # unbounded list let a ~18 KB document with 9,000 malformed ids produce
    # 9,010 warnings and a ~890 KB response from POST /v1/knowledge/validate.
    # Real units reference a handful of rules; 200 is far above any of them.
    risk_ids: list[str] = Field(default_factory=list, max_length=200)
    version: str = Field(min_length=1)
    last_reviewed: date
    requires_ip_review: bool
    provenance: Provenance

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
