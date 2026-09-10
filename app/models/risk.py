"""Risk rule and finding schemas (spec Sections 8 and 17).

The ``Finding`` model enforces decision A8 (2026-09-10): the LLM layer can never
create or clear a deterministic ``FAIL``.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.knowledge import KnowledgeCategory
from app.models.rule_clause import Clause

# Rule ids: PI-003, MEM-001, TOOL-002, CRED-001, ... and LLM-OBS-00001 for LLM findings.
RULE_ID_PATTERN = r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*-\d{3,}$"
LLM_OBS_PREFIX = "LLM-OBS-"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NA = "N/A"


class RuleConditions(BaseModel):
    """Trigger conditions, expressed as data-only clauses over whitelisted facts.

    A rule triggers when every clause in ``all`` is TRUE and (if ``any`` is
    non-empty) at least one clause in ``any`` is TRUE.
    """

    model_config = ConfigDict(extra="forbid")

    all: list[Clause] = Field(default_factory=list)
    any: list[Clause] = Field(default_factory=list)


class RiskRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=RULE_ID_PATTERN)
    title: str = Field(min_length=1)
    category: KnowledgeCategory
    severity: Severity
    conditions: RuleConditions = Field(default_factory=RuleConditions)
    checks: list[Clause] = Field(default_factory=list)
    required_evidence: list[str] = Field(default_factory=list)
    manual_review: bool = False
    mitigations: list[str] = Field(default_factory=list)
    safe_test_template: str | None = None
    knowledge_refs: list[str] = Field(default_factory=list)

    def clauses(self) -> list[Clause]:
        return [*self.conditions.all, *self.conditions.any, *self.checks]


class Evidence(BaseModel):
    knowledge_id: str | None = None
    source_ref: str | None = None
    excerpt: str | None = None
    field: str | None = None


class Finding(BaseModel):
    risk_id: str
    title: str
    severity: Severity
    status: FindingStatus
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    origin: Literal["rule", "llm"] = "rule"
    evidence: list[Evidence] = Field(default_factory=list)
    reasoning_summary: str = ""
    limitations: list[str] = Field(default_factory=list)
    residual_risk: str | None = None

    @model_validator(mode="after")
    def _enforce_llm_boundary(self) -> Finding:
        is_llm_obs = self.risk_id.startswith(LLM_OBS_PREFIX)
        if self.origin == "llm":
            if not is_llm_obs:
                raise ValueError("LLM-origin findings must use an 'LLM-OBS-' risk_id")
            if self.status not in (FindingStatus.WARN, FindingStatus.UNKNOWN):
                raise ValueError("LLM-origin findings are capped at WARN or UNKNOWN")
        elif is_llm_obs:
            raise ValueError("'LLM-OBS-' risk_ids are reserved for origin='llm' findings")
        return self
