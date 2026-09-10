"""Assessment input and result schemas (spec Sections 13, 14, 17, 20)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.models.risk import Finding, Severity


# --------------------------------------------------------------------------- #
# Input (spec Section 20)
# --------------------------------------------------------------------------- #
class RagInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    sources: list[str] = Field(default_factory=list)


class MemoryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    persistent: bool | None = None
    scope: str | None = None


class ToolInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    permissions: str | None = None
    requires_approval: bool | None = None


class OutboundInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    destinations: list[str] = Field(default_factory=list)


class CredentialInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    storage: str | None = None
    exposed_to_model: str | None = None  # "true" | "false" | "unknown"


class AssessmentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    system_prompt: str | None = None
    developer_prompt: str | None = None
    user_prompts: list[str] = Field(default_factory=list)
    rag: RagInput = Field(default_factory=RagInput)
    memory: MemoryInput = Field(default_factory=MemoryInput)
    tools: list[ToolInput] = Field(default_factory=list)
    outbound: OutboundInput = Field(default_factory=OutboundInput)
    human_approval: dict[str, bool] = Field(default_factory=dict)
    credentials: CredentialInput = Field(default_factory=CredentialInput)


# --------------------------------------------------------------------------- #
# Result (spec Sections 13, 14, 17)
# --------------------------------------------------------------------------- #
class OverallStatus(StrEnum):
    PASS = "PASS"
    CONDITIONAL = "CONDITIONAL"
    UNKNOWN = "UNKNOWN"
    FAIL = "FAIL"


class AttackSurface(BaseModel):
    input_channels: list[str] = Field(default_factory=list)
    external_content_sources: list[str] = Field(default_factory=list)
    retrieval_sources: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    tool_permissions: dict[str, str] = Field(default_factory=dict)
    memory_scope: str | None = None
    persistence: bool | None = None
    outbound_channels: list[str] = Field(default_factory=list)
    credentials: list[str] = Field(default_factory=list)
    human_approval_points: list[str] = Field(default_factory=list)
    high_impact_actions: list[str] = Field(default_factory=list)


class MissingInformation(BaseModel):
    field: str
    why_needed: str
    related_rule_ids: list[str] = Field(default_factory=list)


class Question(BaseModel):
    text: str
    field: str | None = None
    related_rule_ids: list[str] = Field(default_factory=list)


class SafeTestEnvironment(StrEnum):
    SANDBOX = "sandbox"
    READ_ONLY = "read_only"
    CANARY = "canary"


class UntrustedSafeTestProposal(BaseModel):
    """An LLM's idea for a safe test. It is *not* executable and is never promoted
    to a ``SafeTest`` automatically - a human turns it into a vetted template."""

    model_config = ConfigDict(extra="forbid")

    title: str
    relates_to_risk_id: str | None = None
    idea: str
    origin: Literal["llm"] = "llm"


class SafeTest(BaseModel):
    """A vetted safe test (spec Section 14). Only ``template`` or ``human`` origin.

    Every field that keeps the test safe is required by the schema, and
    ``app/policy/safe_test.py`` re-checks the content before it is attached."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    risk_id: str
    origin: Literal["template", "human"] = "template"
    environment: list[SafeTestEnvironment] = Field(min_length=1)
    scope: str = Field(min_length=1)
    uses_canary_values: bool
    preconditions: list[str] = Field(default_factory=list)
    setup: list[str] = Field(default_factory=list)
    steps: list[str] = Field(min_length=1)
    expected_secure_behavior: str = Field(min_length=1)
    failure_condition: str = Field(min_length=1)
    cleanup: list[str] = Field(min_length=1)
    requires_human_approval: bool = True


class Mitigation(BaseModel):
    risk_id: str
    recommendation: str
    priority: Severity | None = None


class ModelInfo(BaseModel):
    llm_provider: str
    llm_model: str | None = None
    deterministic_only: bool


class AssessmentResult(BaseModel):
    assessment_id: str
    created_at: datetime
    mode: str
    scope: str | None = None
    attack_surface: AttackSurface = Field(default_factory=AttackSurface)
    findings: list[Finding] = Field(default_factory=list)
    missing_information: list[MissingInformation] = Field(default_factory=list)
    questions: list[Question] = Field(default_factory=list)
    safe_tests: list[SafeTest] = Field(default_factory=list)
    safe_test_proposals: list[UntrustedSafeTestProposal] = Field(default_factory=list)
    mitigations: list[Mitigation] = Field(default_factory=list)
    overall_status: OverallStatus
    human_review_required: bool
    knowledge_revision: str | None = None
    model_info: ModelInfo
