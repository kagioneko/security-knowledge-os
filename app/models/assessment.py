"""Assessment input and result schemas (spec Sections 13, 14, 17, 20)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from app.models._credential_shapes import reject_credential_shapes
from app.models.risk import Finding, FindingStatus, Severity

# Codex cross-review finding #6 (round 2, 2026-09-11): AssessmentInput had no
# field-level size bounds at all - a single request with e.g. a 1 MiB
# user_prompts string was accepted (200) and retained in full in app/main.py's
# _STORE. The entry-count cap (_MAX_STORE_ENTRIES) added in round 1 bounds how
# many assessments are kept, not how large any ONE of them is; a store full of
# maximum-size entries can still be multi-gigabyte. These are generous-but-
# finite bounds on free text / list sizes, not a tuned production limit.
#
# Codex#2 (round 9, 2026-09-12): every free-text field here (and on
# AnswerPatch) accepted arbitrary text, including a value shaped like a
# real credential, which then flowed unchanged into AttackSurface and the
# ReviewPayload sent to an external LLM provider. reject_credential_shapes
# rejects the same concrete, unambiguous secret SHAPES secret_scan.py /
# safe_test.py already recognize - it cannot catch every possible secret,
# but every free-text field is now covered, not left unfiltered.
_Short = Annotated[str, Field(max_length=500), AfterValidator(reject_credential_shapes)]
_Text = Annotated[str, Field(max_length=50_000), AfterValidator(reject_credential_shapes)]

# Codex cross-review finding #3 (round 3, 2026-09-12): the per-field bounds
# above cap any ONE field, but nothing capped the serialized size of the
# WHOLE input. `user_prompts=["x" * 50_000] * 200` is well within every
# individual field limit yet serializes to ~10 MB; the 5,000-entry
# `_STORE` cap in app/main.py then permits roughly 50 GB of accepted input
# alone. This bounds the total request, independent of how the bytes are
# distributed across fields.
_MAX_SERIALIZED_BYTES = 300_000


class RagInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    sources: list[_Short] = Field(default_factory=list, max_length=200)


class MemoryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    persistent: bool | None = None
    scope: str | None = Field(default=None, max_length=100)


class ToolInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Annotated[str, Field(max_length=200), AfterValidator(reject_credential_shapes)]
    permissions: str | None = Field(default=None, max_length=100)
    requires_approval: bool | None = None


class OutboundInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    destinations: list[_Short] = Field(default_factory=list, max_length=200)


class CredentialInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    storage: str | None = Field(default=None, max_length=100)
    exposed_to_model: str | None = Field(default=None, max_length=100)  # "true"|"false"|"unknown"


class AssessmentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(max_length=500)
    system_prompt: (
        Annotated[str, Field(max_length=50_000), AfterValidator(reject_credential_shapes)] | None
    ) = None
    developer_prompt: (
        Annotated[str, Field(max_length=50_000), AfterValidator(reject_credential_shapes)] | None
    ) = None
    user_prompts: list[_Text] = Field(default_factory=list, max_length=200)
    rag: RagInput = Field(default_factory=RagInput)
    memory: MemoryInput = Field(default_factory=MemoryInput)
    tools: list[ToolInput] = Field(default_factory=list, max_length=200)
    outbound: OutboundInput = Field(default_factory=OutboundInput)
    human_approval: dict[_Short, bool] = Field(default_factory=dict, max_length=200)
    credentials: CredentialInput = Field(default_factory=CredentialInput)

    @model_validator(mode="after")
    def _bound_total_size(self) -> AssessmentInput:
        size = len(self.model_dump_json().encode("utf-8"))
        if size > _MAX_SERIALIZED_BYTES:
            raise ValueError(
                f"assessment input is {size} bytes, exceeding the "
                f"{_MAX_SERIALIZED_BYTES}-byte total limit"
            )
        return self


# --------------------------------------------------------------------------- #
# Result (spec Sections 13, 14, 17)
# --------------------------------------------------------------------------- #
class OverallStatus(StrEnum):
    PASS = "PASS"
    CONDITIONAL = "CONDITIONAL"
    UNKNOWN = "UNKNOWN"
    FAIL = "FAIL"


class AttackSurface(BaseModel):
    # Codex#7 (round 9, 2026-09-12): round 8's extra="forbid" pass (Codex#14)
    # covered the report envelope and selected nested models but missed
    # these remaining ones - an extra/misspelled property here validated
    # and was silently discarded.
    model_config = ConfigDict(extra="forbid")

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
    model_config = ConfigDict(extra="forbid")
    field: str
    why_needed: str
    related_rule_ids: list[str] = Field(default_factory=list)


class Question(BaseModel):
    model_config = ConfigDict(extra="forbid")
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
    model_config = ConfigDict(extra="forbid")
    risk_id: str
    recommendation: str
    priority: Severity | None = None


class ModelInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    llm_provider: str
    llm_model: str | None = None
    deterministic_only: bool


class AssessmentResult(BaseModel):
    # Codex#14 (round 8, 2026-09-12), reproduced exactly as reported: an
    # extra or misspelled property in a saved/reloaded result validated
    # and was silently discarded, weakening schema-drift and tamper
    # detection for externally loaded report data.
    model_config = ConfigDict(extra="forbid")

    assessment_id: str
    created_at: datetime
    mode: str
    scope: str | None = None
    supersedes: str | None = None  # the assessment_id this one re-evaluates (M6.1 /answers)
    revision: int = 1
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
    retrieved_knowledge_ids: list[str] = Field(default_factory=list)
    model_info: ModelInfo

    # Codex#4 (round 9, 2026-09-12), reproduced exactly as reported: nothing
    # validated overall_status/human_review_required against findings/
    # attack_surface/missing_information - a tampered saved report could
    # claim overall_status="PASS" and human_review_required=False while
    # carrying a FAIL finding. This reimplements (rather than imports)
    # app.reviewer.rollup.compute_overall_status()'s decision-A6 ordering
    # and a subset of requires_human_review()'s signals, to avoid a
    # models -> reviewer import cycle (rollup.py imports OverallStatus
    # FROM this module) - the real assess() pipeline (app/reviewer/
    # assess.py) already computes both fields via those exact functions,
    # so this only ever rejects a result that DISAGREES with its own data,
    # never a legitimately-produced one. `confidential_knowledge_used` is
    # one of requires_human_review()'s inputs that has no corresponding
    # persisted field on this model, so it cannot be re-derived and
    # verified here - this is a partial, not exhaustive, consistency
    # check, but it directly closes the reported FAIL-vs-PASS repro.
    @model_validator(mode="after")
    def _rollup_is_consistent_with_findings(self) -> AssessmentResult:
        rank = {FindingStatus.FAIL: 0, FindingStatus.WARN: 1, FindingStatus.UNKNOWN: 2}
        worst = min((rank.get(f.status, 3) for f in self.findings), default=3)
        expected_overall = [
            OverallStatus.FAIL,
            OverallStatus.CONDITIONAL,
            OverallStatus.UNKNOWN,
            OverallStatus.PASS,
        ][worst]
        if self.overall_status != expected_overall:
            raise ValueError(
                f"overall_status={self.overall_status!r} does not match findings "
                f"(expected {expected_overall!r})"
            )

        needs_review = (
            bool(self.missing_information)
            or bool(self.attack_surface.high_impact_actions)
            or any(
                f.status in (FindingStatus.FAIL, FindingStatus.WARN, FindingStatus.UNKNOWN)
                or f.origin == "llm"
                for f in self.findings
            )
        )
        if needs_review and not self.human_review_required:
            raise ValueError(
                "human_review_required=False contradicts findings, "
                "missing_information, or high-impact actions that require review"
            )
        return self
