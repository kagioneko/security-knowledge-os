"""Assessment input and result schemas (spec Sections 13, 14, 17, 20)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from app.models._credential_shapes import reject_credential_shapes, reject_non_identifier_shapes
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
#
# Codex#1 (round 13, 2026-09-13): `_Short` is used for RAG sources,
# outbound destinations, and approval-action names - identifier-shaped BY
# CONTRACT, unlike `_Text` below (actual prompt prose) - so it also gets
# `reject_non_identifier_shapes`, the allowlist half of the credential-
# shape defense (app/models/_credential_shapes.py's own docstring
# explains why both a denylist and an allowlist are applied).
_Short = Annotated[
    str,
    Field(max_length=500),
    AfterValidator(reject_credential_shapes),
    AfterValidator(reject_non_identifier_shapes),
]
_Text = Annotated[str, Field(max_length=50_000), AfterValidator(reject_credential_shapes)]

# Codex cross-review finding #3 (round 3, 2026-09-12): the per-field bounds
# above cap any ONE field, but nothing capped the serialized size of the
# WHOLE input. `user_prompts=["x" * 50_000] * 200` is well within every
# individual field limit yet serializes to ~10 MB; the 5,000-entry
# `_STORE` cap in app/main.py then permits roughly 50 GB of accepted input
# alone. This bounds the total request, independent of how the bytes are
# distributed across fields.
_MAX_SERIALIZED_BYTES = 300_000


def _serialized_size_exceeds(value: Any, limit: int) -> bool:
    """True if `value`'s compact JSON serialization is certainly longer
    than `limit` bytes. Counts a LOWER bound (string escapes and unknown
    types count as their minimum), so it never rejects anything the exact
    `after` check would accept - the raw input has no defaults filled in
    and no extra keys (extra="forbid"), so it is never larger than the
    validated model. Every visited node adds at least one byte, so the walk
    stops after at most `limit + 1` nodes however much a shared/aliased
    structure would expand (Codex round-33)."""
    total = 0
    stack: list[Any] = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            total += len(item.encode("utf-8", errors="replace")) + 2
        elif isinstance(item, dict):
            total += 1 + len(item)  # braces, and a colon or comma per entry
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            total += 1 + len(item)  # brackets and commas
            stack.extend(item)
        elif isinstance(item, bool) or item is None:
            total += 4
        elif isinstance(item, (int, float)):
            total += 1
        else:
            total += 1
        if total > limit:
            return True
    return False


class RagInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    sources: list[_Short] = Field(default_factory=list, max_length=200)


# Codex#3 / Antigravity SKOS-ADV-24 (round 18, 2026-09-14), reproduced
# exactly as reported: MemoryInput.scope, ToolInput.permissions,
# CredentialInput.storage, and CredentialInput.exposed_to_model were the
# only externally-supplied string fields on this model still missing
# reject_credential_shapes - normalize.py maps an unrecognized value to
# UNKNOWN before it reaches the LLM, but the RAW value is retained in
# the in-memory _STORE regardless, contradicting this module's own
# stated invariant that every free-text field gets shape validation.
# `_Scalar` mirrors `_Text` above but stays at the shorter 100-char bound
# these four fields already used.
_Scalar = Annotated[str, Field(max_length=100), AfterValidator(reject_credential_shapes)]


class MemoryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    persistent: bool | None = None
    scope: _Scalar | None = None


class ToolInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Annotated[
        str,
        Field(max_length=200),
        AfterValidator(reject_credential_shapes),
        AfterValidator(reject_non_identifier_shapes),
    ]
    permissions: _Scalar | None = None
    requires_approval: bool | None = None


class OutboundInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    destinations: list[_Short] = Field(default_factory=list, max_length=200)


class CredentialInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    storage: _Scalar | None = None
    exposed_to_model: _Scalar | None = None  # "true"|"false"|"unknown"


class AssessmentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Codex#6 / Antigravity SKOS-ADV-21 (round 17, 2026-09-14), reproduced
    # exactly as reported: unlike every other free-text field on this
    # model (system_prompt, developer_prompt below), `name` had no
    # reject_credential_shapes validator - AssessmentInput(name="AKIA...")
    # validated and was retained/returned in reports, while the identical
    # value in system_prompt was correctly rejected.
    name: Annotated[str, Field(max_length=500), AfterValidator(reject_credential_shapes)]
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

    @model_validator(mode="before")
    @classmethod
    def _bound_raw_size_first(cls, data: Any) -> Any:
        """Codex round-32 (2026-09-25), reproduced exactly as reported: the
        total-size bound below is an `after` validator, so it only ran once
        every field validator - including the credential-shape regex scan of
        each free-text field - had already processed the full input: a
        ~0.9 MB request (under the transport limit, over this 300 KB bound)
        was scanned in full before being rejected. This cheap pre-check
        rejects an oversized raw payload BEFORE any field-level scanning; the
        `after` check stays as the authoritative bound on the validated
        model.

        Codex round-33 (2026-09-26), reproduced exactly as reported: the
        first version of this check measured the input with `json.dumps()`,
        which fully expands a YAML alias bomb - a 391-byte file whose
        anchors nest ten references per level (`x1: [*x0, *x0, ...]`, ...)
        loads as a small shared graph but serializes to ~10^8 elements, so
        the size check itself ran out of memory (MemoryError after ~8 s)
        where the pre-round-32 code rejected the same input instantly.
        `_serialized_size_exceeds()` walks the value but stops as soon as
        its running total passes the limit, so the work is bounded by the
        limit, not by the expanded size."""
        if _serialized_size_exceeds(data, _MAX_SERIALIZED_BYTES):
            raise ValueError(
                f"assessment input exceeds the {_MAX_SERIALIZED_BYTES}-byte total limit"
            )
        return data

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
