"""The top-level assessment report envelope.

An assessment either **completes** (and carries an ``AssessmentResult``) or is
**stopped by policy** (and carries the ``PolicyDecision`` that stopped it). A
stopped assessment is never returned as a normal result with empty findings -
``status`` and the presence of ``result`` vs ``policy_decision`` make the two
cases unambiguous for a CLI exit code or an HTTP handler.

``HUMAN_APPROVAL_REQUIRED`` is *not* a report status. It is a workflow flag
(``AssessmentResult.human_review_required``) inside a COMPLETED report.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, model_validator

from app.models.assessment import AssessmentResult
from app.models.policy_outcome import PolicyDecision


class ReportStatus(StrEnum):
    COMPLETED = "COMPLETED"
    POLICY_BLOCKED = "POLICY_BLOCKED"


class AssessmentReport(BaseModel):
    # Codex#14 (round 8, 2026-09-12), reproduced exactly as reported:
    # without extra="forbid", parsing a saved report (or one loaded from a
    # CLI-written file) containing an extra or misspelled property
    # validated and silently discarded it, weakening schema-drift and
    # tamper detection for externally loaded report data - every other
    # externally-fed model in this project (AssessmentInput, AnswerPatch,
    # RiskRule, ...) already forbids unknown fields.
    model_config = ConfigDict(extra="forbid")

    status: ReportStatus
    result: AssessmentResult | None = None
    policy_decision: PolicyDecision | None = None

    @model_validator(mode="after")
    def _check_shape(self) -> AssessmentReport:
        # Codex cross-review finding #14 (2026-09-11): this only checked the
        # required side of each case ("COMPLETED has a result",
        # "POLICY_BLOCKED has a decision") - a COMPLETED report carrying a
        # policy_decision too, or a POLICY_BLOCKED report carrying a result
        # too (or an ALLOWED-outcome decision, contradicting its own status),
        # all validated. status must be a true XOR over (result,
        # policy_decision), matching the module docstring's own contract.
        if self.status is ReportStatus.COMPLETED:
            if self.result is None:
                raise ValueError("a COMPLETED report must carry a result")
            if self.policy_decision is not None:
                raise ValueError("a COMPLETED report must not carry a policy_decision")
        elif self.status is ReportStatus.POLICY_BLOCKED:
            if self.policy_decision is None:
                raise ValueError("a POLICY_BLOCKED report must carry a policy_decision")
            if self.result is not None:
                raise ValueError("a POLICY_BLOCKED report must not carry a result")
            if self.policy_decision.is_allowed:
                raise ValueError(
                    "a POLICY_BLOCKED report's policy_decision must not be an allowed outcome"
                )
        return self

    @classmethod
    def completed(cls, result: AssessmentResult) -> AssessmentReport:
        return cls(status=ReportStatus.COMPLETED, result=result)

    @classmethod
    def blocked(cls, decision: PolicyDecision) -> AssessmentReport:
        return cls(status=ReportStatus.POLICY_BLOCKED, policy_decision=decision)
