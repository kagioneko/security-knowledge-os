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

from pydantic import BaseModel, model_validator

from app.models.assessment import AssessmentResult
from app.models.policy_outcome import PolicyDecision


class ReportStatus(StrEnum):
    COMPLETED = "COMPLETED"
    POLICY_BLOCKED = "POLICY_BLOCKED"


class AssessmentReport(BaseModel):
    status: ReportStatus
    result: AssessmentResult | None = None
    policy_decision: PolicyDecision | None = None

    @model_validator(mode="after")
    def _check_shape(self) -> AssessmentReport:
        if self.status is ReportStatus.COMPLETED and self.result is None:
            raise ValueError("a COMPLETED report must carry a result")
        if self.status is ReportStatus.POLICY_BLOCKED and self.policy_decision is None:
            raise ValueError("a POLICY_BLOCKED report must carry a policy_decision")
        return self

    @classmethod
    def completed(cls, result: AssessmentResult) -> AssessmentReport:
        return cls(status=ReportStatus.COMPLETED, result=result)

    @classmethod
    def blocked(cls, decision: PolicyDecision) -> AssessmentReport:
        return cls(status=ReportStatus.POLICY_BLOCKED, policy_decision=decision)
