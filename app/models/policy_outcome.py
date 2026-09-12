"""Typed policy outcomes.

Every policy decision in the system (classification gate, human gate, read-only
knowledge guard, safe-test validator, index integrity) returns one of these -
never a bare string - so reports, audit logs and the API can switch on them.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class PolicyOutcome(StrEnum):
    ALLOWED = "ALLOWED"
    HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"
    POLICY_BLOCKED = "POLICY_BLOCKED"
    READ_ONLY_VIOLATION = "READ_ONLY_VIOLATION"


# Anything that is not an explicit ALLOW is a stop.
_STOPS = {
    PolicyOutcome.HUMAN_APPROVAL_REQUIRED,
    PolicyOutcome.POLICY_BLOCKED,
    PolicyOutcome.READ_ONLY_VIOLATION,
}


class PolicyDecision(BaseModel):
    # Codex#7 (round 9, 2026-09-12): round 8's extra="forbid" pass (Codex#14)
    # covered the report envelope and its immediately-nested models but
    # missed this one - an extra/misspelled property here validated and
    # was silently discarded, the same schema-drift/tamper gap round 8
    # closed elsewhere.
    model_config = ConfigDict(extra="forbid")

    outcome: PolicyOutcome
    subject: str
    reasons: list[str] = Field(default_factory=list)

    @property
    def is_allowed(self) -> bool:
        return self.outcome is PolicyOutcome.ALLOWED

    @property
    def is_stop(self) -> bool:
        return self.outcome in _STOPS


class PolicyStop(Exception):
    """Raised when a stop decision must abort the current operation (fail-closed)."""

    def __init__(self, decision: PolicyDecision) -> None:
        reasons = "; ".join(decision.reasons)
        super().__init__(f"{decision.outcome.value}: {decision.subject} ({reasons})")
        self.decision = decision


def allow(subject: str) -> PolicyDecision:
    return PolicyDecision(outcome=PolicyOutcome.ALLOWED, subject=subject)


def stop(outcome: PolicyOutcome, subject: str, *reasons: str) -> PolicyDecision:
    return PolicyDecision(outcome=outcome, subject=subject, reasons=list(reasons))
