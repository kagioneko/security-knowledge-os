"""Human Gate (spec Section 15).

The system never executes a tool or an action itself. This gate classifies an
*action kind* and returns a typed decision. Anything that is a recognised
high-impact action - or that cannot be recognised at all - fails closed to
``HUMAN_APPROVAL_REQUIRED``. Only an explicitly safe, side-effect-free kind is
``ALLOWED``.
"""

from __future__ import annotations

from enum import StrEnum

from app.models.policy_outcome import PolicyDecision, PolicyOutcome, allow, stop


class HighImpactAction(StrEnum):
    EXTERNAL_SEND = "external_send"
    FILE_DELETE = "file_delete"
    FILE_WRITE = "file_write"
    PRODUCTION_CHANGE = "production_change"
    MONEY_MOVEMENT = "money_movement"
    HR_JUDGEMENT = "hr_judgement"
    LEGAL_JUDGEMENT = "legal_judgement"
    CREDENTIAL_RETRIEVAL = "credential_retrieval"
    DESTRUCTIVE_SHELL = "destructive_shell"


GATED_ACTIONS: frozenset[str] = frozenset(action.value for action in HighImpactAction)

# Side-effect-free kinds the assessment process may perform on its own.
SAFE_ACTIONS: frozenset[str] = frozenset(
    {"read", "list", "search", "retrieve", "analyze", "classify", "noop", "sandbox_probe"}
)

_ALIASES = {
    "send": HighImpactAction.EXTERNAL_SEND.value,
    "email": HighImpactAction.EXTERNAL_SEND.value,
    "outbound_send": HighImpactAction.EXTERNAL_SEND.value,
    "delete": HighImpactAction.FILE_DELETE.value,
    "write": HighImpactAction.FILE_WRITE.value,
    "shell": HighImpactAction.DESTRUCTIVE_SHELL.value,
    "exec": HighImpactAction.DESTRUCTIVE_SHELL.value,
    "payment": HighImpactAction.MONEY_MOVEMENT.value,
    "get_credential": HighImpactAction.CREDENTIAL_RETRIEVAL.value,
}


def evaluate_action(kind: str) -> PolicyDecision:
    key = _ALIASES.get(kind.strip().casefold(), kind.strip().casefold())
    if key in GATED_ACTIONS:
        return stop(
            PolicyOutcome.HUMAN_APPROVAL_REQUIRED,
            kind,
            f"'{key}' is a high-impact action and must not be executed automatically",
        )
    if key in SAFE_ACTIONS:
        return allow(kind)
    # Unknown / ambiguous -> fail closed.
    return stop(
        PolicyOutcome.HUMAN_APPROVAL_REQUIRED,
        kind,
        f"action kind '{kind}' is not on the safe allow-list; a human must review it",
    )
