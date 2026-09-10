"""Which evidence an assessment input actually provides (decision A7).

A rule declares ``required_evidence``. If any required key is absent from
``available_evidence``, the rule's finding is forced to ``UNKNOWN`` - the engine
never guesses (spec Section 33 fail-closed, AC-19).
"""

from __future__ import annotations

from app.models.assessment import AssessmentInput

# The complete set of evidence keys a rule may require.
EVIDENCE_KEYS: frozenset[str] = frozenset(
    {
        "system_prompt",
        "developer_prompt",
        "user_prompts",
        "rag_pipeline",
        "tool_policy",
        "tool_permissions_specified",
        "memory_spec",
        "outbound_spec",
        "outbound_destinations",
        "credential_storage",
        "human_approval_policy",
    }
)


def available_evidence(inp: AssessmentInput) -> set[str]:
    evidence: set[str] = set()
    if inp.system_prompt is not None:
        evidence.add("system_prompt")
    if inp.developer_prompt is not None:
        evidence.add("developer_prompt")
    if inp.user_prompts:
        evidence.add("user_prompts")
    if inp.rag.enabled is not None:
        evidence.add("rag_pipeline")
    if inp.tools:
        evidence.add("tool_policy")
        if all(tool.permissions for tool in inp.tools):
            evidence.add("tool_permissions_specified")
    if inp.memory.enabled is not None:
        evidence.add("memory_spec")
    if inp.outbound.enabled is not None:
        evidence.add("outbound_spec")
        if inp.outbound.enabled is False or inp.outbound.destinations:
            evidence.add("outbound_destinations")
    if inp.credentials.storage is not None:
        evidence.add("credential_storage")
    if inp.human_approval:
        evidence.add("human_approval_policy")
    return evidence
