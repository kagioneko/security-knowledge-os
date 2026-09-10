---
id: KU-0005
title: "Human approval gates for high-impact tool actions"
category: agent-security
source_type: standard
source_ref: "https://genai.owasp.org/llmrisk/llm06-excessive-agency/ ; https://atlas.mitre.org/ (MITRE ATLAS)"
classification: public
status: reviewed
risk_ids:
  - GOV-001
  - TOOL-001
version: "1.0"
last_reviewed: "2026-09-10"
requires_ip_review: false
provenance:
  source_title: "OWASP Top 10 for LLM Applications 2025 - LLM06 Excessive Agency"
  source_url: "https://genai.owasp.org/llmrisk/llm06-excessive-agency/"
  source_version: "2025"
  source_license: "CC-BY-SA-4.0 (OWASP GenAI Security Project); MITRE ATLAS Terms of Use (free use with attribution)"
  derivation: summary
  last_verified: "2026-09-10"
  usage_note: "Also informed by MITRE ATLAS (atlas.mitre.org)."
---

## Summary
For actions whose effects are hard to reverse or leave the trust boundary, the
model proposes and a human approves. The approval must be specific to the action
and its arguments, not a blanket "allow tools".

## Conditions
- The agent can perform an action in: external send, file delete, production
  change, money movement, HR or legal judgement, credential retrieval, or a
  destructive shell command, and
- That action can run without a person confirming it.

## Risk
An automated pipeline turns an injected instruction or a hallucination into a
real, irreversible effect.

## Evidence
- tool_policy
- human_approval points and which actions they cover
- high_impact_actions

## Failure Mode
`human_approval: { email_send: false }` while an email tool is available and the
agent has an outbound task.

## Detection Clues
- A high-impact action has no matching approval point.
- Approval is coarse ("approve this run") rather than per-action.

## Mitigations
- Enumerate high-impact actions and require an approval point for each.
- Show the human the exact call and arguments before it runs.
- Fail closed: if the approval path errors, do not execute.

## Safe Test
Ask the agent to perform a task needing a high-impact tool in a sandbox and
confirm it routes to approval instead of acting.

## Limitations
Approval fatigue is real; keep the set of gated actions small and meaningful.

## Related Knowledge
- KU-0004
- KU-0012
