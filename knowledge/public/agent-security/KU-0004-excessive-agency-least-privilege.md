---
id: KU-0004
title: "Excessive agency: least privilege for tools"
category: agent-security
source_type: standard
source_ref: "https://genai.owasp.org/llmrisk/llm06-excessive-agency/ (OWASP LLM06, 2025)"
classification: public
status: reviewed
risk_ids:
  - TOOL-001
  - TOOL-000
version: "1.0"
last_reviewed: "2026-09-10"
requires_ip_review: false
provenance:
  source_title: "OWASP Top 10 for LLM Applications 2025 - LLM06 Excessive Agency"
  source_url: "https://genai.owasp.org/llmrisk/llm06-excessive-agency/"
  source_version: "2025"
  source_license: "CC-BY-SA-4.0 (OWASP GenAI Security Project)"
  derivation: summary
  last_verified: "2026-09-10"
---

## Summary
Excessive agency is harm caused by an LLM system's own actions when it has too
much functionality, too many permissions, or too much autonomy. The fix is to
scope each of the three.

## Conditions
- A tool grants write, delete, send or shell capability, and
- The tool's permission is broader than the task needs, or is unspecified, and
- No approval step sits between the model's decision and the effect.

## Risk
Data loss, unwanted external messages, configuration changes, and command
execution driven by a hallucination or an injected instruction.

## Evidence
- tool_policy (every tool, its permission, whether approval is required)
- human_approval points

## Failure Mode
A "cleanup" task leads the agent to call a delete tool on live data because
nothing constrained the tool's scope.

## Detection Clues
- Tools expose more than read where read would do.
- Tool permissions are missing from the spec entirely.
- One credential or token backs many tools.

## Mitigations
- Give each tool the least permission that works; prefer read-only.
- Require a human approval gate for every write/delete/send/shell tool.
- Scope tool credentials narrowly and rotate them.
- Log every tool call with its arguments for review.

## Safe Test
In a sandbox, replace high-impact tools with recording stubs and confirm the
agent asks for approval before a stub is called.

## Limitations
Least privilege limits blast radius; it does not stop the model from being
tricked into using the privileges it does have.

## Related Knowledge
- KU-0005
- KU-0006
