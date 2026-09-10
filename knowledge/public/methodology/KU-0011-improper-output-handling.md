---
id: KU-0011
title: "Improper output handling: validate model output before use"
category: methodology
source_type: standard
source_ref: "https://genai.owasp.org/llmrisk/llm05-improper-output-handling/ (OWASP LLM05, 2025)"
classification: public
status: reviewed
risk_ids: []
version: "1.0"
last_reviewed: "2026-09-10"
requires_ip_review: false
provenance:
  source_title: "OWASP Top 10 for LLM Applications 2025 - LLM05 Improper Output Handling"
  source_url: "https://genai.owasp.org/llmrisk/llm05-improper-output-handling/"
  source_version: "2025"
  source_license: "CC-BY-SA-4.0 (OWASP GenAI Security Project)"
  derivation: summary
  last_verified: "2026-09-10"
---

## Summary
Model output is untrusted. Passing it straight into a shell, a SQL query, an
HTML page, an eval, or a downstream API without validation turns prompt injection
into classic injection (command, SQL, XSS, SSRF).

## Conditions
- Model output is used to build a command, a query, markup, a path, or a request
  to another system, and
- It is not validated, encoded, or constrained before that use.

## Risk
Remote code execution, SQL injection, XSS, SSRF, privilege escalation - driven by
whatever an attacker put into the model's context.

## Evidence
- How each model output is consumed downstream
- What validation or encoding sits between the model and the sink

## Failure Mode
The model returns a shell command that the orchestrator runs directly.

## Detection Clues
- Output goes into `subprocess`, `eval`, string-built SQL, or raw HTML.
- The output contract is prose, not a schema.

## Mitigations
- Constrain output to a schema and parse it; reject on mismatch.
- Encode or parameterise for the specific sink (SQL params, HTML escaping).
- Never execute model-produced code or commands without a human and a sandbox.
- Apply least privilege to whatever consumes the output.

## Safe Test
Feed the system an input designed to make the model emit a payload for the
downstream sink and confirm the payload is rejected or neutralised.

## Limitations
Schema validation catches shape, not intent; combine with authority limits.

## Related Knowledge
- KU-0001
- KU-0004
