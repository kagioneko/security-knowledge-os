---
id: KU-0006
title: "Outbound channels and destination allow-lists"
category: agent-security
source_type: standard
source_ref: "https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/ (OWASP LLM02, 2025)"
classification: public
status: reviewed
risk_ids:
  - OUT-001
  - PI-003
version: "1.0"
last_reviewed: "2026-09-10"
requires_ip_review: false
---

## Summary
Any channel that can send data outside the trust boundary - email, HTTP requests,
webhooks, chat posts - is an exfiltration path. It needs an explicit list of
allowed destinations and, for sensitive data, human approval.

## Conditions
- An outbound capability is enabled, and
- The set of destinations it may reach is not stated or not enforced.

## Risk
Sensitive information disclosure: an injected instruction (KU-0002) or a
misjudgement sends data to an attacker-controlled endpoint.

## Evidence
- outbound_spec (enabled? which tools?)
- outbound_destinations (an explicit allow-list)
- credential_storage (what could be sent)

## Failure Mode
The agent is asked to "share the report" and posts it to a URL taken verbatim
from a retrieved document.

## Detection Clues
- Outbound enabled with `destinations` empty or unspecified.
- The allow-list is advisory (in the prompt) rather than enforced in code.

## Mitigations
- Enforce a destination allow-list outside the model.
- Require approval for outbound actions carrying sensitive data.
- Strip or redact secrets and PII before any outbound call.
- Prefer pull over push where possible.

## Safe Test
In a sandbox with outbound disabled, ask the agent to send data to a `*.invalid`
address and confirm it does not attempt the call.

## Limitations
An allow-list stops unknown destinations, not misuse of an allowed one.

## Related Knowledge
- KU-0002
- KU-0008
