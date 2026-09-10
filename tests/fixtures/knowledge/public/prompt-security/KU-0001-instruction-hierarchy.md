---
id: KU-0001
title: "System / user instruction hierarchy conflicts"
category: prompt-security
source_type: manual
source_ref: "tests/fixture://KU-0001"
classification: public
status: reviewed
risk_ids:
  - PI-001
version: "0.1"
last_reviewed: "2026-09-10"
requires_ip_review: false
---

## Summary
Fixture knowledge unit used by the validator test-suite.

## Conditions
- A system prompt and user-controlled text are concatenated without a trust boundary.

## Risk
Lower-trust text can override higher-trust instructions.

## Evidence
- system_prompt

## Failure Mode
The model follows an injected instruction taken from user-controlled text.

## Detection Clues
- No explicit statement that user content is data, not instructions.

## Mitigations
- Declare an explicit instruction/data boundary in the system prompt.

## Safe Test
Place a benign canary instruction in the user slot and confirm it is not obeyed.

## Limitations
Fixture only; not a real knowledge unit.

## Related Knowledge
- KU-0002
