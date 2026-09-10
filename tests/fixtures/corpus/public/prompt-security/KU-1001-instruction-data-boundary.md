---
id: KU-1001
title: "Instruction / data boundary in the system prompt"
category: prompt-security
source_type: manual
source_ref: "tests/fixture://KU-1001"
classification: public
status: reviewed
risk_ids:
  - PI-001
version: "0.1"
last_reviewed: "2026-09-10"
requires_ip_review: false
---

## Summary
A system prompt that concatenates user-controlled text without a declared boundary
lets a prompt injection override higher-trust instructions.

## Conditions
- User input is placed in the same channel as system instructions.

## Risk
Direct prompt injection: the model treats user text as instructions.

## Failure Mode
The model obeys "ignore previous instructions" style payloads.

## Detection Clues
- No statement that user content is data, not commands.

## Evidence
- system_prompt

## Mitigations
- Declare an explicit instruction/data boundary and label untrusted spans.

## Safe Test
Insert a benign canary instruction into the user slot; confirm it is not obeyed.

## Limitations
Fixture unit for retrieval tests.

## Related Knowledge
- KU-1002
