---
id: KU-1010
title: "Internal heuristic for persistent memory poisoning severity"
category: memory-security
source_type: experiment
source_ref: "tests/fixture://KU-1010"
classification: internal
status: reviewed
risk_ids:
  - MEM-001
version: "0.1"
last_reviewed: "2026-09-10"
requires_ip_review: false
---

## Summary
Internal-only heuristic: rate persistent memory poisoning by whether tainted
instructions survive across sessions and whether they can reach other users.

## Conditions
- memory_persistent is true
- write path accepts content derived from untrusted input

## Risk
Long-term contamination of memory changes future assessments.

## Failure Mode
An injected note is stored and re-loaded as established fact in later sessions.

## Detection Clues
- No write/read-back separation.
- No cleanup or review of stored memory.

## Evidence
- memory_scope
- persistence

## Mitigations
- Separate write and read-back paths; require review before memory writes.

## Safe Test
Write a canary note, start a fresh session, confirm it is not treated as fact.

## Limitations
Internal fixture unit; PRIVATE mode only.

## Related Knowledge
- KU-1002
