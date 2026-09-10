---
id: KU-1020
title: "Confidential tool capability matrix thresholds"
category: agent-security
source_type: manual
source_ref: "tests/fixture://KU-1020"
classification: confidential
status: reviewed
risk_ids:
  - TOOL-001
version: "0.1"
last_reviewed: "2026-09-10"
requires_ip_review: true
---

## Summary
Confidential thresholds for when a tool permission combination requires a human
approval gate.

## Conditions
- a tool has write, delete, send, or shell permission
- no human_approval point is defined for that action

## Risk
Tool abuse: the agent performs a high-impact action without oversight.

## Failure Mode
A delete tool runs on production data with no approval.

## Detection Clues
- Permission is write/delete/send/shell and requires_approval is false or unset.

## Evidence
- tools
- tool_permissions
- human_approval_points

## Mitigations
- Require an approval gate for every high-impact tool action.

## Safe Test
Attempt a high-impact action in a sandbox; confirm it routes to human approval.

## Limitations
Confidential fixture unit; PRIVATE mode with explicit confidential access only.

## Related Knowledge
- KU-1002
