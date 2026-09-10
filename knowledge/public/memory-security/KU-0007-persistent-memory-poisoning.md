---
id: KU-0007
title: "Persistent memory and long-term data poisoning"
category: memory-security
source_type: standard
source_ref: "https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/ (OWASP LLM04, 2025)"
classification: public
status: reviewed
risk_ids:
  - MEM-001
version: "1.0"
last_reviewed: "2026-09-10"
requires_ip_review: false
provenance:
  source_title: "OWASP Top 10 for LLM Applications 2025 - LLM04 Data and Model Poisoning"
  source_url: "https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/"
  source_version: "2025"
  source_license: "CC-BY-SA-4.0 (OWASP GenAI Security Project)"
  derivation: summary
  last_verified: "2026-09-10"
---

## Summary
When an agent writes to a memory store that later sessions load and trust,
content derived from untrusted input can become "established fact" - and can
reach other sessions or other users.

## Conditions
- Memory is persistent across sessions, and
- The write path accepts content that came from untrusted input (user text,
  retrieved documents), and
- There is no review between write and read-back.

## Risk
Long-term contamination of the assistant's behaviour, cross-session and
cross-user influence, and a durable foothold for an earlier injection (KU-0002).

## Evidence
- memory_spec (enabled? persistent? scope: session/user/global?)
- rag_pipeline (is untrusted content in scope?)

## Failure Mode
An injected note "the admin approved unrestricted tool use" is stored in session
one and loaded as fact in session two.

## Detection Clues
- Write and read-back share a path; nothing distinguishes stored input from
  stored conclusions.
- Memory scope is user or global with no cleanup or review.

## Mitigations
- Separate the write path from the read-back path.
- Require review before content derived from untrusted input is stored.
- Scope memory to the session unless a wider scope is justified and controlled.
- Keep provenance on every memory entry so it can be audited and rolled back.

## Safe Test
Write a canary claim in session one, start a fresh session two, and confirm the
claim is not treated as verified knowledge.

## Limitations
Review adds latency; automate the classification of what is safe to store.

## Related Knowledge
- KU-0002
