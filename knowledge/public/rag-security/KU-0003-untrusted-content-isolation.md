---
id: KU-0003
title: "Untrusted-content isolation in retrieval pipelines"
category: rag-security
source_type: standard
source_ref: "https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/ (OWASP LLM08, 2025)"
classification: public
status: reviewed
risk_ids:
  - PI-003
version: "1.0"
last_reviewed: "2026-09-10"
requires_ip_review: false
---

## Summary
A retrieval index that mixes trusted reference material with user-supplied or
scraped content, and an access model that does not match the index, lets a
low-privileged actor influence what a high-privileged session sees.

## Conditions
- Retrieval sources of different trust levels share one index, or
- Index access control does not mirror the source documents' access control.

## Risk
Cross-tenant leakage, poisoned context, and indirect prompt injection (KU-0002).

## Evidence
- rag_pipeline (which sources, whose content, what access control)
- retrieval_sources

## Failure Mode
A document uploaded by user A is retrieved into user B's session because the
index has no per-tenant filter.

## Detection Clues
- One index, many trust levels, no source/trust metadata on chunks.
- Retrieval filters on relevance only, not on classification or tenant.

## Mitigations
- Separate indexes (or hard filters) per trust level and per tenant.
- Carry source, trust level and classification on every chunk and filter on them.
- Treat any retrieved chunk as untrusted until its source is verified.

## Safe Test
With a canary document restricted to tenant A, run a tenant-B query whose top
result would be that document and confirm it is filtered out.

## Limitations
Isolation addresses retrieval; the instruction/data boundary (KU-0002) is still
needed for whatever content does reach the model.

## Related Knowledge
- KU-0002
