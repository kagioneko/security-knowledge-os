# Shipped Knowledge Corpus

The MVP ships 14 public Knowledge Units under `knowledge/public/`. Every unit is
`classification: public`, `status: reviewed`, `requires_ip_review: false`. 13 of
the 14 are derived from **published standards** - no private, internal, or
unpublished material (decision A9). The remaining unit, KU-0014, is a deliberate
exception: `provenance.derivation: original`, `source_type: incident`, sourced
from this project's own pre-publication cross-AI review process rather than a
third-party standard - a real vulnerability class this project's Knowledge Units
would otherwise have had no first-party example of. It contains no private,
internal, or confidential material (no code, no credentials, no repo-internal
paths); see the file for the generalised writeup.

MVP DoD: **>= 12 reviewed public Knowledge Units** — met (13 English + 1 Japanese).

| id | title | category | source |
| --- | --- | --- | --- |
| KU-0001 | Direct prompt injection and the instruction/data boundary | prompt-security | OWASP Top 10 for LLM Applications 2025, LLM01 |
| KU-0002 | Indirect prompt injection via retrieved content | rag-security | OWASP LLM01; simonwillison.net (prompt injection) |
| KU-0003 | Untrusted-content isolation in retrieval pipelines | rag-security | OWASP LLM08 (2025) |
| KU-0004 | Excessive agency: least privilege for tools | agent-security | OWASP LLM06 (2025) |
| KU-0005 | Human approval gates for high-impact tool actions | agent-security | OWASP LLM06; MITRE ATLAS |
| KU-0006 | Outbound channels and destination allow-lists | agent-security | OWASP LLM02 (2025) |
| KU-0007 | Persistent memory and long-term data poisoning | memory-security | OWASP LLM04 (2025) |
| KU-0008 | Secrets must not be reachable by the model | credential-security | OWASP LLM02 (2025) |
| KU-0009 | Credential broker: short-lived, least-privilege handles | credential-security | NIST AI 600-1 (Generative AI Profile) |
| KU-0010 | System prompt leakage | prompt-security | OWASP LLM07 (2025) |
| KU-0011 | Improper output handling: validate model output before use | methodology | OWASP LLM05 (2025) |
| KU-0012 | Human oversight for consequential decisions | governance | NIST AI Risk Management Framework |
| KU-0013 | モデルは侵害されている前提で権限とリーチャビリティを絞る (assume-compromise, Japanese) | methodology | MITRE ATLAS; OWASP LLM06 |
| KU-0014 | Identifier-shaped secrets leak into LLM payloads even after a denylist | incident | original (this project's own review, rounds 9-14) |

Rules cite these units via `knowledge_refs`; the reviewer retrieves them and hands
them to the LLM as read-only context. To rebuild the index:
`skos reindex knowledge --db var/index.sqlite`.

## Human review note

`status: reviewed` here means "summarised from a reviewed public standard".
The maintainer should still do a final pass before any of these are published
under the project's own name.
