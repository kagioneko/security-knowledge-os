# Architecture

```
AssessmentInput (YAML / JSON)
  |
  v  app/reviewer/normalize.py        (unstated -> None/unknown, never assumed)
AssessmentContext
  |
  +--> app/reviewer/facts.py          FACT_SPEC (whitelist) -> flat fact dict
  +--> app/reviewer/attack_surface.py -> AttackSurface
  +--> app/reviewer/evidence.py       -> available evidence keys
  |
  v  app/reviewer/rule_engine.py      data-only clauses over the fact dict
Finding[]  (FAIL / WARN / PASS / UNKNOWN / N/A ; origin="rule")
  |
  |   app/retrieval/  (optional)      trigram FTS5 over knowledge/public
  |     integrity-checked (app/storage/integrity.py) before use
  |     -> knowledge_revision + retrieved chunks
  |
  v  app/reviewer/llm_review.py       (optional; SKOS_LLM_PROVIDER, default none)
     ReviewPayload: 4 separate fields (context / surface / findings / knowledge)
     -> ReviewerObservations (no status field) -> LLM-OBS-* findings
  |
  v  app/reviewer/rollup.py           A6 overall status ; merge_findings (A8)
  v  app/reviewer/questions.py        missing evidence + undetermined -> questions
  v  app/policy/safe_test.py          vetted templates for flagged findings
  |
  v  app/reviewer/report.py           PolicyStop -> POLICY_BLOCKED report
AssessmentReport { status, result?, policy_decision? }
```

## Packages

| package | milestone | role |
| --- | --- | --- |
| `app/models` | M1+ | Pydantic schemas: knowledge (+ provenance), risk, rule_clause, context, assessment, reviewer_output, llm_io, report, answer, policy_outcome |
| `app/ingestion` | M1 / M2 | front-matter parsing, KU validation, corpus loading, section chunking |
| `app/policy` | M1 / M5 | classification gate, human gate, knowledge read-only guard, safe-test validator |
| `app/storage` | M2 / M5 | SQLite + contentless FTS5 index, repository, integrity check |
| `app/retrieval` | M2 | query classification, BM25/trigram retrieval, atomic reindex, hybrid seam |
| `app/reviewer` | M3 / M4 / M6 | normalize, facts, rule engine, attack surface, evidence, rollup, llm_review, questions, answers, assess (orchestrator), report |
| `app/llm` | M4 | client protocol, mock, anthropic (lazy), factory |
| `app/eval` | M7 | Section 24 metrics over labelled fixtures |
| `app/cli.py` | M6 | `skos` command-line interface |
| `app/main.py` | M6 | FastAPI application |

## Configurability seams

- **Knowledge root** (`SKOS_KNOWLEDGE_ROOT`): `knowledge/` today; `active/knowledge/`
  once the Pack Manager (M9-M10) lands. Retrieval code is unchanged.
- **LLM provider** (`SKOS_LLM_PROVIDER`): `none` (default) / `mock` / `anthropic`.
  The client protocol is `complete(messages) -> str`; parsing and the single
  repair attempt live in the reviewer.
- **Index path** (`SKOS_DB_PATH`), **rules root** (`SKOS_RULES_ROOT`),
  **safe-tests root** (`SKOS_SAFE_TESTS_ROOT`), **mode** (`SKOS_MODE`,
  public / private), **top-k** (`SKOS_TOP_K`).

## Integration note: identify a Finding by `risk_id`, never by `title`

Antigravity cross-review finding B5.2 (2026-09-11): `merge_findings()` (decision
A8) appends LLM observations after the deterministic rule findings, so
`AssessmentResult.findings` can in principle contain a rule finding and an
`LLM-OBS-*` finding with a similar or identical `title` (an LLM cannot invent a
colliding `risk_id` - `_enforce_llm_boundary` rejects that - but nothing stops
it from choosing similar wording). The engine itself is unaffected either way:
`compute_overall_status()` folds every finding by its worst status regardless of
title, so a same-titled LLM observation can never mask or downgrade a rule
verdict. A downstream integration that deduplicates or indexes findings by
`title` instead of `risk_id` could still display the wrong one, though - always
key on `risk_id` (deterministic findings use the rule's own id; LLM
observations are always `LLM-OBS-NNNNN`, `origin="llm"`).
