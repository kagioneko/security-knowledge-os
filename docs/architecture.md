# Architecture (stub — filled in M8)

```
Input (YAML)
  |
  v
Input Normalization ------> AssessmentContext   (app/models/context.py)
  |
  v
Attack Surface Extraction
  |
  v
Knowledge Retrieval  <----- Knowledge Base (Markdown + YAML front matter)
  |                          + Classification Gate (app/policy/classification.py)
  v
Evidence Sufficiency Check
  |
  v
Deterministic Rule Checks --> Finding[]   (FAIL / WARN / PASS / UNKNOWN / N/A)
  |
  v
LLM-Assisted Review (optional, assistance only)
  |
  v
Missing Info / Questions / Safe Tests / Mitigations
  |
  v
Human Gate
  |
  v
Report (AssessmentResult)  -- overall_status, human_review_required
```

Component packages:

| package | milestone | role |
| --- | --- | --- |
| `app/models` | M1 | Pydantic schemas (knowledge, risk, context, assessment) |
| `app/ingestion` | M1 / M2 | front-matter parsing, KU validation, loading |
| `app/policy` | M1 / M5 | classification gate, disclosure, safe-test, human gate |
| `app/retrieval` | M2 | BM25 / FTS5 retrieval |
| `app/storage` | M2 | SQLite index + repository |
| `app/reviewer` | M3 / M4 / M6 | attack surface, rule engine, rollup, orchestrator, report |
| `app/llm` | M4 | provider adapters (none / mock / anthropic / openai / local) |
