# Security Knowledge OS

**Deterministic security-assessment engine + knowledge retrieval + optional LLM assistance.**

A PoC that converts existing security knowledge (notes, GitHub, incident records,
experiment logs) into versioned *Knowledge Units*, and uses a swappable general LLM
as an *optional* reasoning layer for first-pass AI-security assessment of
Prompt / RAG / Agent / Tool / Memory / Credential surfaces.

The source of truth for the design is the Google Drive document
*"Security Knowledge OS — Claude Code Implementation Specification v0.1"* (2026-09-10).

> This system is **not** an AI that decides "safe" on its own. It finds evidence,
> evaluates against rules, flags gaps, and supports a human decision.

## Core principles

- The LLM is **off by default**. `Input -> AssessmentContext -> Rule Engine -> Finding -> Report`
  runs with no network, no API key, no LLM.
- Knowledge and the reasoning model are **separated**. The LLM is a replaceable layer.
- No unfounded guessing. `UNKNOWN` is a first-class verdict.
- The LLM layer can **never create or clear a `FAIL`** (decision A8).
- `public` / `internal` / `confidential` / `secret` are never mixed (decision A1).
- The final decision is always returned to a human.

## Milestone status

| Milestone | State | Deliverables |
| --- | --- | --- |
| **M1 — Skeleton + Schema + Validator** | done | directory tree, `app/models/*`, `app/ingestion/validator.py`, `scripts/validate_knowledge.py`, `docs/knowledge-schema.md` |
| **M2 — Knowledge Loader + FTS5 Retrieval** | done | `app/ingestion/{loader,chunker}.py`, `app/storage/{db,repository}.py`, `app/retrieval/{base,bm25,hybrid,index}.py`, `scripts/{ingest,build_index}.py` |
| **M3 — Deterministic Rule Engine** | done | `app/models/rule_clause.py`, `app/reviewer/{facts,clause_eval,rule_loader,rule_engine,normalize,attack_surface,evidence,rollup,assess}.py`, `rules/**` (7 rules), `scripts/validate_rules.py`, `docs/rule-schema.md` |
| **M4 — LLM Adapter + Reviewer** | done | `app/llm/{base,mock,anthropic_client,factory}.py`, `app/models/{reviewer_output,llm_io}.py`, `app/reviewer/{llm_review,questions}.py`, `assess()` full, `scripts/assess.py` |
| M5 — Safe Test + Human Gate | not started | |
| M6 — Orchestrator + CLI + API | not started | |
| M7 — Fixtures + Evaluation + starter KUs | not started | |
| M8 — Docs + hardening | not started | |

## Quickstart (M1)

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# Validate the knowledge base (empty on a fresh checkout -> 0 issues)
.venv/bin/python scripts/validate_knowledge.py knowledge

# Load-check a knowledge root, then build the FTS5 index from it
.venv/bin/python scripts/ingest.py knowledge
.venv/bin/python scripts/build_index.py knowledge --db var/index.sqlite

# Validate the deterministic rule catalogue
.venv/bin/python scripts/validate_rules.py rules

# Run an assessment (provider=none by default: the deterministic engine does the work)
.venv/bin/python scripts/assess.py tests/fixtures/assessments/V-001-indirect-injection-auto-email.yaml

# Run the test-suite
.venv/bin/pytest -q
```

Rules are **data, never code** - see `docs/rule-schema.md`. The deterministic
assessment path (`app/reviewer/assess.py`) runs with no LLM: it normalizes the
input, extracts the attack surface, evaluates the rule catalogue over a
whitelisted fact set, and rolls the findings up. A rule is never `PASS` while any
check was `UNKNOWN` or any required evidence was missing.

The LLM is an **optional additive layer** (`SKOS_LLM_PROVIDER`, default `none`).
It receives the deterministic findings as a read-only view and its output schema
has no field for a status or an overall verdict, so it structurally cannot change
a deterministic result - it can only add `LLM-OBS-*` observations (capped at
`WARN`/`UNKNOWN`), questions, and notes. Malformed LLM output is repaired once,
then discarded (`LLM_PARSE_ERROR`).

The knowledge root and index path are parameters (`SKOS_KNOWLEDGE_ROOT`,
`SKOS_DB_PATH`), so the same code serves `knowledge/` today and a Pack Manager's
`active/knowledge/` later. `top_k` counts Knowledge Units; secret-classified units
never enter the index.

`scripts/validate_knowledge.py` exits non-zero when any `ERROR`-level issue is found
(use `--strict` to also fail on warnings).

## Knowledge classification & layout (decision A1)

```
knowledge/
├─ public/            # git-tracked; retrievable in PUBLIC and PRIVATE mode
│  ├─ prompt-security/  rag-security/  agent-security/
│  ├─ memory-security/  credential-security/
│  └─ incidents/  methodology/
└─ private/           # git-ignored content (skeleton kept)
   ├─ internal/       # PRIVATE mode only
   └─ confidential/   # PRIVATE mode + explicit --allow-confidential

secret/               # OUTSIDE this repository, separate root.
                      # Never indexed, never sent to an LLM.
```

`classification: secret` appearing anywhere inside the repo is a validator **ERROR**.

## LLM configuration (decision A3)

The default provider is `none`. To enable an external LLM, set both:

```bash
export SKOS_LLM_PROVIDER=anthropic
export ANTHROPIC_API_KEY=...      # injected by the operator, never stored in the repo
```

See `.env.example`.

## Documentation

- `docs/knowledge-schema.md` — Knowledge Unit schema (front matter + body)
- `docs/safety-boundaries.md` — confirmed decisions A1/A3/A6/A7/A8, Human Gate list
- `docs/architecture.md` — component overview (stub until M8)
- `docs/threat-model.md` — threat model (stub until M8)
