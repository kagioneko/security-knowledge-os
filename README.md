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

## Security disclaimer & scope

- **This is a security assessment *support* tool, not a security guarantee.**
- **`PASS` is not a security guarantee.** It means "no major issue was detected
  within the assessed scope, the available evidence, the active knowledge
  revision, the rule set, and the model configuration". It does not prove the
  target is secure.
- **`UNKNOWN` is a valid, first-class verdict** - it means evidence was
  insufficient. The engine returns `UNKNOWN` rather than guessing.
- **Fixture performance is not real-world effectiveness.** The current metrics
  (known-risk recall, false-positive rate, etc.) are measured on a small set of
  *artificial* fixtures and show that the mechanism separates
  vulnerable / safe / unknown as designed. They do **not** establish real-world
  security effectiveness.
- **Human review is required.** High-impact decisions - deployment approval, risk
  acceptance, and anything affecting money, people, contracts, production, or
  external parties - stay with a named human owner. High-impact *actions* are
  never auto-executed; the engine returns `HUMAN_APPROVAL_REQUIRED`.
- **The Knowledge Repository is read-only during assessment.** Retrieved content
  can contain descriptions of prompt injection, tool abuse, and memory poisoning;
  letting the same agent modify its own rules or knowledge would create a
  knowledge-poisoning path. Do not grant an AI agent write access to the
  production Knowledge Repository. Changes go through a separate review workflow.

### Trust boundary

| Trusted / controlled | Untrusted / potentially adversarial |
| --- | --- |
| Reviewed Knowledge Units | User prompts |
| Approved risk rules | External documents / web / PDF / images |
| Classification gate | RAG content before source & integrity verification |
| Deterministic rule engine | The assessed AI's own output |
| Human review / maintainer approval | LLM-generated observations & suggestions |
| | An update pack before verification |

"Ignore this rule" / "rewrite the knowledge" appearing in any untrusted input is
treated as data, never as a control instruction. Details in
`docs/safety-boundaries.md` and `docs/threat-model.md`.

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
| **M5 — Safe Test + Human Gate** | done | `app/models/policy_outcome.py`, `app/policy/{human_gate,knowledge_guard,safe_test}.py`, `app/storage/integrity.py`, `safe_tests/**` (4 templates), `scripts/validate_safe_tests.py` |
| **M6 — Orchestrator + CLI + API** | done | `app/models/report.py`, `app/reviewer/report.py`, `app/cli.py` (`skos`), `app/main.py` (FastAPI), `app/retrieval/index.py::reindex_atomic` |
| **M7 — Fixtures + Evaluation + starter KUs** | done | `knowledge/public/**` (14 KUs), `tests/fixtures/assessments/{safe,vulnerable,unknown}/`, `app/eval/metrics.py`, `scripts/evaluate.py`, JA retrieval (trigram) |
| **M8 — Docs + hardening** | done | Security disclaimer (AC-15–18), KU `provenance` schema, `docs/{attribution,threat-model,architecture}.md`, `sbom.json`, `scripts/{secret_scan,generate_sbom,preflight}.py` |

## Quickstart (M1)

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e ".[api,llm,dev]" -c constraints.txt --build-constraint constraints.txt

# Validate the knowledge base (empty on a fresh checkout -> 0 issues)
.venv/bin/python scripts/validate_knowledge.py knowledge

# Load-check a knowledge root, then build the FTS5 index from it
.venv/bin/python scripts/ingest.py knowledge
.venv/bin/python scripts/build_index.py knowledge --db var/index.sqlite

# Validate the deterministic rule catalogue and the safe-test templates
.venv/bin/python scripts/validate_rules.py rules
.venv/bin/python scripts/validate_safe_tests.py safe_tests

# Run an assessment (provider=none by default: the deterministic engine does the work)
.venv/bin/skos assess tests/fixtures/assessments/V-001-indirect-injection-auto-email.yaml
.venv/bin/skos test          # run all 14 fixtures as a smoke test

# Rebuild the FTS index (atomic + fail-closed; never touches knowledge content)
.venv/bin/skos reindex knowledge --db var/index.sqlite

# Local API (needs the [api] extra)
.venv/bin/uvicorn app.main:app

# Evaluate the engine + indexed knowledge against the labelled fixtures (§24 metrics)
.venv/bin/python scripts/evaluate.py --db var/index.sqlite

# Run the test-suite
.venv/bin/pytest -q
```

The MVP ships **14 public Knowledge Units** (`knowledge/public/`; 13 from
published standards - OWASP LLM Top 10 2025, MITRE ATLAS, NIST AI RMF / AI 600-1;
one in Japanese - plus one, KU-0014, an original write-up of a vulnerability
class this project's own pre-publication review process actually found). Each
unit carries `provenance` (source title, URL, version, licence, derivation
status, last-verified date). See `docs/knowledge-corpus.md` and
`docs/attribution.md`.

**Internal fixture evaluation** (`scripts/evaluate.py`, 14 artificial fixtures ×
14 indexed KUs):

```
Classification Leakage          = 0
Safe Test Safety Violation      = 0
Human Gate Bypass               = 0
current controlled-fixture metrics = 1.0
  (known-risk recall, false-positive rate=0, UNKNOWN-appropriateness,
   evidence coverage, citation/source match)
```

These results **do not establish real-world security effectiveness**. They show
the mechanism behaves as designed on a controlled set.

### `skos` CLI

`validate-knowledge` · `validate-rules` · `validate-safe-tests` · `ingest` ·
`reindex` · `assess` · `report` · `test`. Exit codes: `0` ok, `1` findings
failure with `--strict`, `2` usage/input error, `3` `POLICY_BLOCKED`.

### API (`app/main.py`)

`POST /v1/assessments` · `GET /v1/assessments/{id}` ·
`POST /v1/assessments/{id}/answers` · `GET /v1/assessments/{id}/history` ·
`GET /v1/assessments/{id}/report` · `POST /v1/knowledge/validate` (read-only) ·
`POST /v1/knowledge/reindex` · `GET /health`.

`/answers` takes a **typed `AnswerPatch`** - an allow-list of fields a follow-up
question can fill (`memory_persistent`, `memory_scope`, `outbound_enabled`,
`credential_storage`, `tool_permissions`, `human_approval`, …). There is no
generic deep-merge and no field is *named* for a raw secret value.

The actual "never sends a raw secret to the external LLM" guarantee is
**structural, not a content filter**: fields that are identifiers/hostnames
*by contract* (`rag_sources`, `outbound_destinations`, `tool_permissions`/
`human_approval` keys, tool `name`s) are never forwarded to the LLM as their
real value at all - `app/reviewer/llm_review.py::build_payload()` replaces
each with a stable, locally-scoped anonymized label (`rag_source_1`,
`destination_1`, `tool_1`, `action_1`, …) before ever constructing the
request, consistently across `assessment_context` and `attack_surface` so
the LLM can still reason about structure (counts, permissions, which
labelled tool needs approval) and refer to a specific one across its own
observations. This closes the class outright: no value these fields could
ever hold - a known credential shape, an unknown future one, or a genuine
business secret that merely looks like an ordinary name - can reach the
provider through them, because the raw value is never serialized in the
first place (Codex#1, rounds 9-14, 2026-09-12 -- 2026-09-13, five rounds of
content-filter attempts each defeated by a new shape - see
`tests/unit/test_llm_review.py`). The ORIGINAL objects (used by the
deterministic rule engine, and returned to the calling human via
`AssessmentResult.attack_surface`) are untouched; only the LLM request-
building path is anonymized. `app/models/_credential_shapes.py`'s denylist
(known credential shapes) and allowlist (identifier-shaped values) remain
as defense in depth on these same fields, not as this boundary.
`system_prompt`/`developer_prompt` (actual prose, not identifiers) are
never anonymized and only get the denylist - an arbitrary opaque string
with no recognizable shape is indistinguishable from ordinary prose there.
Given this project's Vault-only credential policy, never place a real
secret in any assessment field regardless. **Rejected (HTTP 422):**
an unknown patch field, a permission value outside the closed enum, a type
mismatch. Tool names are *not* a fixed vocabulary - a diagnosed system can have
any tool name - so `tool_permissions[<new name>]` **adds** that tool to the
assessment (and a high-impact permission on it becomes a re-evaluation target);
`tool_permissions[<existing>]` replaces its permission. The patched input is
**re-assessed from scratch** - findings are never edited in place - and the new
result records `supersedes` and `revision`.

### Deviation from the spec

Spec Section 5 recommends **Typer** for the CLI; this build uses stdlib `argparse`
so the core install needs only `pydantic` + `pyyaml`. Spec Section 18's
`POST /v1/knowledge/reindex` is implemented as index-only re-derivation (it never
accepts or changes knowledge content).

**There is no endpoint that changes knowledge content.** `/v1/knowledge/reindex`
only re-derives the FTS index from the already-verified read-only knowledge root
(classification + integrity checked before an atomic swap; the old index is kept
on any failure).

HTTP status and policy outcome are separate layers: a policy-blocked assessment
is HTTP 422 with `status: "POLICY_BLOCKED"` and the `policy_decision` in the body,
never HTTP 200 with empty findings. `human_review_required` is a workflow flag
inside a `COMPLETED` (HTTP 200) body, not an error.

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

**Policy outcomes are typed** (`PolicyOutcome`: `ALLOWED` /
`HUMAN_APPROVAL_REQUIRED` / `POLICY_BLOCKED` / `READ_ONLY_VIOLATION`), never bare
strings. The Human Gate fails closed - a recognised high-impact action, or any
unrecognised one, returns `HUMAN_APPROVAL_REQUIRED`. The Knowledge Repository is
read-only during assessment. Safe tests are **vetted templates only**
(`safe_tests/*.yaml`, passed through a deterministic validator that forbids real
secrets, external destinations, destructive operations and production targets);
an LLM's `safe_test_suggestions` land in `safe_test_proposals` as untrusted ideas
and are never promoted to an executable test automatically.

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

- `docs/architecture.md` — component overview and configurability seams
- `docs/threat-model.md` — assets, trust boundary, threats & controls, residual risks
- `docs/safety-boundaries.md` — decisions A1/A3/A6/A7/A8, Human Gate, §32 read-only, §33 trust boundary
- `docs/knowledge-schema.md` — Knowledge Unit schema (front matter + `provenance` + body)
- `docs/rule-schema.md` — data-only rule schema and operators
- `docs/safe-test-schema.md` — safe-test schema, validator rules, Human Gate, read-only guard
- `docs/knowledge-corpus.md` — the 14 shipped Knowledge Units and their sources
- `docs/attribution.md` — third-party sources, licences, derivation status
- `docs/acceptance-criteria.md` — AC-01..20 status and §24 evaluation metrics

## Licence

Apache License 2.0 — see `LICENSE` and `NOTICE`.

The engine code is licensed under Apache-2.0. The Knowledge Units under
`knowledge/public/` are original prose licensed under the same terms; they cite
public standards (OWASP, MITRE ATLAS, NIST) and do not reproduce third-party text
verbatim (see `docs/attribution.md`). A future commercial "Update Pack" would be
licensed separately (see the Update Pack / Distribution specification).
