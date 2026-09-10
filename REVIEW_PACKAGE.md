# Review Package — Security Knowledge OS (pre-publication)

Prepared for the cross-AI review required by `AI_RULES.md` before the first public
push. **Not yet pushed.** Licence: Apache-2.0.

Split the review into two roles:

- **Code audit** (e.g. Codex): implementation, types, exception handling,
  permission boundaries, unsafe paths, SQL, file operations, missing tests.
- **Adversarial design audit** (e.g. Antigravity): how to fool the system itself,
  poison the knowledge, pull `UNKNOWN` toward `PASS`, bypass the Human Gate, or
  turn a future Update Pack into an RCE path.

Checklist for both: `REVIEW_CHECKLIST.md`. What ships: `PUBLICATION_MANIFEST.md`.

---

## 1. System overview

Security Knowledge OS is a **deterministic security-assessment engine + knowledge
retrieval + optional LLM assistance**. It converts security knowledge into
versioned Knowledge Units and evaluates an AI/agent system description against a
data-only rule catalogue, producing findings, questions, safe-test plans and an
overall status. It supports a human decision; it does not make one.

```
AssessmentInput -> normalize -> AssessmentContext -> facts (whitelist)
  -> deterministic Rule Engine -> Finding[] (rule)
  -> retrieval (trigram FTS5 over knowledge/public, integrity-checked)
  -> optional LLM review (observations only) -> LLM-OBS-* findings
  -> rollup (A6) + merge (A8) -> questions / missing info / safe tests
  -> AssessmentReport { status: COMPLETED | POLICY_BLOCKED, result?, policy_decision? }
```

Entry points: `skos` CLI (`app/cli.py`), FastAPI (`app/main.py`), library
(`app/reviewer/assess.py::assess`).

## 2. Trust boundary

| Trusted / controlled | Untrusted / potentially adversarial |
| --- | --- |
| Reviewed Knowledge Units | User prompts |
| Approved risk rules (`rules/`) | External documents / web / PDF / images |
| Classification gate | RAG content before source & integrity verification |
| Deterministic rule engine | The assessed AI's own output |
| Human review / maintainer approval | LLM-generated observations & suggestions |
| Safe-test templates (`safe_tests/`) | An Update Pack before verification (future) |

Instructions embedded in any untrusted input ("ignore this rule", "rewrite the
knowledge") are treated as data, never control.

## 3. Threat model

`docs/threat-model.md`. Key controls:

| threat | control |
| --- | --- |
| `secret` knowledge reaches retrieval/LLM | classification gate at 4 layers (validator, loader, repository, retriever); `secret/` outside repo; `secret` never indexed |
| a rule file becomes a code-execution path | rules are data - closed operator enum, whitelisted fact fields, no `eval`/`exec`/dynamic dispatch (see `app/reviewer/clause_eval.py`, `test_no_code_execution.py`) |
| LLM fabricates/suppresses a verdict | output schema has no status field; `LLM-OBS-*` capped at `WARN`/`UNKNOWN`; `merge_findings` refuses anything else |
| an LLM safe-test idea is executed | proposals `origin: llm`, 3 fields, non-executable; `promote_proposal` is always `HUMAN_APPROVAL_REQUIRED`; templates pass a deterministic validator |
| assessment performs a high-impact action | the system executes nothing; `evaluate_action` fails closed |
| agent poisons its own knowledge | Knowledge Repo read-only during assessment; no knowledge-write API; `READ_ONLY_VIOLATION` |
| tampered index used | `verify_chunk_hashes` before use; `reindex_atomic` verifies before an atomic swap, keeps old index on failure |
| policy stop swallowed as normal result | `AssessmentReport` is `COMPLETED` xor `POLICY_BLOCKED`; API returns HTTP 422 with `policy_decision`, never 200-with-empty-findings |

## 4. Read-only Knowledge policy (spec §32)

- `app/policy/knowledge_guard.py`: `read`/`list`/`search` -> `ALLOWED`; every
  mutating or unknown op -> `READ_ONLY_VIOLATION`; `guard_knowledge_operation`
  raises `PolicyStop`.
- `app/reviewer/assess.py` contains no knowledge write; assessments complete
  against a read-only SQLite connection (`test_assess_m5.py::test_ac14_*`).
- **No runtime API changes knowledge content.** `POST /v1/knowledge/validate` is
  read-only; `POST /v1/knowledge/reindex` only re-derives the FTS index from the
  existing verified read-only knowledge root (classification + integrity checked;
  atomic swap; old index kept on failure). `test_api.py::test_no_knowledge_write_endpoint`.

## 5. Deterministic rule vs LLM responsibility (decision A8)

```
Deterministic Rule Engine  --immutable Finding[]-->  LLM Reviewer  --observations only-->  merge
```

- The LLM receives deterministic findings as a **read-only view**
  (`DeterministicFindingView`). Its output schema (`ReviewerObservations`) has
  **no field** for a status or an overall verdict, so it structurally cannot
  change one. `test_llm_output_schema.py`, `test_llm_boundary.py`.
- LLM observations become `LLM-OBS-NNNNN` findings, `origin="llm"`, capped at
  `WARN`/`UNKNOWN` by the `Finding` model validator.
- `rollup.merge_findings` refuses any LLM finding that is not `origin="llm"` or
  that collides with a rule id.
- Malformed LLM output: one repair attempt, then `LLM_PARSE_ERROR` with **no
  fabricated observations**.

## 6. Human Gate (spec §15)

`app/policy/human_gate.py::evaluate_action`:

- recognised high-impact action (`external_send`, `file_delete`, `file_write`,
  `production_change`, `money_movement`, `hr_judgement`, `legal_judgement`,
  `credential_retrieval`, `destructive_shell`) or a known alias -> `HUMAN_APPROVAL_REQUIRED`
- explicit side-effect-free kind (`read`, `list`, `search`, `retrieve`, `analyze`,
  `classify`, `noop`, `sandbox_probe`) -> `ALLOWED`
- anything else -> **fail closed** -> `HUMAN_APPROVAL_REQUIRED`

The system never executes an action. `test_human_gate.py`.

## 7. Fail-closed conditions

- Evidence insufficient -> `UNKNOWN` (never a guessed `PASS`) — `rule_engine`, AC-19.
- Classification decision fails -> `PolicyBlocked` stops retrieval and LLM input.
- LLM output fails to parse -> repair once -> `LLM_PARSE_ERROR`, no observations.
- Rule/LLM disagree -> LLM cannot lift/downgrade a deterministic `FAIL`/`WARN`.
- Human Gate decision fails -> `HUMAN_APPROVAL_REQUIRED`.
- Index integrity / revision check fails -> `POLICY_BLOCKED`; `PolicyStop` aborts.
- `reindex_atomic` failure -> existing index untouched (no partial update).

`test_fail_closed.py`, `test_reindex.py`.

## 8. Classification structure (decision A1)

```
knowledge/
  public/      git-tracked; retrievable in PUBLIC and PRIVATE mode
  private/     git-ignored content (skeleton kept)
    internal/      PRIVATE mode only
    confidential/  PRIVATE mode + explicit --allow-confidential
secret/          OUTSIDE the repository. Never indexed, never sent to an LLM.
```

- `classification: secret` anywhere in the repo is a validator ERROR.
- Retrieval filters by `is_retrievable(classification, mode, allow_confidential)`
  in SQL **and** re-checks each returned chunk (defence in depth); a leak raises
  `PolicyBlocked`.
- All 13 shipped Knowledge Units are `classification: public`.
- `PolicyOutcome` enum: `ALLOWED` / `HUMAN_APPROVAL_REQUIRED` / `POLICY_BLOCKED` /
  `READ_ONLY_VIOLATION` (typed, never a bare string).

## 9. Known limitations / accepted risks

| item | note |
| --- | --- |
| API assessment store is in-memory | lost on restart; spec §18 "unauthenticated localhost" scope |
| integrity = SHA-256 (content), not authenticity | signature / trusted manifest / human approval is Pack Manager (M9-M10) |
| fixtures are artificial | the §24 metrics (all 1.0) show the mechanism, not real-world detection performance |
| `status: reviewed` on KUs | means "summarised from a reviewed public standard"; a human should still do a final pass before publishing |
| `retrieval/hybrid.py` | thin BM25 wrapper; embeddings / reranker are future work |
| JA-R02 (cross-language retrieval) | out of MVP scope; test skipped |
| Update Pack / Pack Manager | not in this codebase (M9-M10, separate track); the ZIP-import attack surface it introduces is future work |
| trigram tokenizer | substring matching; can over-retrieve on a large corpus (fine for 13 KUs) |

## 10. How to run

```
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python scripts/preflight.py      # pytest + ruff + mypy + validators + scans
.venv/bin/skos test                        # 12-fixture smoke
.venv/bin/python scripts/evaluate.py --db var/index.sqlite   # §24 metrics
```
