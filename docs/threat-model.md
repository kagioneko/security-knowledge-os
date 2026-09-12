# Threat Model

Scope: the assessment tool itself, not the systems it assesses. Spec Sections 25,
32, 33.

## Assets

- Knowledge base content, especially `internal` / `confidential` units.
- `secret`-classified knowledge - stored **outside** this repository; must never
  enter it. `classification: secret` inside the repo is a validator ERROR.
- Operator LLM API credentials (only present when `SKOS_LLM_PROVIDER` is a real
  provider).
- Assessment inputs (a customer's system prompts, tool configs).
- The rule catalogue and safe-test templates - the "measuring stick".

## Trust boundary

See `docs/safety-boundaries.md` §33. In short: reviewed knowledge, approved rules,
the classification gate, the deterministic engine, and human approval are trusted.
User prompts, external / retrieved content, the assessed AI's output, LLM
observations, and unverified update packs are untrusted.

## Threats and controls

| threat | control | where |
| --- | --- | --- |
| `secret` knowledge reaches retrieval or the LLM | classification gate (4 layers: validator, loader, repository, retriever) + `secret/` git-ignored + `secret` never in the index | M1 / M2 |
| a rule file becomes a code-execution path | rules are data only - closed operator enum, whitelisted fact fields, no `eval` / `exec` / dynamic dispatch on the evaluation path | M3 |
| the LLM fabricates or suppresses a verdict | LLM output schema has no status field; observations capped at `LLM-OBS-*` / `WARN`+`UNKNOWN`; `merge_findings` refuses anything else | M4 |
| an LLM safe-test idea is executed | proposals are `origin: llm`, 3 fields, never executable; `promote_proposal` is always `HUMAN_APPROVAL_REQUIRED`; templates pass a deterministic validator (no real secrets / external destinations / destructive ops / production targets) | M5 |
| the assessment process performs a high-impact action | the system executes nothing; `evaluate_action` fails closed to `HUMAN_APPROVAL_REQUIRED` | M5 |
| an agent poisons its own knowledge / rules | Knowledge Repo is read-only during assessment; no knowledge-write API; `READ_ONLY_VIOLATION` on any mutating op | M5 / M6 |
| a tampered index is used | `verify_chunk_hashes` before use; `reindex_atomic` verifies classification + integrity before an atomic swap and keeps the old index on failure | M5 / M6 |
| a policy stop is swallowed as a normal result | `AssessmentReport` is `COMPLETED` xor `POLICY_BLOCKED`; the API returns HTTP 422 with the `policy_decision`, never HTTP 200 with empty findings | M6 |
| API key committed or logged | `.gitignore` for `.env`; keys only from env; prompts not logged verbatim; `scripts/secret_scan.py` in preflight | all |
| assessment input treated as instructions to the reviewer | inputs parsed into typed models; never concatenated into the system prompt; the reviewer prompt frames deterministic findings as read-only context | M3 / M4 |
| an update pack ships malicious content | out of MVP scope (Pack Manager = M9-M10); the spec requires path-traversal / symlink / absolute-path rejection, checksum + signature, staging + atomic swap, and no auto-apply of `severity` downgrades or Human-Gate removals |

## Non-goals

Unauthorised assessment of third-party systems; attack tests with real secrets or
real external delivery; exploit generation as a primary purpose; a runtime API
that edits knowledge content.

## Residual risks (accepted for the MVP)

- API assessment store is in-memory (lost on restart) - `§18` "unauthenticated
  localhost" scope.
- Integrity is a content hash (SHA-256), which proves the index matches the
  knowledge files, **not** that the knowledge files are authentic. Signature /
  trusted-manifest / human-approval is Pack Manager (M9-M10) work.
- Fixtures are artificial; the evaluation numbers show mechanism, not field
  performance.
- Licence: Apache-2.0 (`LICENSE`, `NOTICE`).
