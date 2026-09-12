# Publication Manifest — Security Knowledge OS v0.1.0

Snapshot of what the first public push contains. Generated for the pre-publication
review; regenerate with `git ls-files` after any change.

- Commit: `bccbf6d` (round-7 cross-review findings addressed, **not yet pushed**)
- Licence: **Apache-2.0** (`LICENSE`, `NOTICE`, `pyproject.toml`)
- Tracked files: **206**
- Tests: **468** items (467 pass, 1 skip = JA-R02)
- `scripts/preflight.py`: **PASS** (now also runs `pip-audit`, round 7
  Codex#13, and enforces the SBOM's dependency-closure/license fixes,
  round 7 Codex#9)
- Cross-AI review: Codex (code audit) + Antigravity (adversarial design
  audit), **seven rounds**, 2026-09-11 -- 2026-09-12. Rounds 1-2
  (2026-09-11): CHANGES-REQUIRED both times, 19 then 13 findings, all
  fixed — see `REVIEW_CHECKLIST.md` sign-off tables. Rounds 3-6
  (2026-09-12): CHANGES-REQUIRED each time, independent findings each
  round, mostly deeper versions of the same areas the previous round
  touched (reindex TOCTOU/rollback edge cases, YAML/dependency/licence
  accuracy, concurrency gaps, chunk-hash/FTS-integrity coverage, the
  empty-root guard, foreign-database clobbering, secret leakage into
  public findings, SBOM/manifest/secret-scan self-consistency) — all
  fixed each round; Antigravity **PASS-with-nits** on the round-5 commit
  (two low-severity nits, not blocking). Itemized in `git log` commit
  messages ("fix round-N Codex#…") rather than this file. Round 7
  (2026-09-12, audited commit `ad03a9a`): Codex **CHANGES-REQUIRED** again
  (13 findings independent of round 6's: 3 HIGH — reindex could publish
  transient/mixed corpus content read during the build, symlink
  containment was still racy through an ANCESTOR-directory swap (not just
  the final component), a rule with no conditions/checks/manual_review
  yielded a false PASS; 7 MEDIUM — index files created world-readable,
  malformed corpus/YAML inputs (invalid UTF-8, deep nesting) escaped typed
  results in rule/safe-test loaders too, an empty safe-test catalogue was
  never checked on the assess()/API path, an unpaired-surrogate LLM
  response bypassed the repair flow, `--require-complete` could overwrite
  a valid SBOM before deciding to fail, the SBOM inventoried environment
  noise (pip, the project itself) and had a license-classifier parsing
  bug, secret-scan had whole-file/broad-word false negatives; 3 LOW —
  `Finding` was mutable after validation, `AnswerPatch`'s "no raw secret"
  claim was stronger than the schema provides, dependency resolution
  admitted a known-vulnerable pytest floor) — **all 13 fixed**, each with
  a regression test confirmed to fail against the pre-fix code (or, for
  the two pure dependency-management items, verified directly) — see
  `git log` commit messages ("fix round-7 Codex#…") for the itemized
  mapping. An eighth round re-reviewing these round-7 fixes is the next
  step before push.

## Tracked files by area

Per-area counts below were last verified at round 2 (commit `bcd9519`) and
have not been re-walked file-by-file for rounds 3-5; `git ls-files <area>`
is authoritative if these drift. The two numbers the automated preflight
check enforces (total tracked files, total tests) are kept current above.

| area | files | notes |
| --- | --- | --- |
| `app/` | 56 (.py) | engine, models, policy, retrieval, reviewer, llm, storage, eval, cli, main |
| `tests/` | 74 | 41 test modules + fixtures (round 5 added test_build_index_script.py, test_anthropic_client.py, test_preflight_manifest.py) |
| `knowledge/` | 23 | 13 public KUs + `private/` skeleton (README + 2 `.gitkeep`) + category `.gitkeep`s |
| `rules/` | 13 | 7 rule YAMLs + category `.gitkeep`s |
| `safe_tests/` | 4 | 4 vetted templates |
| `scripts/` | 12 | validators, ingest/build_index, assess, evaluate, sbom, secret_scan, preflight, cross-review runner |
| `docs/` | 9 | see below |
| `reviews/` | 2 | `.gitignore` + `README.md` only — cross-review output `.md`/`.log` files are gitignored, never tracked |
| root | 10 | `README.md`, `LICENSE`, `NOTICE`, `pyproject.toml`, `.gitignore`, `.env.example`, `sbom.json` |
| review docs | 3 | `REVIEW_PACKAGE.md`, `REVIEW_CHECKLIST.md`, `PUBLICATION_MANIFEST.md` |

Docs: `architecture`, `threat-model`, `safety-boundaries`, `knowledge-schema`,
`rule-schema`, `safe-test-schema`, `knowledge-corpus`, `attribution`,
`acceptance-criteria`.

## Explicitly excluded (in `.gitignore`)

- `/secret/` — secret-classified knowledge (must live outside the repo)
- `.env`, `*.key`, `*.pem`, `.claude/`
- `/knowledge/private/**` content — only the folder skeleton + README are tracked
- `/packs/`, `/active/`, `/var/`, `*.sqlite` — Pack Manager local state, built index
- `.venv/`, `__pycache__/`, `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`, `dist/`, `build/`, `*.egg-info/`

Verified: no `secret/`, no `.env`, no private-KU content tracked
(`scripts/preflight.py`).

## Public Knowledge Units (13)

All `classification: public`, `status: reviewed`, `derivation: summary`
(original prose, no verbatim third-party text). Full list + per-unit sources in
`docs/knowledge-corpus.md`; licence analysis in `docs/attribution.md`.

| id | category | source |
| --- | --- | --- |
| KU-0001 | prompt-security | OWASP LLM Top 10 2025 LLM01 |
| KU-0002 | rag-security | OWASP LLM01 (+ simonwillison.net, referenced not reproduced) |
| KU-0003 | rag-security | OWASP LLM08 |
| KU-0004 | agent-security | OWASP LLM06 |
| KU-0005 | agent-security | OWASP LLM06 + MITRE ATLAS |
| KU-0006 | agent-security | OWASP LLM02 |
| KU-0007 | memory-security | OWASP LLM04 |
| KU-0008 | credential-security | OWASP LLM02 |
| KU-0009 | credential-security | NIST AI 600-1 |
| KU-0010 | prompt-security | OWASP LLM07 |
| KU-0011 | methodology | OWASP LLM05 |
| KU-0012 | governance | NIST AI RMF 1.0 |
| KU-0013 | methodology (Japanese) | MITRE ATLAS + OWASP LLM06 |

Source licences: OWASP CC-BY-SA-4.0 · MITRE ATLAS Terms of Use · NIST public
domain. No content in the repo is under terms incompatible with Apache-2.0
redistribution.

## Rules (7)

`rules/` — data-only YAML, operators `{eq, ne, in, contains, is_unknown}`, facts
from `app/reviewer/facts.py::FACT_SPEC` (whitelist).

| id | severity | category | detects |
| --- | --- | --- | --- |
| PI-003 | high | rag-security | indirect injection + outbound path |
| MEM-001 | high | memory-security | persistent memory + untrusted ingestion |
| TOOL-001 | high | agent-security | high-impact tool without approval |
| TOOL-000 | medium | agent-security | tool permissions unspecified -> UNKNOWN |
| CRED-001 | high | credential-security | raw secret reachable by the model |
| GOV-001 | medium | governance | high-impact actions without approval coverage |
| OUT-001 | medium | agent-security | outbound enabled without a destination allow-list |

Safe-test templates (4): `ST-IPI-001`, `ST-MEM-001`, `ST-TOOL-001`, `ST-CRED-001`.

## Fixtures

- Assessment fixtures: **14** in `tests/fixtures/assessments/{safe,vulnerable,unknown}/`
  (4 safe, 5 vulnerable, 5 unknown — U-005 for the ADV-01 regression, V-005
  for the round-2 ADV-05 regression). Labels drive `scripts/evaluate.py`.
- Knowledge/validator fixtures: 16 `.md` under `tests/fixtures/` (valid, invalid,
  secret-in-repo, corpus, corpus_alt) — test data only, `source_license: "test
  fixture - not for distribution"`.

## Dependencies (`sbom.json`)

29 components — every distribution actually installed in the project `.venv`
(Codex finding #12 fixed the previous hand-maintained allowlist, which
silently omitted transitive dependencies). Core install = `pydantic` +
`pyyaml`; the rest are `[api]`/`[llm]` extras or dev/test-only. Zero
`UNKNOWN` licences. Licences present: MIT, BSD (2/3-Clause), Apache-2.0,
PSF-2.0 — permissive — plus **`pathspec` and `certifi`, both under MPL-2.0**
(Codex finding #10, round 2, 2026-09-11, corrected round 3, 2026-09-12: an
earlier draft said "all permissive"; the first correction still missed
`certifi` and misattributed `pathspec`'s dependency chain). MPL-2.0 is
file-level (weak) copyleft, not permissive, but it does not require this
Apache-2.0 project to relicense anything — its copyleft obligations attach
only to each package's own source files. `certifi` is a transitive
dependency of `httpx`/`httpcore` (the `[llm]` extra's HTTP client);
`pathspec` is a transitive dependency of `mypy` (**not** `ruff`, which
declares no dependencies of its own per installed-environment metadata) —
both dev/test-only or extras, never imported by, bundled with, or
distributed as part of `app/`'s core install. None of the 29 components
conflict with Apache-2.0 distribution of this project. Full list in
`sbom.json`.

## §24 evaluation (internal fixtures — not real-world performance)

```
known_risk_recall        = 1.000
false_positive_rate      = 0.000   (gate: 0)
unknown_appropriateness  = 1.000
evidence_coverage        = 1.000
citation_source_match    = 1.000
safe_test_violations     = 0       (gate: 0)
```

Fixtures are artificial. These numbers show the mechanism separates
vulnerable / safe / unknown as designed; they do **not** establish real-world
security effectiveness (stated in README).

## Acceptance criteria

AC-01 .. AC-20: all **done** (`docs/acceptance-criteria.md`).

## Known / accepted risks

| item | status |
| --- | --- |
| API assessment store in-memory (FIFO cap 5000 entries; `AssessmentInput` fields size-bounded; repeated-patch results deduped) | accepted (spec §18 localhost scope) — round-1 Codex#10, round-2 Codex#6 |
| integrity = SHA-256 (content, not authenticity) | accepted (signature is Pack Manager, M9-M10) — Antigravity ADV-03 |
| `Finding` A8 boundary can be bypassed via direct Python `model_copy(update=...)` | accepted — Codex#13: no code path in this app does this; Pydantic's construction bypass is a library property, not a security boundary; the actual boundary is the LLM's JSON output going through `model_validate_json` + schema `extra="forbid"`, which cannot be bypassed this way |
| `SafeTest._FORBIDDEN` regex deny-list would be bypassable by a determined author if a future execution engine is added | accepted / architectural note — Antigravity ADV-04: no execution engine exists yet (safe tests are non-executable templates only); M9-M10 must use sandboxed execution (gVisor/bubblewrap), not regex filtering, when one is added |
| fixtures artificial; §24 metrics = mechanism check | accepted (stated in README) |
| KU `status: reviewed` = "summary of a reviewed public standard" | accepted (human final pass recommended) |
| `retrieval/hybrid.py` is a thin wrapper | accepted (embeddings/reranker future) |
| JA-R02 cross-language retrieval | accepted (out of MVP scope) |
| CLI uses argparse, not Typer (spec §5) | accepted, documented |
| Pack Manager (M9-M10) not in repo | out of scope; ZIP-import attack surface is future work |

## Cross-AI review — seven rounds so far, round 8 pending

1. **Round 1** (Codex code audit + Antigravity adversarial design audit) per
   `AI_RULES.md`, 2026-09-11, recorded in `HANDOFF.md`. Both verdicts:
   **CHANGES-REQUIRED**, 19 findings. 16 fixed (regression tests confirmed
   to fail against the pre-fix code), 3 accepted/documented above.
2. **Round 2** — re-review of the round-1 fixes, same two reviewers, same
   date, against commit `28e3c06`. Both verdicts: **CHANGES-REQUIRED** again
   — 13 NEW findings, independent of round 1's (mostly in code paths round 1
   did not touch: RAG-source trust default, the `assess()`/`build_index()`
   library entry points, reindex publish ordering, CSRF via Origin vs Host, a
   second unguarded symlink read, SQLite/YAML edge cases, SBOM schema
   compliance, request size limits). Round 1's fixes themselves held up under
   re-review. **All 13 fixed** — see `REVIEW_CHECKLIST.md` for both rounds'
   full findings-to-commit tables.
3. **Rounds 3-4** (2026-09-12): re-review of the round-2 fixes and then the
   round-3 fixes. Both verdicts **CHANGES-REQUIRED** each time — independent
   findings each round, mostly in reindex TOCTOU/rollback edge cases, YAML
   merge-key/nesting DoS, dependency-licence accuracy, and origin/body-size/
   concurrency gaps. All fixed each round. See `git log` commit messages
   ("fix round-3 Codex#…" / "fix round-4 Codex#…") for the itemized
   findings-to-commit mapping — not reproduced in this file.
4. **Round 5** (2026-09-12, audited commit `ecb410e`): Codex
   **CHANGES-REQUIRED** — 11 findings (1 HIGH: a forgeable "localhost-only"
   API boundary relying only on client-supplied headers; 8 MEDIUM: FTS
   content-integrity gap, corpus load TOCTOU double-read, two reindex
   failure-coverage/rollback-truthfulness gaps, raw provider-exception text
   reaching a public finding, unguarded concurrent store eviction, an unsafe
   direct index-build script overwriting a live index, this manifest and
   `reviews/.gitignore` drifting from reality, SBOM coverage silently
   omitting declared dependencies; 2 LOW: an unvalidated safe-test root, and
   unbounded external LLM output). **All 11 fixed**, each with a regression
   test confirmed to fail against the pre-fix code — see `git log` commit
   messages ("fix round-5 Codex#…") for the itemized mapping. Antigravity's
   independent adversarial design audit on the same commit: **PASS-with-
   nits** (two low-severity nits, not blocking; `NIT-ADV-01`/`NIT-ADV-02`).
5. **Round 6** (2026-09-12, audited commit `823c5e4`): Codex
   **CHANGES-REQUIRED** — 10 findings independent of round 5's, mostly
   deeper versions of the same areas round 5 touched (1 HIGH: the chunk
   hash covered only `text`, so a classification flip passed integrity as
   ALLOWED; 7 MEDIUM: the round-5 FTS exact-phrase probe missed an
   appended-token tamper, the empty-knowledge-root guard was only at the
   CLI layer not in `reindex_atomic()`/the API, an unrelated SQLite file
   with a compatible `meta` table could be silently adopted and clobbered,
   the symlink containment check was still TOCTOU-racy at the read itself,
   `str(ValidationError)` leaked pydantic's rejected input value into a
   public finding, an oversized rejected response was still forwarded
   intact during LLM repair, preflight accepted and rewrote a partial SBOM;
   2 LOW: reindex lock/setup failures raised raw exceptions instead of a
   typed result, this manifest's own commit line was never checked against
   git history). **All 10 fixed**, each with a regression test confirmed to
   fail against the pre-fix code — see `git log` commit messages ("fix
   round-6 Codex#…") for the itemized mapping.
6. **Round 7** (2026-09-12, audited commit `ad03a9a`): Codex
   **CHANGES-REQUIRED** — 13 findings independent of round 6's (3 HIGH:
   reindex could publish transient/mixed corpus content changed and
   restored during the build, symlink containment was still racy through
   an ANCESTOR-directory swap rather than just the final component, a rule
   with no conditions/checks/manual_review yielded a false PASS; 7 MEDIUM:
   index files created world-readable, malformed corpus/YAML inputs
   (invalid UTF-8, ~1,500 nested collections) escaped typed results in the
   rule/safe-test loaders too, an empty safe-test catalogue was never
   checked on the assess()/API path, an unpaired-surrogate LLM response
   bypassed the repair flow, `--require-complete` could overwrite a valid
   SBOM before deciding to fail, the SBOM inventoried environment noise
   (pip, the project's own component) plus a license-classifier parsing
   bug, secret-scan had whole-file/broad-word false negatives; 3 LOW:
   `Finding` was mutable after validation via direct assignment,
   `AnswerPatch`'s "no raw secret" claim was stronger than the schema
   provides, dependency resolution admitted a known-vulnerable pytest
   floor with an unversioned build backend). **All 13 fixed**, each with a
   regression test confirmed to fail against the pre-fix code (or, for the
   two pure dependency-management items, verified directly) — see `git
   log` commit messages ("fix round-7 Codex#…") for the itemized mapping.
7. `scripts/preflight.py`: **PASS** after all seven rounds' fixes (468
   tests, ruff + mypy --strict clean, commit `bccbf6d`), now also running
   `pip-audit` (round 7, Codex#13) and requiring the SBOM's
   dependency-closure fixes (round 7, Codex#9).
8. An eighth re-review round is queued to confirm the round-7 fixes before
   push, per the same AI_RULES requirement ("修正した上で再レビューを受ける
   こと") applied again.
9. Human confirmation: no real customer / private material in any commit —
   still to confirm before push.
