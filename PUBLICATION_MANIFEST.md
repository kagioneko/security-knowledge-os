# Publication Manifest — Security Knowledge OS v0.1.0

Snapshot of what the first public push contains. Generated for the pre-publication
review; regenerate with `git ls-files` after any change.

- Commit: `2c04fda` (round-13 fixes + a post-round-13 hardening pass, **not yet pushed**)
- Licence: **Apache-2.0** (`LICENSE`, `NOTICE`, `pyproject.toml`)
- Tracked files: **211**
- Tests: **619** items (618 pass, 1 skip = JA-R02)
- `scripts/preflight.py`: **PASS** (now also verifies the documented
  quickstart `pip install -e` command installs every declared extra,
  pins `constraints.txt`, AND passes `--build-constraint constraints.txt`
  so pip's isolated build environment is pinned too, round 11 Codex#9 /
  round 12 Codex#7; and that the tracked `sbom.json` matches the current
  environment, ignoring only its timestamp, without preflight itself
  rewriting that tracked file to check it, round 11 Codex#12)
- Cross-AI review: Codex (code audit) + Antigravity (adversarial design
  audit), **thirteen rounds**, 2026-09-11 -- 2026-09-13. Rounds 1-2
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
  mapping. Round 8 (2026-09-12, audited commit `46e3a00`): Codex
  **CHANGES-REQUIRED** again (15 findings independent of round 7's: 2 HIGH —
  a rule with a trigger `conditions` block but empty `checks` and
  `manual_review=False` still loaded and, once triggered with full
  evidence, produced zero findings and a silent PASS (two real shipped
  rules had this exact shape), and the round-7 snapshot copy was still not
  atomic against a write landing (and even being reverted) during the
  read itself, nor against directory entries changing mid-walk; 9 MEDIUM —
  cross-port localhost Origins passed the CSRF gate, DB/lock setup
  followed symlinks and chmod'd shared directories, rule/safe-test
  loaders retained the round-7 snapshot fix's ancestor-directory
  protection gap themselves, `knowledge_revision`/`fts_shadow_digest`
  were checked for presence but not shape, README overstated the "no raw
  secret" guarantee beyond what the schema provides, store eviction was
  entry-count- not byte-based (~1.5 GB worst case), SBOM scope/group
  didn't account for a package reachable only transitively through a
  required root, the SBOM's own atomic-write temp path followed a
  symlink, secret-scan's suffix allowlist and decode-failure handling
  both failed open; 4 LOW — per-key answer-lock eviction could serve a
  fresh, uncontended lock for a key still held elsewhere, request-size
  enforcement was bypassed on a bodyless route, several serialized report
  models lacked `extra="forbid"`, dependency resolution had no reviewed
  lock) — **all 15 fixed**, each with a regression test confirmed to fail
  against the pre-fix code via `git stash` — see `git log` commit messages
  ("fix round-8 Codex#…") for the itemized mapping. Round 9 (2026-09-13,
  audited commit `d20b714`): Codex **CHANGES-REQUIRED** again (13 findings
  independent of round 8's: 2 HIGH — the round-8/9 snapshot's per-file
  identity check still had a scan-to-open window where a regular file
  could be swapped for a different one of the same name, and
  AnswerPatch/AssessmentInput free-text fields accepted a credential-shaped
  value that flowed into the LLM payload; 7 MEDIUM — connect()'s O_NOFOLLOW
  check-then-sqlite3.connect() sequence still had a check-to-use race,
  saved reports could claim a contradictory overall_status/
  human_review_required, the /answers cache key omitted rule/safe-test/
  knowledge-revision/settings context, the API had no concurrency
  admission control, four more nested report models still lacked
  `extra="forbid"`, constraints.txt was never actually compared against
  the installed environment, and the SBOM ignored non-extras PEP 508
  markers while missing an applicable-but-absent transitive dependency
  case; 4 LOW — chunked (Content-Length-less) oversized bodies still
  bypassed the bodyless-route limit, reindex error responses disclosed
  configured filesystem paths, heterogeneous YAML mapping keys raised a
  raw TypeError, and the manifest's own component-count statement drifted
  a second time uncaught) — **all 13 fixed**, each with a regression test
  confirmed to fail against the pre-fix code via `git stash` — see
  `git log` commit messages ("fix round-9 Codex#…") for the itemized
  mapping. Round 10 (2026-09-13, audited commit `f1acfb5`): Codex
  **CHANGES-REQUIRED** again (10 findings independent of round 9's: 2 HIGH —
  reindex_atomic()'s backup copy used a predictable path and `shutil.copy2`,
  so a pre-created symlink at that path let an attacker overwrite an
  arbitrary file with SQLite bytes, and the verified staging database could
  be substituted with a symlink to an attacker-built database between
  verification and the final `os.replace()`; 4 MEDIUM — direct (non-reindex)
  corpus loading via `load_corpus()` was still vulnerable to an ancestor
  directory being swapped to a symlink after containment checks passed, the
  knowledge revision hash omitted `classification`/`title`/`category`/
  `source_ref`/`provenance` so changing them without bumping `version` left
  the `/answers` cache key unchanged, that same cache key was computed from
  a separate, independent read of rules/safe-tests/the index taken before
  the actual evaluation reloaded them (a race, not just a staleness gap),
  and unauthenticated `POST /v1/knowledge/reindex` had no nonblocking
  admission control despite entering a blocking `flock()`; 4 LOW — a
  clause-level `sorted()` on heterogeneous YAML keys raised a raw
  `TypeError` (the sibling condition-level case was fixed in round 9), a
  corrupt/foreign SQLite database made `/answers` return an untyped 500
  instead of failing closed, `constraints.txt` completeness (every
  installed dependency having a pin) was never checked, only pin
  consistency, and this manifest's own "Tracked files by area" table plus
  a residual-risk doc still contradicted reality) — **all 10 fixed**, each
  with a regression test confirmed to fail against the pre-fix code via
  `git stash`/`git checkout` — see `git log` commit messages ("fix
  round-10 Codex#…" and the finding-specific commits above them) for the
  itemized mapping. Round 11 (2026-09-13, audited commit `f291ec0`): Codex
  **CHANGES-REQUIRED** again (12 findings independent of round 10's: 3 HIGH
  — `AnswerPatch`'s credential-shape detection covered only five known
  formats (AWS, private-key, Slack, GitHub, Anthropic), so a Stripe-style
  key or JWT (both concrete, enumerable shapes, same as the five above)
  reached the external LLM review payload unredacted — this remains an
  enumeration of KNOWN shapes only, never a claim that no opaque secret
  can pass (round 12, Codex#1, re-flagged this exact phrasing here as
  inaccurate); the public `assess()` library entry point validated only
  that a `RuleCatalogue` was non-empty, so a directly-constructed rule
  referencing a nonexistent fact evaluated to a deterministic false PASS
  instead of going through `load_rules()`'s full validation; and the
  round-10 staging-database fix still checked the staging file by
  pathname and only *then* called `os.replace()`, leaving an ABA window
  where the pathname could be swapped to an attacker database in between;
  7 MEDIUM — the `/answers` cache fingerprint was computed from a second,
  independent re-read of the rules/safe-test directories rather than the
  parsed objects actually evaluated, resource loading for `/answers` ran
  before the concurrency semaphore was acquired, the round-9/10
  `O_NOFOLLOW` SQLite `connect()` fix still re-resolved the pathname after
  opening (rather than binding to the held file descriptor), the
  directory-fd snapshot walk copied every file with no count/size/depth
  bound, CLI assessment YAML parsing had no pre-parse size/depth
  protections and did not catch `yaml.YAMLError`/`RecursionError`, the
  documented `pip install -e ".[dev]"` quickstart did not install the
  `api`/`llm` extras `scripts/preflight.py`'s own SBOM completeness check
  requires and never applied `constraints.txt`, and `preflight.py`
  invoked `generate_sbom.py` without `--check`, so every run silently
  overwrote the tracked `sbom.json`; 2 LOW — the standalone
  `validate_tree()` (used by the CLI, independent of `load_corpus()`) still
  read the live, externally-mutable knowledge root twice per file with no
  directory-fd snapshot, and this manifest's own test/component counts
  were already one commit stale at the audited commit) — **all 12 fixed**,
  each with a regression test confirmed to fail against the pre-fix code
  (via `git stash` for the code-level findings; the sbom-mutation fix was
  verified by diffing `sbom.json` before/after both the old and new
  invocations) — see `git log` commit messages ("fix round-11 Codex#…")
  for the itemized mapping. Round 12 (2026-09-13, audited commit
  `7a6f252`): Codex **CHANGES-REQUIRED** again (10 findings independent of
  round 11's: 1 HIGH — the credential-shape deny-list still missed Google
  API keys, GitLab PATs, Discord bot tokens, and database connection
  strings with embedded credentials (a Google-API-key-shaped value in
  `outbound_destinations` reached the external LLM payload unfiltered) —
  added, and `scripts/secret_scan.py`'s own separate, hand-maintained
  pattern dict (never updated when round 11 added Stripe/JWT detection to
  the runtime model) now builds from the SAME shared dict as the runtime
  model, closing that drift class outright (round 12, Codex#8, folded
  into this same fix); 7 MEDIUM — duplicate keys in one YAML mapping
  silently kept only the LAST value (a duplicated `severity` field could
  silently weaken a reviewed rule with no error), the directory-fd
  snapshot walk silently skipped FIFOs/sockets/device files in place of a
  real file (indistinguishable from an intentionally deleted rule), the
  no-follow/trusted-directory checks (`snapshot_tree()`'s root,
  `connect()`'s write path) only ever verified the directory ITSELF, never
  any ANCESTOR (an attacker able to rename one could still substitute an
  otherwise perfectly-owned directory — the first version of this fix
  rejected the project's OWN real deployment directory outright, caught
  by the full suite before it ever reached Codex, not by Codex), `/answers`
  chains had no bound on their LENGTH (always patching the newest child
  bypasses the answer-cache dedup indefinitely), `EvalMetrics.gates_pass`
  ignored three of its five computed ratios and treated an EMPTY
  evaluation as a trivial pass, `constraints.txt` was never applied to
  pip's ISOLATED build environment (where the `hatchling` build backend
  itself installs — only the main install environment was pinned), and
  preflight's own quickstart-install-line reference to fixture count was
  stale; 2 LOW — a standalone `validate_tree()`/CLI-fixture-list class of
  drift (`app/cli.py`'s `skos test` silently ran only 12 of the real 14
  fixtures and never checked a result against its own label's expected
  status), and a malformed `Origin` header (`localhost:bad`, an out-of-
  range port, or a malformed IPv6 literal) raised a raw 500 instead of the
  403 every other untrusted-origin shape gets) — **all 10 fixed**, each
  with a regression test confirmed to fail against the pre-fix code (via
  `git stash`, or by hand for the two pure documentation/behavioral-
  observation items) — see `git log` commit messages ("fix round-12
  Codex#…") for the itemized mapping. Round 13 (2026-09-13, audited
  commit `b1b899e`): Codex **CHANGES-REQUIRED** again (5 findings
  independent of round 12's: 1 HIGH — a modern OpenAI project API key
  (`sk-proj-` prefix) reached the external LLM review payload unfiltered
  — the FOURTH round in a row (9, 11, 12, 13) this same credential-shape
  gap has been found under a new format; Codex explicitly noted this
  round that widening the enumeration "cannot establish a never-accepts/
  never-sends guarantee" and suggested stopping the forwarding of raw
  free-text identifiers to the LLM entirely — discussed with the user,
  who chose to continue the enumeration for this round (added OpenAI,
  Hugging Face, npm, PyPI, and GitHub fine-grained PAT shapes) rather
  than take on the larger AttackSurface/AssessmentContext redesign now;
  3 MEDIUM — `_REINDEX_LOCK` only serialized reindex admission WITHIN one
  process, so a multi-worker Uvicorn deployment could still let a second
  worker block on (then redundantly repeat) a rebuild instead of getting
  429, the post-publish rollback only caught `OSError`/`sqlite3.Error`,
  missing `RuntimeError`-family exceptions `connect()` itself can raise
  post-swap (`ForeignDatabaseError`/`UntrustedStateDirectoryError`/
  `FTS5Unavailable`), and round 12's group-writable-ancestor trust check
  only compared GIDs, not whether the group was actually PRIVATE (no
  other account could write as it) — the fix (`_group_is_private()`)
  still had to avoid re-rejecting this project's own real deployment
  directory, which round 12's fix had already gotten wrong once; 1 LOW —
  `scripts/ingest.py`/`skos ingest` always returned exit 0, even when
  `load_corpus()` recorded an ERROR-level "could not safely snapshot"
  failure (e.g. `skos ingest README.md`, a file, not a directory)) —
  **all 5 fixed**, each with a regression test confirmed to fail against
  the pre-fix code (via `git stash`; one test needed a bounded
  thread-pool timeout rather than an unbounded call, since the pre-fix
  always-blocking flock() would otherwise hang the test suite itself
  indefinitely - confirmed by hand) — see `git log` commit messages ("fix
  round-13 Codex#…") for the itemized mapping.

  Post-round-13 hardening (commit `2c04fda`, same day, discussed with the
  user rather than found by a review round): round 13's Codex#1 was the
  FOURTH round in a row (9, 11, 12, 13) the credential-shape denylist
  missed a new vendor's key format — a denylist can only ever catch
  formats someone has already enumerated. Added a second, independent
  ALLOWLIST (`reject_non_identifier_shapes()`) for the fields that are
  identifiers/hostnames by contract (RAG sources, outbound destinations,
  tool/approval names — never `system_prompt`/`developer_prompt`, which
  hold prose): any unbroken segment over 24 characters is rejected,
  regardless of shape, since a real credential's random body is always
  one long unbroken run of characters. Verified against a completely
  fictional key shape absent from every existing pattern — rejected;
  this project's own real fixture values (hostnames, snake_case names)
  all still pass. The full structural redesign Codex originally suggested
  (never forward raw identifiers to the LLM at all) was discussed and
  deliberately deferred again — this allowlist is a narrower, faster
  change with the same generalizing property for this specific class of
  gap, not the broader one; revisit the full redesign if the denylist
  needs a sixth entry despite this. A fourteenth round re-reviewing
  everything through this commit is the next step before push.

## Tracked files by area

Per-area counts below were last verified at round 2 (commit `bcd9519`) and
have not been re-walked file-by-file for rounds 3-5; `git ls-files <area>`
is authoritative if these drift. The two numbers the automated preflight
check enforces (total tracked files, total tests) are kept current above.

| area | files | notes |
| --- | --- | --- |
| `app/` | 58 (.py) | engine, models, policy, retrieval, reviewer, llm, storage, eval, cli, main |
| `tests/` | 79 | 48 test modules + fixtures |
| `knowledge/` | 23 | 13 public KUs + `private/` skeleton (README + 2 `.gitkeep`) + category `.gitkeep`s |
| `rules/` | 13 | 7 rule YAMLs + category `.gitkeep`s |
| `safe_tests/` | 4 | 4 vetted templates |
| `scripts/` | 12 | validators, ingest/build_index, assess, evaluate, sbom, secret_scan, preflight, cross-review runner |
| `docs/` | 9 | see below |
| `reviews/` | 2 | `.gitignore` + `README.md` only — cross-review output `.md`/`.log` files are gitignored, never tracked |
| root | 11 | `README.md`, `LICENSE`, `NOTICE`, `pyproject.toml`, `.gitignore`, `.env.example`, `constraints.txt`, `sbom.json` |
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

62 components — the project's actual dependency closure (Codex#9, round 7:
walked outward from every declared root rather than listing every
installed distribution, which also included `pip` and unrelated
environment packages; Codex#9, round 8: a package reachable only
transitively through a required "runtime" root, such as `pydantic_core`
via `pydantic`, is now also marked CycloneDX scope "required", not just
one that is itself a *direct* pyproject.toml entry). Core install =
`pydantic` + `pyyaml`; the rest are `[api]`/`[llm]` extras or dev/test-only.
Zero `UNKNOWN` licences. Licences present: MIT, BSD (2/3-Clause), Apache-2.0,
PSF-2.0 — permissive — plus **`pathspec` and `certifi`, both under MPL-2.0**
(Codex finding #10, round 2, 2026-09-11, corrected round 3, 2026-09-12: an
earlier draft said "all permissive"; the first correction still missed
`certifi` and misattributed `pathspec`'s dependency chain). MPL-2.0 is
file-level (weak) copyleft, not permissive, but it does not require this
Apache-2.0 project to relicense anything — its copyleft obligations attach
only to each package's own source files. `certifi` is a transitive
dependency of `httpx`/`httpcore` (Codex#13, round 9, 2026-09-12,
correcting the previous attribution: this project's own **`dev`** extra
declares `httpx` directly, for FastAPI's `TestClient` in tests - the
pinned Anthropic SDK's actual runtime HTTP client is `httpx2`/`httpcore2`,
which use Python's native `truststore` instead of `certifi`); `pathspec`
is a transitive dependency of `mypy` (**not** `ruff`, which declares no
dependencies of its own per installed-environment metadata) — both
dev/test-only or extras, never imported by, bundled with, or distributed
as part of `app/`'s core install. None of the 62 components conflict with
Apache-2.0 distribution of this project. Full list in `sbom.json`.

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
| API assessment store in-memory (FIFO cap 5000 entries; `AssessmentInput` fields size-bounded; repeated-patch results deduped; per-lineage `/answers` chain capped at 100 revisions, round-12 Codex#5) | accepted (spec §18 localhost scope) — round-1 Codex#10, round-2 Codex#6 |
| unbounded AGGREGATE provider spend across many independent assessments/chains, without authentication or a monetary budget | accepted — round-12 Codex#5: a full auth + per-principal rate/token/budget system is a real feature, not a bug fix (same "out of scope" line drawn in round 9, Codex#6, for concurrency); only reachable at all when an operator has opted into a real, paid LLM provider — the default `llm_provider` is `none` (fully offline, zero cost) |
| integrity = SHA-256 (content, not authenticity) | accepted (signature is Pack Manager, M9-M10) — Antigravity ADV-03 |
| `Finding` A8 boundary can be bypassed via direct Python `model_copy(update=...)` | accepted — Codex#13: no code path in this app does this; Pydantic's construction bypass is a library property, not a security boundary; the actual boundary is the LLM's JSON output going through `model_validate_json` + schema `extra="forbid"`, which cannot be bypassed this way |
| `SafeTest._FORBIDDEN` regex deny-list would be bypassable by a determined author if a future execution engine is added | accepted / architectural note — Antigravity ADV-04: no execution engine exists yet (safe tests are non-executable templates only); M9-M10 must use sandboxed execution (gVisor/bubblewrap), not regex filtering, when one is added |
| fixtures artificial; §24 metrics = mechanism check | accepted (stated in README) |
| KU `status: reviewed` = "summary of a reviewed public standard" | accepted (human final pass recommended) |
| `retrieval/hybrid.py` is a thin wrapper | accepted (embeddings/reranker future) |
| JA-R02 cross-language retrieval | accepted (out of MVP scope) |
| CLI uses argparse, not Typer (spec §5) | accepted, documented |
| Pack Manager (M9-M10) not in repo | out of scope; ZIP-import attack surface is future work |

## Cross-AI review — status

See the "Cross-AI review" bullet near the top of this file for the
itemized round-by-round history (rounds 1-9 so far, each CHANGES-REQUIRED
then fully fixed) - it is the single, current source of truth for round
counts and findings-per-round numbers. This section used to duplicate that
narrative independently and drifted out of sync with it (Codex#10, round
10, 2026-09-13); a count or round-history claim is now written in exactly
one place in this file.

Outstanding before push:
- The next cross-AI review round, per the same AI_RULES requirement
  ("修正した上で再レビューを受けること") applied again.
- Human confirmation: no real customer / private material in any commit.
