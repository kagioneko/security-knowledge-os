# Publication Manifest — Security Knowledge OS v0.1.0

Snapshot of what the first public push contains. Generated for the pre-publication
review; regenerate with `git ls-files` after any change.

- Commit: `023ace3` (round-30 fixes: raw-value leaks in error/log paths, **not yet pushed**)
- History: rewritten once on 2026-09-20, before first publication, to normalise author/committer identity to the
  GitHub no-reply address (one commit message also scrubbed of a local account name). Every commit's tree is
  identical before and after, so the reviewed content is the published content; commit hashes cited in the
  review records below are the **pre-rewrite** ones - see `docs/history-rewrite-map.md` for old -> new.
- Licence: **Apache-2.0** (`LICENSE`, `NOTICE`, `pyproject.toml`)
- Tracked files: **217**
- Tests: **761** items (760 pass, 1 skip = JA-R02)
- `scripts/preflight.py`: **PASS** (now also verifies the documented
  quickstart `pip install -e` command installs every declared extra,
  pins `constraints.txt`, AND passes `--build-constraint constraints.txt`
  so pip's isolated build environment is pinned too, round 11 Codex#9 /
  round 12 Codex#7; and that the tracked `sbom.json` matches the current
  environment, ignoring only its timestamp, without preflight itself
  rewriting that tracked file to check it, round 11 Codex#12)
- Cross-AI review: Codex (code audit) + Antigravity (adversarial design
  audit), **twenty-eight rounds**, 2026-09-11 -- 2026-09-20. Rounds 1-2
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
  needs a sixth entry despite this.

  Round 14 (2026-09-13, audited commit `77a78bc`): Codex
  **CHANGES-REQUIRED** again (6 findings independent of round 13's: 2 HIGH
  — the round-13 identifier ALLOWLIST assumed every credential is one
  long unbroken segment, which is false for UUID-form tokens (all hyphen-
  separated segments individually short enough to pass); this was the
  FIFTH round in a row (9, 11, 12, 13, 14) a content filter over the raw
  value was defeated by a differently-shaped real secret, so — discussed
  with the user — the structural fix Codex had suggested twice was
  finally taken: `build_payload()` now anonymizes every identifier-shaped
  field (RAG sources, outbound destinations, tool names, approval keys)
  into stable local labels before ever serializing the LLM request,
  consistently across `assessment_context`/`attack_surface`, so no value
  these fields could ever hold can reach the provider through them at
  all; and `scripts/run_cross_review.sh` runs the Codex reviewer with
  `CODEX_SANDBOX=danger-full-access` (bwrap fails on this host), giving a
  reviewer that reads a prompt-injected file real OS-level permission to
  act on it instead of just auditing — discussed with the user, the full
  container/VM fix was deliberately deferred (it changes the shared
  review pipeline across every project on the host) in favor of a
  `ulimit`-based CPU-time/max-file-size mitigation needing no new
  infrastructure; 3 MEDIUM — `validate_safe_test()` never scanned
  `preconditions`, `expected_secure_behavior`, or `failure_condition`,
  and its credential/destination detection was its own stale hand-rolled
  list rather than the shared, maintained one, the snapshot per-file size
  limit was checked once before copying rather than enforced DURING the
  chunked copy (a fault-injected repro copied 5 MB+ from a 1-byte
  source), and `submit_answers()` acquired the concurrency semaphore
  BEFORE the per-request dedup lock, so a duplicate request waiting on
  that lock held a scarce admission slot it was not using, able to starve
  an unrelated request; 1 LOW — the SBOM's dependency-closure walk fixed
  `extra` to `""` for every requirement, discarding which extras a parent
  requirement had actually activated on its own dependency, hiding
  `filelock` (genuinely installed, reachable only through `pip-audit`'s
  own `CacheControl[filecache]` requirement) from the "complete" SBOM) —
  **all 6 addressed** (5 fixed outright, 1 mitigated with the container/
  VM alternative explicitly deferred by request), each with a regression
  test confirmed to fail against the pre-fix code via `git stash` (one
  needed a bounded thread-pool timeout rather than an unbounded call,
  since the pre-fix always-blocking flock() would otherwise hang the
  test suite itself — confirmed by hand) — see `git log` commit messages
  ("fix round-14 Codex#…") for the itemized mapping.

  Round 15 (2026-09-14, audited commit `557f036`, after one usage-limit
  interruption and a scheduled automatic retry): Codex **CHANGES-REQUIRED**
  again (9 findings independent of round 14's: 2 HIGH — the round-12/13
  ancestor-directory trust check started with `path.resolve(strict=False)`,
  which silently follows every symlink before any check runs, so a
  world-writable `exposed/` containing `exposed/link -> elsewhere/` was
  invisible to the check entirely (it only ever inspected `elsewhere`'s
  own ancestors); and the review-runner's `danger-full-access` sandbox
  risk, re-confirmed still present (round-14's accepted `ulimit`
  mitigation, container/VM fix still deliberately deferred, unchanged);
  6 MEDIUM — `connect()`/`reindex_atomic()`'s "only chmod what we
  created" fix (round 8) was itself still check-then-act
  (`.exists()` then `.mkdir(exist_ok=True)`, which silently accepts a
  pre-existing symlink), so `os.chmod()` could re-permission an
  attacker's own directory reached through a raced symlink — reproduced
  with Codex's own exploit script; `FTS5Unavailable` (a RuntimeError
  subclass) escaped both pre-swap reindex exception handlers instead of
  the typed `POLICY_BLOCKED` contract; the safe-test destination
  validator truncated a URL authority at its first `:`, treating
  userinfo as the host (`https://localhost:443@attacker.com/x` checked
  only "localhost") and never recognized a bare IPv6 literal at all;
  `AnswerPatch`'s "never accepts a raw secret" guarantee does not extend
  to an opaque, unrecognized-shape value in free-text fields — already
  an intentional, tested limitation, clarified in documentation rather
  than re-scoped; the `/answers` singleflight lock's blocking
  `threading.Lock.acquire()` had no timeout, so enough duplicate
  requests could exhaust FastAPI's shared sync-route worker pool; and
  both cross-review scripts reported success (exit 0, a "実行済み"
  HANDOFF.md marker) even when the reviewer or preflight actually
  failed or produced no verdict; 1 LOW — dependency versions are pinned
  but not hash-authenticated, re-confirmed as the same already-accepted
  MVP-scope trade-off `constraints.txt` already documented) — **all 9
  addressed** (7 fixed outright with regression tests confirmed to fail
  against the pre-fix code via `git stash`/`git checkout`, 2 documented
  as already-accepted unchanged risk) — see `git log` commit messages
  ("fix round-15 Codex#…") for the itemized mapping. Notably, **finding
  #1 from rounds 9/11/12/13/14 (credential-shaped values reaching the
  LLM payload) did NOT recur** — the round-14 structural anonymization
  fix held under this round's independent audit, confirmed explicitly in
  finding #5's own text ("the LLM-review anonymization prevents these
  values from being structurally copied into its review payload").
  While fixing the review-script honesty finding (#8), an earlier
  attempt to test it assumed `timeout 0` fails a command instantly; GNU
  `timeout` actually treats `0` as "no timeout", so a real Codex
  invocation ran (and consumed real usage) before being caught and
  killed ~15s in — subsequent testing used a fake `codex`/`agy` shim in
  a throwaway sandbox instead.

  Round 16 (2026-09-14, audited commit `06e3007`): Codex
  **CHANGES-REQUIRED** again (6 findings), and — for the first time this
  project ran Antigravity alongside Codex in the SAME round since round
  5 — Antigravity **independently found the same top two findings**
  (`SKOS-ADV-16`/`SKOS-ADV-17`), plus two additional LOW/Nit items of its
  own: 1 HIGH — `_untrusted_directory_stat_reason()` checked only CURRENT
  write bits (group/other), never OWNERSHIP, so a directory owned by a
  different, untrusted account but currently mode 0755 (no write bit at
  all) passed outright even though that owner can chmod it writable or
  replace its contents at any later time; separately, a symlink ENTRY's
  own owner was never checked before following it, so an attacker's
  symlink planted inside a shared sticky directory like `/tmp` (whose
  sticky bit stops renaming/deleting an entry you don't own, but never
  stops CREATING a new one) was followed unconditionally; 2 MEDIUM —
  `_try_parse()`/`run_llm_review()` assumed a pluggable `LLMClient`'s
  `complete()` always returns a `str` and never raises anything but
  `LLMError`, so a misbehaving custom adapter returning `None` or
  raising an unexpected exception escaped as a raw AttributeError/500
  instead of the documented `LLM_PARSE_ERROR` fail-closed contract; and
  the round-15 `/answers` lock timeout bounded each INDIVIDUAL wait but
  not how MANY duplicates could queue on one key, so a slow first
  assessment plus a worker-pool's worth of duplicates could still stall
  `/health` for repeated 30-second intervals; 1 MEDIUM (both
  reviewers, independently) — the round-15 `_has_verdict()` fix matched
  `PASS`/`CHANGES-REQUIRED` UNANCHORED anywhere in the log, so a
  reviewer that crashed after merely printing "preflight: PASS" (or
  quoting `PUBLICATION_MANIFEST.md`'s own round-history prose, which
  contains those words throughout) would still clear the publication
  gate; plus Antigravity's own 2 LOW/Nit — `PolicyBlocked` (a
  defence-in-depth check in `Bm25Retriever`) inherits from plain
  `Exception`, not `PolicyStop`, so it escaped `build_report()` as a raw
  HTTP 500 instead of a structured `POLICY_BLOCKED` report; and a TOCTOU
  concern in `load_corpus()`'s re-enumeration, investigated and found to
  describe a two-step `validate_tree()`-then-`iter_knowledge_files()`
  sequence that does not match the current single-pass-over-snapshot
  implementation (closed by round 10's `snapshot_tree()` design) — no
  code change made for this one, noted as already mitigated. Codex's
  remaining 2 LOW findings (`AnswerPatch` opaque-secret retention,
  dependency hash-pinning) were re-confirmations of round-15's
  already-accepted, already-documented trade-offs. **5 of 9 distinct
  findings fixed outright** with regression tests confirmed to fail
  against the pre-fix code via `git stash`/`git checkout`, the rest
  re-confirmed-accepted or investigated-and-not-applicable — see
  `git log` commit messages ("fix round-16 Codex#…" / "fix round-16
  NIT-ADV-01") for the itemized mapping. A stray `rm -f` while testing
  finding #4's fix accidentally deleted the round's own real Codex
  review transcript (`reviews/` is gitignored, unrecoverable) - the
  findings had already been read and recorded before the file was lost,
  so nothing substantive is missing, only the raw transcript.

  Round 17 (2026-09-14, audited commit `2dc6bd1`): Codex **CHANGES-
  REQUIRED** again (9 findings: 6 new + 3 re-confirmations of already-
  accepted round-15/16 risks), and Antigravity independently found 4 of
  the same 6 new ones (`SKOS-ADV-18` through `-21`) plus no new items of
  its own this round: 2 MEDIUM — `_MaxBodySizeMiddleware` retained every
  individual ASGI `receive()` message in a list, one per frame -
  `_MAX_BODY_BYTES` bounded total bytes but not the NUMBER of frames, so
  a body of at most 1 MB split into a million one-byte frames stayed
  within the byte cap while the list grew to a million dict objects
  (hundreds of MB for a "1 MB" request); and the round-16 per-key
  `/answers` waiter cap bounded worst-case thread occupancy for ONE
  assessment ID, but nothing bounded how many DISTINCT keys could each
  hit that cap at once (four slow assessments × ten callers = 40
  threads, a typical worker pool's entirety); 2 MEDIUM (Antigravity
  independently, `SKOS-ADV-18`/`-20`) — `.mkdir(parents=True,
  exist_ok=True)` resolved and created directories through an EXISTING,
  pre-planted symlink ancestor BEFORE any trust check ran (fail-closed
  on the eventual WRITE, not on the side effect of having created a
  directory through the attacker's symlink at all - reproduced with
  Codex's own exploit shape); and the round-16 verdict-gate fix only
  ever asked "does a verdict line exist", never WHICH verdict, so a
  completed `CHANGES-REQUIRED` review satisfied it exactly like `PASS`
  does and the scheduled wrapper labeled that run "成功"; 1 LOW
  (Antigravity independently, `SKOS-ADV-19`) — `urlsplit(...).hostname`
  raises `ValueError` for a malformed bracketed IPv6 authority (e.g.
  `http://[:::]`), uncaught, surfacing as an untyped 500; 1 LOW
  (Antigravity independently, `SKOS-ADV-21`) — `AssessmentInput.name`
  was the only free-text field on that model without a
  `reject_credential_shapes` validator. **All 6 new findings fixed**
  with regression tests confirmed to fail against the pre-fix code via
  `git stash`/`git checkout`; the remaining 3 (danger-full-access,
  `AnswerPatch` opaque secrets, dependency hash-pinning) were
  re-confirmations of already-accepted round-15/16 trade-offs, no new
  action — see `git log` commit messages ("fix round-17 Codex#…") for
  the itemized mapping. While investigating the symlink-mkdir finding,
  found and fixed a latent test-isolation bug in two EXISTING round-16
  tests: forging `os.geteuid()` globally also made `tmp_path`'s own real
  ancestors (e.g. `/tmp/pytest-of-<user>`, owned by the test's real uid,
  not root) look foreign-owned to the same ownership check, which
  rejected the chain THERE first - both tests' assertions passed anyway,
  but only because the intended target's path string happened to be a
  substring of the unrelated rejection's generic trailing clause, not
  because the intended code path fired; rewritten to fake only the
  specific target's own stat/lstat result instead.

  Round 18 (2026-09-14, audited commit `5ecaa36`): Codex **CHANGES-
  REQUIRED** again (6 findings: 4 new + 2 re-confirmations of already-
  accepted round-14/15 risk), and Antigravity independently found all 3
  of the actionable new ones (`SKOS-ADV-22`/`-23`/`-24`): 1 MEDIUM (both
  reviewers) — the `db-connection-string` credential-shape pattern only
  matched a lowercase URI scheme, but a scheme is case-insensitive per
  RFC 3986, so an uppercase-scheme connection string (otherwise a
  perfectly valid, credential-bearing URI) evaded both the schema
  validators and `scripts/secret_scan.py` (which imports the same shared
  pattern dict);
  1 LOW (both reviewers) — `MemoryInput.scope`, `ToolInput.permissions`,
  `CredentialInput.storage`, and `CredentialInput.exposed_to_model` were
  the only externally-supplied string fields on `AssessmentInput` still
  missing `reject_credential_shapes`, the same class of gap fixed for
  `name` itself one round earlier; 1 LOW (both reviewers) — round 6's
  fix for `ValidationError` hid the REJECTED VALUE but not the rejected
  KEY: for an `extra_forbidden` violation, pydantic's own `loc` IS the
  untrusted extra property name an attacker-influenced LLM response
  supplied, and it flowed into the repair prompt and the public
  `LLM-OBS-00000` finding verbatim; 1 LOW (Codex only) — README.md,
  REVIEW_PACKAGE.md, and docs/acceptance-criteria.md each separately
  stated the fixture count (claimed 12, actually 14) and/or public-KU
  count (claimed 13, actually 14) in prose, drifted from
  `PUBLICATION_MANIFEST.md`'s own already-correct counts with nothing
  checking them. **All 4 new findings fixed**, each with a regression
  test confirmed to fail against the pre-fix code via `git stash`/`git
  checkout`; the stale-count fix also added a new preflight check
  (`_publication_docs_counts_match_reality()`) so this specific class of
  drift cannot recur silently again — verified it actually catches the
  drift by reverting the doc fixes and confirming all 7 stale
  occurrences are reported, then reapplying. The remaining 2 (danger-
  full-access, dependency hash-pinning) were re-confirmations of
  already-accepted trade-offs — see `git log` commit messages ("fix
  round-18 Codex#…") for the itemized mapping.

  Round 19 (2026-09-14, audited commit `5cdabb0`): Codex **CHANGES-
  REQUIRED** again (3 findings, all new): 1 HIGH — `reindex_atomic()`
  copies/replaces only db_path's MAIN sqlite file; a `-wal`/`-shm`
  sidecar left by a prior writer (journal_mode is persisted INSIDE the
  database file itself, so any writer with file access could leave one
  behind) survives a reindex untouched, and `verify_chunk_hashes()`
  alone can't catch it — a stale-but-internally-consistent revision is
  still a real, valid index by that check's own definition, just not
  the one just published; 2 LOW — `_walk_no_follow()`'s snapshot walk
  materialized the full directory listing (`list(os.scandir(...))`)
  before `_MAX_SNAPSHOT_FILES` had any chance to fire, and only FILES
  (never directories) consumed that budget, so a wide fan-out of empty
  subdirectories evaded the count limit entirely; and
  `_is_local_origin()`'s port comparison read the un-guarded
  `request.url.port`, raising a raw ValueError (-> generic 500 instead
  of the established 403) for an out-of-range Host port — while
  verifying that fix, testing also found an adjacent crash one property
  earlier (`request.url.path`, for an invalid bracketed-IPv6 Host),
  fixed in the same commit as the same class of bug. **All 3 fixed**,
  each with a regression test confirmed to fail against the pre-fix
  code via `git stash` — the WAL fix's test simulates the mismatch by
  monkeypatching `ChunkRepository.knowledge_revision` to return the old
  revision on its second in-process call (the documented post-swap
  check site), deliberately avoiding real-WAL-internals trickery; the
  snapshot fix adds both an oversized-single-directory and an
  empty-directory-fanout test; the Host fix covers both the numeric
  out-of-range port Codex reported and the bracketed-IPv6 case found
  alongside it (and documents, via a third value deliberately NOT
  included as a repro, why `Host: localhost:bad` is not exploitable —
  Starlette's own `_HOST_RE` rejects a non-numeric port before either
  code path is ever reached). See `git log` commit messages ("fix
  round-19 Codex#…") for the itemized mapping.

  Round 20 (2026-09-15, audited commit `386bf8b`): Codex **CHANGES-
  REQUIRED** again (4 findings, all new) and Antigravity independently
  found all 4 of them (`SKOS-ADV-25`..`-28`) — the strongest independent-
  match round yet: 2 MEDIUM — the round-19 `journal_mode = DELETE` fix
  itself ran BEFORE the foreign-database (`application_id`) check, so
  `connect()` mutated (checkpointed, sidecar-deleted) ANY database it
  opened in write mode, including one about to be rejected as foreign a
  few lines later, and a LOCKED foreign database made this worse by
  raising `sqlite3.OperationalError` instead of `ForeignDatabaseError`
  entirely; and `_is_local_origin()` verified Origin's hostname was SOME
  allowed loopback alias but never compared it against the hostname the
  request actually arrived on, letting `localhost`/`127.0.0.1`/`::1`
  silently substitute for each other — a page on IPv6 loopback could
  CSRF this service on IPv4 loopback at the same port. 2 LOW — the
  snapshot walk's stability RESCAN (unlike the round-19-fixed first
  scan) still built its full `after_names` set before comparing it,
  letting a concurrent writer force unbounded allocation there instead;
  and `untrusted_directory_reason()`'s `Path.resolve(strict=False)`
  raises `RuntimeError` (not `OSError`) for a self-referential symlink
  loop, escaping every caller's `OSError`-only handling as a raw 500.
  **All 4 fixed**, each with a regression test confirmed to fail against
  the pre-fix code via `git stash`: the foreign-database fix's test
  creates a real WAL-mode foreign database and commits without closing
  it, naturally reproducing the lock contention that turned the wrong-
  exception-type half of the bug into an observable pre-fix failure too;
  the origin-gate fix's test sends `Origin: http://[::1]:80` against
  `Host: 127.0.0.1:80`; the rescan fix's test monkeypatches `os.scandir`
  to flood the second scan and counts how many entries are actually
  consumed before aborting (10,000 pre-fix, 1 post-fix); the symlink-loop
  fix's test creates a root that is a symlink to itself. See `git log`
  commit messages ("fix round-20 Codex#…") for the itemized mapping.

  Round 21 (2026-09-15, audited commit `31d5fed`): Codex **CHANGES-
  REQUIRED** again (6 findings, all new) and Antigravity independently
  found 4 of them (`SKOS-ADV-29`..`-32`; the other 2 are LOW/Nit,
  Codex-only) — 3 MEDIUM (Antigravity rated the first as HIGH; treated
  as the higher severity here): chunk_content_hash() NUL-separated its
  fields, which is not injective - an embedded NUL inside one field's
  own content (YAML permits it in a quoted scalar) is indistinguishable
  from the separator between two DIFFERENT fields, so a local attacker
  with write access to the index file could rebind a CONFIDENTIAL
  chunk's classification to `public` while shifting the excess bytes
  into an adjacent field, producing the EXACT SAME hash and a complete,
  silent bypass of the classification gate; the snapshot walk's
  per-file before/after check and names-only rescan together still
  missed a file mutated in place AFTER being copied while a sibling (or
  a whole sibling subtree) was still being processed, producing a
  composite snapshot state that never existed on the source tree at any
  single instant; and connect() treated "no tables/views" as sufficient
  proof a database was safe to claim as fresh, without checking whether
  its application_id was already a foreign, nonzero value stamped by
  some OTHER application before it ever created a table. 3 LOW — a
  non-text (BLOB) stored `knowledge_revision` value could crash
  `reindex_atomic()` with a raw Pydantic ValidationError, confirmed by
  this fix's own regression test to happen AFTER a successful publish
  (misrepresenting success as failure); round 20's connection-closing
  fix only covered setup steps from the has_existing_content check
  onward, leaving the identity-verification and FTS5-probe steps just
  above it still able to leak the connection on an unanticipated
  failure; and a repair-call-raises-LLMError shape (distinct from both
  already-covered repair-call cases) lacked test coverage, closed with
  a test alone since the existing shared code path already handled it
  correctly. **All 6 addressed**, each with a regression test (the
  Codex#6 coverage gap needed a test only, no source change; the other
  5 confirmed failing against the pre-fix code via `git stash` and
  passing post-fix). Changing the chunk-hash encoding invalidates any
  previously-built index (no migration path; this project has never
  shipped a released index, so only a local `var/index.sqlite` dev
  artifact needed rebuilding). See `git log` commit messages ("fix
  round-21 Codex#…") for the itemized mapping.

  **Rounds 22-28 (2026-09-19 -- 2026-09-20, Codex only; Antigravity's
  round-22 PASS on `1437d88` stands).** Round 22 (Codex, CHANGES-REQUIRED,
  3 MEDIUM): rejected credentials echoed in HTTP 422 bodies / CLI stderr;
  schema-derived SQLite column names executed as SQL in the integrity
  check; snapshot mixing generations across sibling subdirectories (closed
  by a whole-tree re-verification after the copy). Round 23 (5 findings,
  3 MEDIUM 2 LOW): secret-shaped KEYS leaking through error `loc`, YAML
  syntax-error snippets, unbounded CLI read, untyped shorthand-clause
  error, and the state-directory creation race (`mkdirat`-relative walk);
  the coordinated-writer ABA race against the snapshot re-verification was
  **accepted and documented** (`docs/threat-model.md`). Round 24 (1
  MEDIUM): a raced-in ordinary directory bypassed the no-follow creation
  guard (now judged by `fstat` on the descriptor). Round 25 (1 MEDIUM, 1
  LOW): observed directories are pinned with `O_NOFOLLOW` plus an inode
  check; `skos report` read is bounded. Round 26 (3 MEDIUM, 2 LOW): the
  final state directory is judged by descriptor too, a BLOB
  `sqlite_master.sql` fails closed, the review script accepts only a
  verdict that is the transcript's final line and refuses a dirty tree or
  one that changed during the review, and this manifest is now checked by
  preflight to name the latest code commit and mention the latest round.
  Round 27 (1 MEDIUM, 1 LOW): `POST /v1/knowledge/validate` reflected the
  submitted `source` and malformed risk ids (now a fixed label / an index),
  and CLI wrappers enumerated a symlinked knowledge root before the
  snapshot check rejected it (`iter_knowledge_files()` now returns nothing
  for one). Round 28 (2 MEDIUM, 1 LOW, all in `app/storage/integrity.py`):
  integrity failure reasons no longer carry database cell values (row
  ordinals, counts and stored types only), `chunks_fts` must match the
  application's exact definition (one `search_text` column, contentless,
  trigram tokenizer, no extra `chunks_fts_*` table), and the shadow digest
  uses a type-tagged, length-prefixed, row-counted encoding (**an index
  built before this must be rebuilt**). Every fix has a regression test
  that fails against the pre-fix code.

  **Review scope (2026-09-20, agreed with the owner after round 28).**
  Findings kept arriving that require write access to the state directory,
  the index or the rule trees - locations `docs/threat-model.md` now states
  (section "Deployment assumptions") are inside the trust boundary, writable
  only by the service's OS user, where the writer can replace a rule directly
  and a hash they can recompute is no defence. From the next round on, both
  reviewer prompts (`scripts/run_cross_review.sh`) ask for findings that are
  exploitable WITHOUT that access (untrusted input, or another local account
  lacking it) and to list the write-access ones once as out of scope; a
  crash, fail-open behaviour or leak in the handling of a corrupt file stays
  in scope. This narrows what the remaining rounds can conclude and is
  recorded here so it cannot be mistaken for the earlier, unscoped rounds.
  The twenty-ninth round (scoped, 2026-09-20; Codex **PASS-with-nits**,
  Antigravity **PASS**, both on `720df3e`) left one LOW nit - `risk_ids` was
  unbounded, so `POST /v1/knowledge/validate` could return ~890 KB for an
  ~18 KB document - fixed with a 200-entry bound (`round-29`) and one further
  scoped Codex run over the fixed commit. That re-run (`ea33755`, same code
  plus the one-line bound) came back **CHANGES-REQUIRED** with different
  findings - the two scoped runs disagree, i.e. a single Codex verdict is not
  a stable signal: untrusted text could forge or hide the human-readable
  verdict via terminal escape sequences in `render_text()` (now escaped),
  a corrupt `chunks` table with a TEXT `rowid` column could smuggle a cell
  into an integrity diagnostic (ordinals no longer come from the database,
  `chunks`/`meta` schemas are checked, the stored chunk count is not echoed),
  and validation errors were an unbounded amplifier (capped at 100 with
  totals). Regression tests fail against the pre-fix code (`round-29`
  re-review). The PASS verdicts on `720df3e` are for the scoped review;
  rounds 22-28, before the scope was stated, each ended CHANGES-REQUIRED.

  **Round 30** (scoped, 2026-09-25, audited commit `bd3d956` - a README-only
  change adding an English-first note and a collapsed Japanese summary for
  human reviewers; no code changed since round-29's re-review): Codex
  **CHANGES-REQUIRED**, 3 findings independent of round 29's, all in
  error/log paths rather than the reviewed README change itself - 2 MEDIUM
  (`_current_revision()` checked type but not shape, so a forged/corrupted
  `knowledge_revision` string flowed into `ReindexReport.old_revision` and
  back out through the HTTP 422 body and logs, now rejected unless it is a
  64-hex-digit sha256 digest; several rule/knowledge-validation error paths
  echoed the rejected value itself - `raw!r`, `sorted(raw)`, the malformed
  `risk_id`, a malformed URL authority that can carry userinfo credentials -
  and three `RuleLoadError` sites kept the original `ValidationError` as
  `__cause__` via `from exc`, whose own str/repr embeds the rejected input
  regardless of the outer message's sanitization; switched to `from None`
  and to position/count/type-only diagnostics, matching the pattern
  `validate_markdown()`'s risk_ids loop already used since round 27), 1 LOW
  (the `chunk_count` integer conversion caught `TypeError`/`ValueError` but
  not `OverflowError` - a non-finite REAL in a corrupted `meta` table
  escaped `build_report()` instead of producing the documented
  `POLICY_BLOCKED` result). All 3 fixed in `023ace3`; 760 passed / 1 skipped,
  ruff and strict mypy clean. Re-review not yet run.

## Tracked files by area

Per-area counts below were last verified at round 2 (commit `bcd9519`) and
have not been re-walked file-by-file for rounds 3-5; `git ls-files <area>`
is authoritative if these drift. The two numbers the automated preflight
check enforces (total tracked files, total tests) are kept current above.

| area | files | notes |
| --- | --- | --- |
| `app/` | 59 (.py) | engine, models, policy, retrieval, reviewer, llm, storage, eval, cli, main |
| `tests/` | 82 | 51 test modules + fixtures |
| `knowledge/` | 24 | 14 public KUs + `private/` skeleton (README + 2 `.gitkeep`) + category `.gitkeep`s |
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

## Public Knowledge Units (14)

All `classification: public`, `status: reviewed`. 13 are `derivation: summary`
(original prose, no verbatim third-party text, citing a published standard).
KU-0014 is `derivation: original` / `source_type: incident` — a first-party
write-up of a vulnerability class found by this project's own pre-publication
cross-AI review (rounds 9-14), not sourced from any external standard. Full
list + per-unit sources in `docs/knowledge-corpus.md`; licence analysis in
`docs/attribution.md`.

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
| KU-0014 | incident | original (this project's own cross-AI review, rounds 9-14) |

Source licences: OWASP CC-BY-SA-4.0 · MITRE ATLAS Terms of Use · NIST public
domain · KU-0014 original (no external licence applies). No content in the
repo is under terms incompatible with Apache-2.0 redistribution.

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

63 components — the project's actual dependency closure (Codex#9, round 7:
walked outward from every declared root rather than listing every
installed distribution, which also included `pip` and unrelated
environment packages; Codex#9, round 8: a package reachable only
transitively through a required "runtime" root, such as `pydantic_core`
via `pydantic`, is now also marked CycloneDX scope "required", not just
one that is itself a *direct* pyproject.toml entry; Codex#6, round 14:
`filelock` (MIT), reachable only through `pip-audit`'s own
`CacheControl[filecache]` requirement - fixing `extra` to `""` for every
requirement, round 9's own fix, had discarded which extras a PARENT
requirement actually activated on its dependency, hiding this one).
Core install =
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
as part of `app/`'s core install. None of the 63 components conflict with
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
| `scripts/run_cross_review.sh` runs the Codex reviewer with `CODEX_SANDBOX=danger-full-access` (bwrap fails on this host's kernel config) - a prompt-injection string in any reviewed file could induce the reviewer to run arbitrary commands or write/exfiltrate outside this repo, not just audit it | accepted, mitigated — round-14 Codex#2, re-confirmed unchanged round-15 Codex#7: a full fix (disposable container/VM, read-only bind mount, no Vault/socket access, restricted network) was discussed with the user and deliberately deferred - it changes how the shared Codex review pipeline runs across every project on the host, needing the host's actual container/VM capabilities checked first. Applied instead: `ulimit`-based CPU-time and max-written-file-size caps scoped to the reviewer process alone (deliberately not a process-count limit, which is enforced per-UID system-wide on Linux and could starve unrelated services running as the same account) |
| `AnswerPatch` free-text fields accept an opaque, unrecognized-shape value (no known credential pattern matches it) | accepted, documented — round-15 Codex#5: already an intentional, tested limitation (round-7); never reaches the external LLM regardless (round-14 structural anonymization); retained in the in-memory store for the entry's lifetime, same accepted unauthenticated-localhost scope as the store itself |
| `constraints.txt` pins exact versions but not package hashes - the same version string could still come from an unintended index or a replaced artifact | accepted (documented in `constraints.txt` itself, out of scope for this MVP release process) — round-15 Codex#9 re-confirmed the same trade-off, no new action; round-18 Codex#6 re-confirmed again, still unchanged |
| `scripts/run_cross_review.sh` and `_scheduled_cross_review.sh` (mitigated round-15) re-confirmed by Codex round-16 with no change requested | accepted, unchanged — round-16 Codex#7 (HIGH) is the same `danger-full-access` risk above, re-confirmed at that severity; no new mitigation was requested or applied this round; round-18 Codex#1 re-confirmed again, still unchanged |
| Antigravity NIT-ADV-02: possible TOCTOU in `load_corpus()`'s file re-enumeration (a local actor replacing a file with a symlink between `validate_tree()` completing and `iter_knowledge_files()` completing) | investigated, not applicable — round-16: the described two-step sequence does not match `load_corpus()`'s current implementation, which snapshots the ENTIRE knowledge root via a directory-fd no-follow walk (`app/ingestion/snapshot.py`, round 10) BEFORE any validation or file read, then validates and reads each file exactly once from that private, externally-immutable snapshot copy - there is no separate `validate_tree()`-then-`iter_knowledge_files()` sequence on the live tree for a local actor to race. No code change made; revisit if a future refactor reintroduces a two-pass read. |

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
