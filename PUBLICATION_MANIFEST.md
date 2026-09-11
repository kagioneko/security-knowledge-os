# Publication Manifest — Security Knowledge OS v0.1.0

Snapshot of what the first public push contains. Generated for the pre-publication
review; regenerate with `git ls-files` after any change.

- Commit: `8535cb6` (M8.2 — cross-review findings addressed, **not yet pushed**)
- Licence: **Apache-2.0** (`LICENSE`, `NOTICE`, `pyproject.toml`)
- Tracked files: **198**
- Tests: **355** items (354 pass, 1 skip = JA-R02)
- `scripts/preflight.py`: **PASS**
- Cross-AI review: Codex (code audit) + Antigravity (adversarial design audit),
  2026-09-11, both initially **CHANGES-REQUIRED** — all 19 findings addressed
  (16 fixed with regression tests, 3 accepted/documented). See `HANDOFF.md` and
  `REVIEW_CHECKLIST.md` sign-off table.

## Tracked files by area

| area | files | notes |
| --- | --- | --- |
| `app/` | 56 (.py) | engine, models, policy, retrieval, reviewer, llm, storage, eval, cli, main |
| `tests/` | 69 | 39 test modules + fixtures |
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

- Assessment fixtures: **13** in `tests/fixtures/assessments/{safe,vulnerable,unknown}/`
  (4 safe, 4 vulnerable, 5 unknown — U-005 added for the ADV-01 regression).
  Labels drive `scripts/evaluate.py`.
- Knowledge/validator fixtures: 16 `.md` under `tests/fixtures/` (valid, invalid,
  secret-in-repo, corpus, corpus_alt) — test data only, `source_license: "test
  fixture - not for distribution"`.

## Dependencies (`sbom.json`)

29 components — every distribution actually installed in the project `.venv`
(Codex finding #12 fixed the previous hand-maintained allowlist, which
silently omitted transitive dependencies). Core install = `pydantic` +
`pyyaml`; the rest are `[api]`/`[llm]` extras or dev/test-only. All permissive
(MIT / BSD / Apache-2.0 / MPL-2.0 / PSF-2.0); zero `UNKNOWN`; none conflict
with Apache-2.0 for a separate work. Full list in `sbom.json`.

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
| API assessment store in-memory (now size-bounded, FIFO cap 5000) | accepted (spec §18 localhost scope) — Codex#10 |
| integrity = SHA-256 (content, not authenticity) | accepted (signature is Pack Manager, M9-M10) — Antigravity ADV-03 |
| `Finding` A8 boundary can be bypassed via direct Python `model_copy(update=...)` | accepted — Codex#13: no code path in this app does this; Pydantic's construction bypass is a library property, not a security boundary; the actual boundary is the LLM's JSON output going through `model_validate_json` + schema `extra="forbid"`, which cannot be bypassed this way |
| `SafeTest._FORBIDDEN` regex deny-list would be bypassable by a determined author if a future execution engine is added | accepted / architectural note — Antigravity ADV-04: no execution engine exists yet (safe tests are non-executable templates only); M9-M10 must use sandboxed execution (gVisor/bubblewrap), not regex filtering, when one is added |
| fixtures artificial; §24 metrics = mechanism check | accepted (stated in README) |
| KU `status: reviewed` = "summary of a reviewed public standard" | accepted (human final pass recommended) |
| `retrieval/hybrid.py` is a thin wrapper | accepted (embeddings/reranker future) |
| JA-R02 cross-language retrieval | accepted (out of MVP scope) |
| CLI uses argparse, not Typer (spec §5) | accepted, documented |
| Pack Manager (M9-M10) not in repo | out of scope; ZIP-import attack surface is future work |

## Cross-AI review — closed

1. **Cross-AI review** (Codex code audit + Antigravity adversarial design
   audit) per `AI_RULES.md` — **done**, 2026-09-11, recorded in `HANDOFF.md`.
   Both initial verdicts: **CHANGES-REQUIRED**.
2. **Findings addressed**: 16 of 19 fixed (with regression tests confirmed to
   fail against the pre-fix code where practical), 3 accepted/documented above.
   See `REVIEW_CHECKLIST.md` sign-off table for the full list mapped to
   commits.
3. `scripts/preflight.py`: **PASS** after fixes (355 tests, ruff + mypy --strict
   clean).
4. Re-review of the fixes: recommended before push per AI_RULES ("修正した上で
   再レビューを受けること"); not yet run at commit `8535cb6`.
5. Human confirmation: no real customer / private material in any commit —
   still to confirm before push.
