# Publication Manifest — Security Knowledge OS v0.1.0

Snapshot of what the first public push contains. Generated for the pre-publication
review; regenerate with `git ls-files` after any change.

- Commit: (M8 branch tip, **not yet pushed**)
- Licence: **Apache-2.0** (`LICENSE`, `NOTICE`, `pyproject.toml`)
- Tracked files: **185**
- Tests: **309** items (308 pass, 1 skip = JA-R02)
- `scripts/preflight.py`: **PASS**

## Tracked files by area

| area | files | notes |
| --- | --- | --- |
| `app/` | 52 (.py) | engine, models, policy, retrieval, reviewer, llm, storage, eval, cli, main |
| `tests/` | 63 | 33 test modules + fixtures |
| `knowledge/` | 23 | 13 public KUs + `private/` skeleton (README + 2 `.gitkeep`) + category `.gitkeep`s |
| `rules/` | 13 | 7 rule YAMLs + category `.gitkeep`s |
| `safe_tests/` | 4 | 4 vetted templates |
| `scripts/` | 10 | validators, ingest/build_index, assess, evaluate, sbom, secret_scan, preflight |
| `docs/` | 9 | see below |
| root | 7 | `README.md`, `LICENSE`, `NOTICE`, `pyproject.toml`, `.gitignore`, `.env.example`, `sbom.json` |
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

- Assessment fixtures: **12** in `tests/fixtures/assessments/{safe,vulnerable,unknown}/`
  (4 each). Labels drive `scripts/evaluate.py`.
- Knowledge/validator fixtures: 16 `.md` under `tests/fixtures/` (valid, invalid,
  secret-in-repo, corpus, corpus_alt) — test data only, `source_license: "test
  fixture - not for distribution"`.

## Dependencies (`sbom.json`)

| package | version | licence | scope |
| --- | --- | --- | --- |
| pydantic | 2.13.5 | MIT | runtime |
| PyYAML | 6.0.3 | MIT | runtime |
| fastapi | 0.141.1 | MIT | `[api]` |
| uvicorn | — | BSD-3-Clause | `[api]` |
| anthropic | — | MIT | `[llm]` |
| httpx | 0.28.1 | BSD-3-Clause | dev (TestClient) |
| pytest / ruff / mypy | — | MIT | dev |

Core install = `pydantic` + `pyyaml`. All permissive; none conflict with Apache-2.0.

## §24 evaluation (internal fixtures — not real-world performance)

```
known_risk_recall        = 1.000
false_positive_rate      = 0.000   (gate: 0)
unknown_appropriateness  = 1.000
evidence_coverage        = 1.000
citation_source_match    = 1.000
safe_test_violations     = 0       (gate: 0)
classification_leakage   = 0       (gate: 0)
human_gate_bypass        = 0       (gate: 0)
```

Fixtures are artificial. These numbers show the mechanism separates
vulnerable / safe / unknown as designed; they do **not** establish real-world
security effectiveness (stated in README).

## Acceptance criteria

AC-01 .. AC-20: all **done** (`docs/acceptance-criteria.md`).

## Known / accepted risks

| item | status |
| --- | --- |
| API assessment store in-memory | accepted (spec §18 localhost scope) |
| integrity = SHA-256 (content, not authenticity) | accepted (signature is Pack Manager, M9-M10) |
| fixtures artificial; §24 metrics = mechanism check | accepted (stated in README) |
| KU `status: reviewed` = "summary of a reviewed public standard" | accepted (human final pass recommended) |
| `retrieval/hybrid.py` is a thin wrapper | accepted (embeddings/reranker future) |
| JA-R02 cross-language retrieval | accepted (out of MVP scope) |
| CLI uses argparse, not Typer (spec §5) | accepted, documented |
| Pack Manager (M9-M10) not in repo | out of scope; ZIP-import attack surface is future work |

## Blocking before push

1. **Cross-AI review** (Codex code audit + Antigravity adversarial audit) per
   `AI_RULES.md`, recorded in `HANDOFF.md`. — **pending**
2. Address findings -> re-run `scripts/preflight.py` -> re-review if needed.
3. Human confirmation: no real customer / private material in any commit.
