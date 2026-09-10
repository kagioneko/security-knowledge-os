# Safety Boundaries

Confirmed decisions (2026-09-10). These are load-bearing: tests enforce them and
they must not be relaxed without an explicit written decision.

## A1 — Classification isolation

```
knowledge/
├─ public/              # git-tracked
└─ private/             # .gitignore (content), skeleton kept
   ├─ internal/
   └─ confidential/
secret/                 # OUTSIDE the repository, separate root
```

| classification | location | retrievable |
| --- | --- | --- |
| public | `knowledge/public/` | PUBLIC + PRIVATE mode |
| internal | `knowledge/private/internal/` | PRIVATE mode |
| confidential | `knowledge/private/confidential/` | PRIVATE mode + explicit allow |
| secret | outside repo | never — indexing & LLM input forbidden |

Secret is **not** merely "private/". A single misconfiguration must not be able to
pull secret content into retrieval. `classification: secret` inside the repo = ERROR.

## A3 — LLM off by default

- Default provider is `none`. The deterministic path
  `Input -> AssessmentContext -> Rule Engine -> Finding -> Report` runs with no
  network, no API key, no LLM.
- An external LLM is used only when `SKOS_LLM_PROVIDER` is set to a real provider
  *and* its credentials are present in the environment.
- API keys are injected via environment variables; never stored in the repo, never
  written to logs.
- The LLM is an assistance layer only: organising evidence prose, generating
  follow-up questions, explanations, and Safe Test proposals.

## A8 — Deterministic rules vs the LLM

```
Deterministic Rule  ->  FAIL / WARN / PASS / UNKNOWN  ->  LLM (assistance)
```

- The LLM can **never downgrade or override** a deterministic verdict.
  Rule Engine says `FAIL`, LLM says "probably fine" -> Final: `FAIL`.
- LLM-only observations use `risk_id` prefix `LLM-OBS-` and are capped at
  `status` `WARN` or `UNKNOWN`.
- The LLM cannot create a `FAIL` and cannot remove one.

Enforced by `app/models/risk.py::Finding` model validation.

## A6 — Overall status rollup

| condition | `overall_status` |
| --- | --- |
| any finding is `FAIL` | `FAIL` |
| no `FAIL`, any `WARN` | `CONDITIONAL` |
| no `FAIL`/`WARN`, any `UNKNOWN` | `UNKNOWN` |
| only `PASS` (and `N/A`) | `PASS` |

`human_review_required = true` if **any** of:
`FAIL`, `WARN`, `UNKNOWN`, a high-impact action, confidential knowledge was used,
or an `LLM-OBS-*` finding exists.

(Implementation lands in M3: `app/reviewer/rollup.py`.)

## A7 — Evidence sufficiency

Each rule declares `required_evidence`. If any required evidence field is
`None` / `unknown` / missing in the `AssessmentContext`, that rule's status is
`UNKNOWN`. Guessing is forbidden.

(Implementation lands in M3.)

## Human Gate (spec Section 15) — never auto-executed

external send · file deletion / write · production config change · money movement ·
HR judgement · contract / legal judgement · credential retrieval ·
destructive shell / CLI operations.

`app/policy/human_gate.py::evaluate_action` returns `HUMAN_APPROVAL_REQUIRED` for
any recognised high-impact action **and for any unrecognised action** (fail
closed). Only an explicit, side-effect-free kind is `ALLOWED`. The system never
executes an action itself.

## §32 — Knowledge Repository is read-only during assessment

Part of the threat model, not a usage note. Retrieved content can contain
descriptions of prompt injection, tool abuse and memory poisoning; if the same
agent could modify its own rules or knowledge, that is a knowledge-poisoning path.

- `app/policy/knowledge_guard.py`: `read` / `list` / `search` -> `ALLOWED`; every
  mutating or unknown operation -> `READ_ONLY_VIOLATION`.
- The assessment path (`app/reviewer/assess.py`) contains no knowledge write and
  completes against a read-only SQLite connection (AC-14).
- There is **no runtime API that changes knowledge content**.
  `POST /v1/knowledge/reindex` only re-derives the FTS index from the existing,
  already-verified read-only knowledge root, with classification + integrity
  checks before an atomic swap; on any failure the existing index is kept.
- An AI's proposed knowledge change is an untrusted proposal, not an edit - it is
  handled through a separate review workflow, never by the assessment agent.

## §33 — Trust boundary & fail-safe

| Trusted / controlled | Untrusted / potentially adversarial |
| --- | --- |
| Reviewed Knowledge Units | User prompts |
| Approved risk rules | External documents / web / PDF / images |
| Classification gate | RAG content before source & integrity verification |
| Deterministic rule engine | The assessed AI's own output |
| Human review / maintainer approval | LLM-generated observations & suggestions |
| | An update pack before verification |

Retrieved content is not trusted just because it came from the Knowledge Repo -
its source, classification and integrity are checked first. Instructions embedded
in untrusted input ("ignore this rule", "rewrite the knowledge") are data, never
control.

Fail-closed rules:

- Evidence insufficient -> `UNKNOWN` (never a guessed `PASS`).
- Classification decision fails -> stop retrieval and LLM input (`PolicyBlocked`).
- LLM output fails to parse -> one repair attempt, then `LLM_PARSE_ERROR` with no
  fabricated observations.
- Rule engine and LLM disagree -> the LLM cannot lift or downgrade a deterministic
  `FAIL` / `WARN` (decision A8, enforced by the `Finding` model + `merge_findings`).
- Human Gate decision fails -> `HUMAN_APPROVAL_REQUIRED`.
- Index integrity / revision check fails -> `POLICY_BLOCKED`; a `PolicyStop`
  aborts the assessment rather than returning an empty result.

`PASS` is not a security guarantee. `UNKNOWN` is a valid verdict. The final
decision is a human's.
