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

external send · file deletion · production config change · money movement ·
HR judgement · contract / legal judgement · credential retrieval ·
destructive shell / CLI operations.

The reviewer returns `HUMAN_APPROVAL_REQUIRED` instead of acting.
(Implementation lands in M5.)
