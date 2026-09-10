# Knowledge Unit Schema

A Knowledge Unit (KU) is a single Markdown file: a YAML front matter block followed
by a Markdown body. One KU = one judgement unit (do not paste whole source documents).

## Front matter (required)

```yaml
---
id: KU-0001                        # ^KU-\d{4}$, unique across the corpus
title: "System / user instruction hierarchy conflicts"
category: prompt-security          # see "category" below
source_type: note                 # note | github | gdrive | experiment | incident | standard | manual
source_ref: "https://github.com/... or canonical identifier"
classification: public            # public | internal | confidential | secret
status: reviewed                  # draft | reviewed | approved | deprecated
risk_ids:                         # rule ids this KU is evidence for (may be empty)
  - PI-001
version: "0.1"                    # MUST be quoted (string, not a number)
last_reviewed: "2026-09-10"       # YYYY-MM-DD
requires_ip_review: false         # true if IP / trade-secret review is still pending
---
```

- Unknown front-matter keys are rejected (`extra="forbid"`) to catch typos early.
- `version` and `last_reviewed` must be quoted so YAML keeps them as strings/dates.

### category

| value | public sub-directory |
| --- | --- |
| `prompt-security` | `prompt-security/` |
| `rag-security` | `rag-security/` |
| `agent-security` | `agent-security/` |
| `memory-security` | `memory-security/` |
| `credential-security` | `credential-security/` |
| `incident` | `incidents/` |
| `methodology` | `methodology/` |
| `governance` | `governance/` (rules only for now) |

### classification -> location (decision A1)

| classification | required location | retrievable in |
| --- | --- | --- |
| `public` | `knowledge/public/<category-dir>/` | PUBLIC + PRIVATE |
| `internal` | `knowledge/private/internal/` | PRIVATE |
| `confidential` | `knowledge/private/confidential/` | PRIVATE + explicit allow |
| `secret` | **outside the repository** (`secret/`, separate root) | never — index & LLM forbidden |

A file whose `classification` does not match its directory is a validator **ERROR**.
A file with `classification: secret` anywhere in the repo is a validator **ERROR**.

## Body (recommended sections)

Headings are matched case-insensitively. Missing sections are **warnings**, not errors.

- `## Summary`
- `## Conditions`
- `## Risk`
- `## Evidence`
- `## Failure Mode`
- `## Detection Clues`
- `## Mitigations`
- `## Safe Test`
- `## Limitations`
- `## Related Knowledge`

## Validation

```bash
python scripts/validate_knowledge.py knowledge          # ERROR -> exit 1
python scripts/validate_knowledge.py knowledge --strict # WARNING -> exit 1 too
```

Checks performed (see `app/ingestion/validator.py`):

| code | level | meaning |
| --- | --- | --- |
| `front-matter` | ERROR | missing / malformed YAML front matter |
| `schema` | ERROR | front matter fails the Pydantic schema |
| `secret-in-repo` | ERROR | `classification: secret` found inside the repository |
| `wrong-directory` | ERROR | classification does not match the file location |
| `duplicate-id` | ERROR | KU `id` used by more than one file |
| `category-dir-mismatch` | WARNING | public KU not under its category sub-directory |
| `missing-section` | WARNING | a recommended body section is absent |
| `risk-id-format` | WARNING | a `risk_ids` entry is not `^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*-\d{3,}$` |
