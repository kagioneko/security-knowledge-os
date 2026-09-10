# Threat Model (stub — filled in M8)

Scope: the assessment tool itself, not the systems it assesses.

## Assets

- Knowledge base content, especially `internal` / `confidential` classified units.
- `secret`-classified knowledge (stored outside this repo — must never enter it).
- Operator LLM API credentials.
- Assessment inputs (may contain a customer's system prompts / tool configs).

## Key risks & current mitigations

| risk | mitigation | milestone |
| --- | --- | --- |
| secret knowledge reaches retrieval or the LLM | classification gate + validator ERROR on `secret` in repo; `secret/` git-ignored | M1 (gate), M2 (index guard) |
| LLM fabricates or suppresses a security verdict | deterministic rules are authoritative; LLM capped at `LLM-OBS-*` / `WARN`+`UNKNOWN` (A8) | M1 (model), M4 |
| API key committed or logged | `.gitignore` for `.env`; keys only from env; prompts not logged verbatim (spec Section 25) | M1, M4 |
| tool executes a destructive action during assessment | no tool execution in the MVP; Human Gate returns `HUMAN_APPROVAL_REQUIRED` | M5 |
| assessment input treated as instructions to the reviewer | inputs parsed into typed models, never concatenated into the system prompt | M3 / M4 |

## Non-goals

Unauthorized assessment of third-party systems; attack tests with real secrets or
real external delivery; exploit generation as a primary purpose.
