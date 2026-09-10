# knowledge/private/

Git-ignored knowledge content. Only the directory skeleton and this README are tracked.

- `internal/` — `classification: internal`. Retrievable in PRIVATE mode only.
- `confidential/` — `classification: confidential`. Retrievable in PRIVATE mode
  only, and only when confidential access is explicitly allowed.

`classification: secret` knowledge does **not** belong here. It lives outside this
repository under a separate root (`secret/`), is never indexed, and is never sent
to an LLM. See `docs/safety-boundaries.md` (decision A1).
