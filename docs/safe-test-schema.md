# Safe Test Schema & Human Gate

## The path an LLM idea cannot skip

```
LLM safe_test_suggestion
   -> UntrustedSafeTestProposal   (origin="llm", 3 fields: title / relates_to_risk_id / idea)
   -> promote_proposal()          -> HUMAN_APPROVAL_REQUIRED   (always; never ALLOWED)
   -> a human authors a vetted template
   -> safe_tests/<ID>.yaml         (origin="template")
   -> validate_safe_test()        -> ALLOWED | POLICY_BLOCKED
   -> attached to AssessmentResult.safe_tests
```

An LLM's ideas appear in `AssessmentResult.safe_test_proposals` and are marked
`origin="llm"`. They are never executable and never enter `safe_tests`.

## SafeTest schema (`app/models/assessment.py`)

Required by the schema (every field that keeps the test safe):

| field | rule |
| --- | --- |
| `origin` | `template` or `human` - never `llm` |
| `environment` | non-empty, subset of `{sandbox, read_only, canary}` |
| `scope` | non-empty, explicit |
| `uses_canary_values` | bool; must be `true` if `canary` is in `environment` |
| `steps` | non-empty |
| `expected_secure_behavior` | non-empty |
| `failure_condition` | non-empty |
| `cleanup` | non-empty |
| `requires_human_approval` | bool |

## Deterministic validator (`app/policy/safe_test.py::validate_safe_test`)

Returns a `PolicyDecision`. `POLICY_BLOCKED` if any of:

- `origin == "llm"`, empty/unknown environment, missing scope or cleanup
- `canary` environment without `uses_canary_values`
- text (setup + steps + cleanup + scope) matches a forbidden pattern:
  production target, `rm -rf`, `DROP TABLE` / `DELETE FROM` / `TRUNCATE`, `sudo`,
  an AWS/Slack/private-key-shaped literal
- text names an external destination - any host that is not `localhost`,
  `127.0.0.1`, `*.example.{com,org,net,invalid}` or `*.invalid`

Shipped templates: `ST-IPI-001`, `ST-MEM-001`, `ST-TOOL-001`, `ST-CRED-001`
(validate with `python scripts/validate_safe_tests.py safe_tests`).

## Human Gate (`app/policy/human_gate.py`)

The system never executes an action. `evaluate_action(kind)` classifies a kind:

- a recognised `HighImpactAction` (external send, file delete/write, production
  change, money movement, HR / legal judgement, credential retrieval, destructive
  shell) or a known alias -> `HUMAN_APPROVAL_REQUIRED`
- an explicitly safe, side-effect-free kind (`read`, `list`, `search`, `retrieve`,
  `analyze`, `classify`, `noop`, `sandbox_probe`) -> `ALLOWED`
- anything else -> **fail closed** -> `HUMAN_APPROVAL_REQUIRED`

## Read-only Knowledge guard (`app/policy/knowledge_guard.py`)

`evaluate_knowledge_operation(op)`: `read`/`list`/`search` -> `ALLOWED`; every
mutating or unknown operation -> `READ_ONLY_VIOLATION`. `guard_knowledge_operation`
raises `PolicyStop` on a violation. The assessment path never calls a knowledge
write and completes against a read-only SQLite connection (AC-14).

## Index integrity (`app/storage/integrity.py`)

`verify_chunk_hashes(conn)` recomputes each chunk's SHA-256 and checks the
`knowledge_revision` meta row. On a mismatch it returns `POLICY_BLOCKED`;
`assess()` raises `PolicyStop` rather than use a tampered index (AC-20).
