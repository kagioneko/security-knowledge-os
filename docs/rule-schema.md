# Risk Rule Schema

Rules live under `rules/<category>/<ID>.yaml`, one rule per file. **A rule is data,
never code.** There is no expression language and nothing in a rule file is ever
executed - the engine interprets a fixed set of typed comparisons.

Validate the catalogue: `python scripts/validate_rules.py rules`
(a rule that does not parse, references an unknown fact, uses an operator that
does not fit the fact, or requires an unknown evidence key is a hard error).

## Fields

```yaml
id: PI-003                       # ^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*-\d{3,}$, unique
title: Indirect prompt injection with an outbound action path
category: rag-security            # KnowledgeCategory
severity: high                    # low | medium | high | critical
manual_review: true              # if all checks pass, emit WARN (not PASS) - the
                                 # structural risk is real, the mitigation is not
                                 # deterministically verifiable
conditions:                      # when does this rule apply?
  all:                           # every clause must be TRUE
    - external_content_ingestion: true
  any:                           # at least one must be TRUE (omit if not needed)
    - has_send_tool: true
    - outbound_enabled: true
checks:                          # what must hold for the target to be safe?
  - outbound_without_approval: false
required_evidence:               # inputs needed to judge (decision A7)
  - rag_pipeline
  - outbound_spec
mitigations:
  - require human approval for every outbound action
safe_test_template: ST-IPI-001   # optional, resolved in M5
knowledge_refs: [KU-1002]         # optional Knowledge Unit ids
```

## Clause forms

A clause compares **one whitelisted fact** to a **literal** with **one operator**.

| form | meaning |
| --- | --- |
| `{fact_key: literal}` | shorthand for `eq` |
| `{field: fact_key, op: <operator>, value: <literal>}` | explicit |

### Operators

| operator | fact type | value | result |
| --- | --- | --- | --- |
| `eq` | bool / str | scalar | TRUE / FALSE (UNKNOWN if fact not stated) |
| `ne` | bool / str | scalar | TRUE / FALSE (UNKNOWN if fact not stated) |
| `in` | bool / str | non-empty list | TRUE if fact ∈ list |
| `contains` | list | scalar | TRUE if literal ∈ fact list |
| `is_unknown` | bool / str | — | TRUE if the fact was not stated |

`None` (fact not stated) yields `UNKNOWN` for every operator except `is_unknown`.

### Facts

The clause `field` must be one of the keys in `app/reviewer/facts.py::FACT_SPEC`
(booleans such as `external_content_ingestion`, `has_delete_tool`,
`outbound_without_approval`; strings such as `memory_scope`, `credential_storage`;
string lists such as `tool_permissions`, `high_impact_actions`).

## Verdict (see `app/reviewer/rule_engine.py`)

```
rule does not apply                    -> no finding
cannot tell if the rule applies        -> UNKNOWN (high/critical only)
required evidence missing              -> UNKNOWN
a check is FALSE                        -> FAIL (high/critical) or WARN
a check is UNKNOWN                      -> UNKNOWN
all checks TRUE, manual_review: true    -> WARN
all checks TRUE                         -> PASS (suppressed if the rule has no checks)
```

A rule is **never** `PASS` while any check was `UNKNOWN` or any required evidence
was missing (AC-19).
