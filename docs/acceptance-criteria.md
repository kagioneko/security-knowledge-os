# Acceptance Criteria

MVP criteria from the Implementation Spec (Sections 23, 32, 33), each mapped to
the tests that cover it. Status is updated as milestones land.

| AC | Requirement | Milestone | Status | Tests |
| --- | --- | --- | --- | --- |
| AC-01 | Knowledge Unit schema validation passes | M1 | done | `test_knowledge_schema.py` |
| AC-02 | Classification violations are blocked | M1/M2 | done | `test_classification_gate.py`, `test_classification_leakage.py` |
| AC-03 | A query returns Top-K knowledge with sources | M2 | done | `test_retrieval.py` |
| AC-04 | All 12 fixtures process end to end | M3 / M6 | done | `test_assess.py::test_ac04_*`, `test_cli.py::test_test_command_runs_all_fixtures` (`skos test`) |
| AC-05 | Known vulnerable fixtures land on FAIL/WARN | M3 | done | `test_assess.py::test_ac05_*` |
| AC-06 | Safe fixtures are not misjudged as a severe FAIL | M3 | done | `test_assess.py::test_ac06_*` |
| AC-07 | Unknown fixtures return missing info as questions | M4 | done | `test_assess_m4.py::test_ac07_*` |
| AC-08 | Human Gate targets are never auto-executed | M5 | done | `test_human_gate.py` |
| AC-09 | Safe Tests never require real secrets / real delivery | M5 | done | `test_safe_test.py` |
| AC-10 | Output carries Evidence / Limitation / Residual Risk | M3/M4 | done | `test_assess_m4.py::test_ac10_*` |
| AC-11 | Knowledge revision and model info are recorded | M2/M4 | done | `test_assess_m4.py::test_ac11_*` |
| AC-12 | pytest all pass | all | ongoing | CI |
| AC-13 | Normal assessment cannot rewrite production knowledge | M5 | done | `test_knowledge_guard.py`, `test_assess_m5.py::test_assess_source_has_no_knowledge_write` |
| AC-14 | All fixtures complete with no knowledge-write credential | M5 | done | `test_assess_m5.py::test_ac14_*` (read-only sqlite connection) |
| AC-15 | README states read-only, poisoning risk, update review | M8 | not started | |
| AC-16 | README states "PASS is not a security guarantee" | M8 | not started | |
| AC-17 | README states UNKNOWN is a valid verdict | M8 | not started | |
| AC-18 | Trusted / Untrusted boundary is defined | M1/M8 | partial (`docs/safety-boundaries.md`, `docs/threat-model.md`) | |
| AC-19 | Insufficient evidence never falls back to PASS | M3 | done | `test_assess.py::test_ac19_*`, `test_rule_engine` |
| AC-20 | Classification / integrity / Human Gate failures fail closed | M2/M5 | done | `test_fail_closed.py` |

## Deferred acceptance items (registered, not MVP-blocking)

| ID | Requirement | Target |
| --- | --- | --- |
| JA-R01 | A Japanese query can reach a Japanese Knowledge Unit | M7 evaluation |
| JA-R02 | Cross-language retrieval (EN query → JA KU, JA query → EN KU) | future, explicitly out of MVP scope - keep "Japanese support" and "multilingual retrieval" separate |
| M4-DISP-01 | Retrieval representative-section selection prefers content sections (Summary/Risk/…) over meta sections for display; ranking responsibility stays in retrieval, display selection is separate | M4, only if Reviewer output needs it |

## Initial gates (Spec Section 24) - must stay at zero

- Safe Test Safety Violation = 0 (M5, holding: `test_safe_test.py`, all templates pass the validator)
- Classification Leakage = 0 (M2, holding: `test_classification_leakage.py`)
- Human Gate Bypass = 0 (M5, holding: `test_human_gate.py`, no action auto-allowed off the safe list)
