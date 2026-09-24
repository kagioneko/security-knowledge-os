"""M3: rule catalogue loading and validation (fail-closed)."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.models.rule_clause import Operator
from app.reviewer.rule_loader import RuleCatalogue, RuleLoadError, load_rules, parse_clause


def test_real_catalogue_loads(catalogue: RuleCatalogue) -> None:
    ids = sorted(rule.id for rule in catalogue.rules)
    assert ids == ["CRED-001", "GOV-001", "MEM-001", "OUT-001", "PI-003", "TOOL-000", "TOOL-001"]


def test_every_rule_clause_is_data_only(catalogue: RuleCatalogue) -> None:
    for rule in catalogue.rules:
        for clause in rule.clauses():
            assert clause.op in set(Operator)
            assert isinstance(clause.field, str)


def test_shorthand_clause_becomes_eq() -> None:
    clause = parse_clause({"external_content_ingestion": True})
    assert clause.field == "external_content_ingestion"
    assert clause.op is Operator.EQ
    assert clause.value is True


def test_explicit_clause_form() -> None:
    clause = parse_clause({"field": "credential_storage", "op": "in", "value": ["env"]})
    assert clause.op is Operator.IN


def _write_rule(tmp_path: Path, body: str) -> Path:
    root = tmp_path / "rules"
    root.mkdir()
    (root / "r.yaml").write_text(body, encoding="utf-8")
    return root


def test_unknown_fact_is_rejected(tmp_path: Path) -> None:
    root = _write_rule(
        tmp_path,
        "id: X-001\ntitle: t\ncategory: agent-security\nseverity: low\n"
        "conditions:\n  all:\n    - made_up_fact: true\n"
        "checks: [{outbound_enabled: true}]\n",
    )
    with pytest.raises(RuleLoadError, match="unknown fact"):
        load_rules(root)


def test_unknown_evidence_key_is_rejected(tmp_path: Path) -> None:
    root = _write_rule(
        tmp_path,
        "id: X-002\ntitle: t\ncategory: agent-security\nseverity: low\n"
        "checks: [{outbound_enabled: true}]\n"
        "required_evidence: [not_a_real_key]\n",
    )
    with pytest.raises(RuleLoadError, match="required_evidence"):
        load_rules(root)


def test_unknown_evidence_key_error_does_not_echo_the_value(tmp_path: Path) -> None:
    """Regression for Codex round-31 (2026-09-25): required_evidence is an
    unconstrained list[str] - the error used to quote the rejected key(s)
    verbatim."""
    root = _write_rule(
        tmp_path,
        "id: X-003\ntitle: t\ncategory: agent-security\nseverity: low\n"
        "checks: [{outbound_enabled: true}]\n"
        "required_evidence: [AUDIT_DUMMY_CONFIDENTIAL_VALUE]\n",
    )
    with pytest.raises(RuleLoadError) as exc_info:
        load_rules(root)
    assert "AUDIT_DUMMY_CONFIDENTIAL_VALUE" not in str(exc_info.value)


def test_deeply_nested_rule_yaml_fails_closed_not_a_raw_recursionerror(
    tmp_path: Path,
) -> None:
    """Regression for Codex#5 (round 7, 2026-09-12), reproduced exactly as
    reported: plain yaml.safe_load() had none of the merge-key ban / size
    cap / RecursionError handling the knowledge front-matter loader already
    had - roughly 1,500 nested YAML collections raised an uncaught
    RecursionError straight out of load_rules()."""
    nested = "x: " + "[" * 1500 + "]" * 1500
    root = _write_rule(tmp_path, nested)
    with pytest.raises(RuleLoadError, match="deeply nested"):
        load_rules(root)


def test_a_rule_with_no_conditions_or_checks_is_rejected(tmp_path: Path) -> None:
    """Regression for Codex#3 (round 7, 2026-09-12), reproduced exactly as
    reported: a rule with empty conditions, checks, and manual_review=False
    satisfies the non-empty-catalogue check but can never produce a
    finding - assessing against a catalogue containing only such a rule
    returned 0 findings, 0 missing-information, indistinguishable from
    "nothing worth reporting" rather than "this rule is a no-op"."""
    root = _write_rule(
        tmp_path,
        "id: NOOP-001\ntitle: No-op rule\ncategory: governance\nseverity: high\n",
    )
    with pytest.raises(RuleLoadError, match="can never produce a finding"):
        load_rules(root)


def test_a_condition_only_rule_with_no_checks_is_rejected(tmp_path: Path) -> None:
    """Regression for Codex#1 (round 8, 2026-09-12), reproduced exactly as
    reported: round-7's inert-rule check (test above) used `rule.clauses()`,
    which counts `conditions.all`/`conditions.any` together with `checks` -
    a rule with a trigger `conditions` block but empty `checks` and
    `manual_review=False` has a non-empty `clauses()` and loaded
    successfully, but `evaluate_rule()` only ever emits a finding from
    `checks`/`manual_review` (see rule_engine.py's `elif rule.checks:` /
    `elif rule.manual_review:` branches) - when such a rule's conditions
    matched with evidence fully available, it produced zero findings and a
    silent PASS. A rule must have at least one CHECK (not just a trigger
    condition) or manual_review=True to be loadable. This exact shape was
    shipping in rules/agent/OUT-001.yaml and rules/agent/TOOL-000.yaml
    (both fixed by adding manual_review: true in this same round - they
    happened to never actually reach the silent branch at runtime because
    their required_evidence is evidence.py-coupled to always be "missing"
    whenever their condition is true, but nothing enforced that coupling,
    making it a latent trap for the next rule author)."""
    root = _write_rule(
        tmp_path,
        "id: X-999\ntitle: condition-only risk\ncategory: governance\nseverity: high\n"
        "conditions:\n  all:\n    - memory_enabled: true\n",
    )
    with pytest.raises(RuleLoadError, match="can never produce a finding"):
        load_rules(root)


def test_a_manual_review_rule_with_no_checks_is_allowed(tmp_path: Path) -> None:
    """An always-flag-for-human-review rule with no automated checks is a
    legitimate, intentional pattern - not the same inert no-op as above."""
    root = _write_rule(
        tmp_path,
        "id: MANUAL-001\ntitle: Always flag for review\ncategory: governance\n"
        "severity: high\nmanual_review: true\n",
    )
    catalogue = load_rules(root)
    assert catalogue.by_id("MANUAL-001").manual_review is True


def test_ancestor_directory_confinement_is_enforced(tmp_path: Path) -> None:
    """Regression for Codex#5 (round 8, 2026-09-12), reproduced exactly as
    reported: O_NOFOLLOW on the final read (Codex#2, round 7) protects only
    the LAST pathname component - `rglob()`'s own directory walk and the
    later open both re-resolve the full path from scratch, so a symlinked
    ANCESTOR directory under rules_root was silently followed straight
    through to a file entirely outside it. load_rules() now snapshots
    rules_root the same no-follow-at-every-level way
    app/ingestion/snapshot.py already does for the knowledge corpus,
    closing this the same way round 7 closed it there.

    NOTE: this test is deliberately NOT named with "symlink" in it, and
    matches on the wrapper message load_rules() adds around the underlying
    SnapshotError rather than on the word "symlink" alone - pytest's
    `tmp_path` fixture names the temp directory after the TEST FUNCTION
    itself, so a test named e.g. "...symlinked..." would make
    match="symlink" trivially satisfied by that path fragment showing up
    in ANY error message, pre-fix included (the pre-fix message here is
    "no rule files (*.yaml) found under <tmp_path>/rules", which says
    nothing about symlinks - but a test named after the word "symlink"
    would still spuriously pass without ever really exercising the fix)."""
    root = tmp_path / "rules"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "r.yaml").write_text(
        "id: X-901\ntitle: OUTSIDE\ncategory: governance\nseverity: high\n"
        "manual_review: true\n",
        encoding="utf-8",
    )
    (root / "nested").symlink_to(outside, target_is_directory=True)

    with pytest.raises(RuleLoadError, match="could not safely read the rules directory"):
        load_rules(root)


def test_a_rule_id_using_the_reserved_llm_obs_prefix_is_rejected(tmp_path: Path) -> None:
    """Regression for Codex#3 (round 7, 2026-09-12), reproduced exactly as
    reported: `id: LLM-OBS-00001` matches RiskRule's id pattern and loaded
    successfully, but later crashed with an unhandled ValidationError the
    moment this rule actually fired and a Finding(origin="rule",
    risk_id="LLM-OBS-00001") was constructed - Finding._enforce_llm_boundary
    reserves that prefix for origin='llm' findings. Reject it at load time."""
    root = _write_rule(
        tmp_path,
        "id: LLM-OBS-00001\ntitle: t\ncategory: governance\nseverity: high\n"
        "checks: [{outbound_enabled: true}]\n",
    )
    with pytest.raises(RuleLoadError, match="reserved"):
        load_rules(root)


def test_a_duplicated_yaml_key_in_a_rule_file_is_rejected(tmp_path: Path) -> None:
    """Regression for Codex#2 (round 12, 2026-09-13), reproduced exactly as
    reported: a rule file with `severity` written twice loaded successfully
    with only the LAST value in effect - PyYAML's own last-key-wins
    behaviour silently weakened the rule (high -> low here) with no error
    at all. This is the exact repro from the finding."""
    root = _write_rule(
        tmp_path,
        "id: PI-999\ntitle: duplicate-key rule\ncategory: agent-security\n"
        "severity: high\nseverity: low\nchecks:\n  - tools_present: true\n",
    )
    with pytest.raises(RuleLoadError, match="duplicate key"):
        load_rules(root)


def test_a_rule_file_replaced_by_a_fifo_is_rejected_not_silently_dropped(
    tmp_path: Path,
) -> None:
    """Regression for Codex#3 (round 12, 2026-09-13), reproduced exactly as
    reported (this is the finding's own repro shape): a rule file replaced
    by a FIFO used to be silently skipped by the snapshot walk, so
    load_rules() loaded the REMAINING catalogue as if the removed rule had
    never existed - never reporting that TOOL-001-shaped coverage was
    gone. load_rules() must now refuse to load at all rather than load a
    silently-reduced catalogue."""
    import os

    root = tmp_path / "rules"
    root.mkdir()
    os.mkfifo(root / "TOOL-001.yaml")

    with pytest.raises(RuleLoadError, match="not a regular file"):
        load_rules(root)


def test_bad_operator_is_rejected(tmp_path: Path) -> None:
    root = _write_rule(
        tmp_path,
        "id: X-003\ntitle: t\ncategory: agent-security\nseverity: low\n"
        "checks:\n  - field: external_content_ingestion\n    op: regex\n    value: x\n",
    )
    with pytest.raises(RuleLoadError):
        load_rules(root)


def test_conditions_false_is_rejected_not_silently_emptied(tmp_path: Path) -> None:
    """Regression for Codex cross-review finding #1 (round 4, 2026-09-12),
    reproduced exactly as reported: `payload.get("conditions", {}) or {}`
    treated an explicit `conditions: false` the same as "conditions absent"
    (both falsy to `or`), silently normalizing it into an empty - vacuously
    TRUE, since an empty 'all' list always matches - condition set instead
    of rejecting the malformed value. Omitting `conditions` entirely stays
    legal (see other tests in this file); an explicit wrong-typed value must
    not be."""
    root = _write_rule(
        tmp_path,
        "id: X-010\ntitle: t\ncategory: agent-security\nseverity: low\nconditions: false\n",
    )
    with pytest.raises(RuleLoadError, match="conditions"):
        load_rules(root)


def test_checks_wrong_type_is_rejected_not_silently_emptied(tmp_path: Path) -> None:
    """Regression for Codex cross-review finding #1, part 2 (round 4,
    2026-09-12), reproduced exactly as reported: `checks: {}` iterates an
    empty dict (zero key/value pairs) instead of being rejected as "not a
    list" - silently normalizing a malformed `checks` into no checks at
    all."""
    root = _write_rule(
        tmp_path,
        "id: X-011\ntitle: t\ncategory: agent-security\nseverity: low\nchecks: {}\n",
    )
    with pytest.raises(RuleLoadError, match="checks"):
        load_rules(root)


def test_duplicate_rule_id_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "rules"
    root.mkdir()
    text = "id: X-004\ntitle: t\ncategory: agent-security\nseverity: low\n"
    (root / "a.yaml").write_text(text, encoding="utf-8")
    (root / "b.yaml").write_text(text, encoding="utf-8")
    with pytest.raises(RuleLoadError, match="duplicate"):
        load_rules(root)


def test_missing_rules_root_is_rejected(tmp_path: Path) -> None:
    """Regression for Codex cross-review finding #1 (2026-09-11): a rule root
    that does not exist used to silently load an empty catalogue -> every
    assessment evaluated zero rules and settled on a false PASS. Must be a hard
    load error instead."""
    with pytest.raises(RuleLoadError, match="does not exist"):
        load_rules(tmp_path / "no-such-dir")


def test_rules_root_that_is_a_file_is_rejected(tmp_path: Path) -> None:
    f = tmp_path / "not-a-dir.yaml"
    f.write_text("id: X-005\n", encoding="utf-8")
    with pytest.raises(RuleLoadError, match="not a directory"):
        load_rules(f)


def test_empty_rules_root_is_rejected(tmp_path: Path) -> None:
    """A directory that exists but contains no rule YAML files must also be a
    hard error - the same false-PASS risk as a missing directory."""
    root = tmp_path / "rules"
    root.mkdir()
    with pytest.raises(RuleLoadError, match="no rule files"):
        load_rules(root)


def test_unknown_key_under_conditions_is_rejected(tmp_path: Path) -> None:
    """Regression for Codex cross-review finding #9 (2026-09-11): a misspelled
    key under 'conditions' (e.g. 'alll' instead of 'all') used to be silently
    dropped by the shorthand-conversion step, leaving the rule with an empty
    'all'/'any' - which is vacuously TRIGGERED for every assessment - instead
    of raising, even though RuleConditions itself has extra='forbid'."""
    root = _write_rule(
        tmp_path,
        "id: X-007\ntitle: t\ncategory: agent-security\nseverity: low\n"
        "conditions:\n  alll:\n    - tools_present: true\n",
    )
    with pytest.raises(RuleLoadError, match="conditions"):
        load_rules(root)


def test_heterogeneous_unknown_condition_keys_do_not_raise_a_raw_typeerror(
    tmp_path: Path,
) -> None:
    """Regression for Codex#12 (round 9, 2026-09-12), reproduced exactly as
    reported: `conditions` is raw, pre-pydantic YAML at the point unknown
    keys are checked - safe YAML can produce a mapping with heterogeneous
    key types (here, an integer `1` and `null`), and `sorted()` on a set
    mixing those types raises a raw TypeError instead of this loader's
    typed RuleLoadError."""
    root = _write_rule(
        tmp_path,
        "id: X-008\ntitle: t\ncategory: agent-security\nseverity: low\n"
        "conditions:\n  1: true\n  null: true\n",
    )
    with pytest.raises(RuleLoadError, match="conditions"):
        load_rules(root)


def test_heterogeneous_shorthand_clause_keys_do_not_raise_a_raw_typeerror() -> None:
    """Regression for Codex#7 (round 10, 2026-09-13), reproduced exactly as
    reported: `parse_clause({None: 1, "x": 2})` raised a bare
    `TypeError: '<' not supported between instances of 'str' and
    'NoneType'` from the shorthand-clause branch's `sorted(raw)` call - the
    sibling condition-level problem was fixed in round 9 (Codex#12) but
    this clause-level path was missed. `raw` is still raw, pre-pydantic
    YAML here, which can have heterogeneous key types."""
    with pytest.raises(RuleLoadError, match="shorthand clause"):
        parse_clause({None: 1, "x": 2})


def test_heterogeneous_shorthand_clause_keys_via_load_rules(tmp_path: Path) -> None:
    """Same as above, reached through load_rules() as Codex also reported
    ("the same occurs through load_rules() with a null: and string key in
    one clause")."""
    root = _write_rule(
        tmp_path,
        "id: X-009\ntitle: t\ncategory: agent-security\nseverity: low\n"
        "conditions:\n  all:\n    - null: true\n      x: true\n",
    )
    with pytest.raises(RuleLoadError, match="shorthand clause"):
        load_rules(root)


def test_symlinked_rule_file_is_rejected(tmp_path: Path) -> None:
    """Codex cross-review finding #2 (2026-09-11): confinement must be
    consistent across knowledge/rule/safe-test loaders."""
    real = tmp_path / "outside.yaml"
    real.write_text(
        "id: X-006\ntitle: t\ncategory: agent-security\nseverity: low\n", encoding="utf-8"
    )
    root = tmp_path / "rules"
    root.mkdir()
    (root / "linked.yaml").symlink_to(real)
    with pytest.raises(RuleLoadError, match="symlink"):
        load_rules(root)
