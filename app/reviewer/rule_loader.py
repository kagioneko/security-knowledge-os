"""Load and validate the risk-rule catalogue.

Rules are data. A rule file that does not parse, references an unknown fact, uses
an operator that does not fit the fact type, or requires an unknown evidence key
is a hard error - a broken security rule is never silently skipped (fail-closed).
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.ingestion.parser import FrontMatterError, _read_text_no_follow, safe_load_bounded
from app.ingestion.snapshot import snapshot_tree
from app.models.risk import LLM_OBS_PREFIX, RiskRule
from app.models.rule_clause import Clause, Operator
from app.reviewer.clause_eval import ClauseError, validate_clause
from app.reviewer.evidence import EVIDENCE_KEYS
from app.safe_errors import format_validation_error

_CLAUSE_KEYS = {"field", "op", "value"}
_CONDITIONS_KEYS = {"all", "any"}

# Codex#5 (round 7, 2026-09-12): a hand-authored rule file (id/title/
# conditions/checks/...) is at most a few KB in real use; bounds the raw
# text handed to the YAML parser regardless of how it would blow up.
_MAX_RULE_FILE_BYTES = 50_000


class RuleLoadError(Exception):
    """The rule catalogue is invalid."""


@dataclass
class RuleCatalogue:
    rules: list[RiskRule] = field(default_factory=list)

    def by_id(self, rule_id: str) -> RiskRule:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        raise KeyError(rule_id)


def parse_clause(raw: Any) -> Clause:
    """Accept either the explicit ``{field, op, value}`` form or the shorthand
    ``{fact_key: literal}`` (which means ``eq``)."""
    if not isinstance(raw, dict):
        raise RuleLoadError(f"clause must be a mapping, got {type(raw).__name__}: {raw!r}")

    if _CLAUSE_KEYS.issuperset(raw) and "field" in raw and "op" in raw:
        try:
            return Clause.model_validate(raw)
        except ValidationError as exc:
            raise RuleLoadError(f"invalid clause: {format_validation_error(exc)}") from exc

    if len(raw) != 1:
        # Codex#7 (round 10, 2026-09-13), reproduced exactly as reported: the
        # equivalent condition-level problem was fixed in round 9 (Codex#12,
        # see _parse_rule's own comment above) but this clause-level `sorted()`
        # was missed - `raw` is still raw, pre-pydantic YAML here, which can
        # have heterogeneous key types (e.g. both `null` and a string), and
        # plain `sorted()` on a mix of types raises a bare TypeError instead
        # of this function's typed RuleLoadError. Sorting by each key's
        # str() representation is always well-defined, regardless of the mix
        # of types.
        raise RuleLoadError(
            f"shorthand clause must have exactly one key, got {sorted(raw, key=str)}"
        )
    ((fact_key, literal),) = raw.items()
    # Codex#5 (round 23, 2026-09-20), reproduced exactly as reported: only the
    # explicit form above converted a pydantic ValidationError into the typed
    # RuleLoadError - `{"external_content_ingestion": {"nested": "value"}}`
    # escaped here raw (a traceback from the validation script, an untyped
    # 500 from API resource loading), and pydantic's own message embeds the
    # rejected value.
    try:
        return Clause(field=str(fact_key), op=Operator.EQ, value=literal)
    except ValidationError as exc:
        raise RuleLoadError(f"invalid clause: {format_validation_error(exc)}") from exc


def _as_list(value: Any, *, field: str, source: Path) -> list[Any]:
    # Codex cross-review finding #1 (round 4, 2026-09-12), reproduced exactly
    # as reported (`conditions: false`, `checks: {}`): iterating a non-list
    # value that merely happens to be *iterable* (a dict iterates its keys, a
    # string iterates its characters) silently produces zero or nonsense
    # clauses instead of an error - and an empty 'all'/'checks' list is
    # vacuously true, so a malformed rule silently becomes a rule that always
    # passes rather than one that fails to load.
    if not isinstance(value, list):
        raise RuleLoadError(f"{source}: '{field}' must be a list, got {type(value).__name__}")
    return value


def _parse_rule(data: dict[str, Any], source: Path) -> RiskRule:
    payload = dict(data)
    conditions = payload.get("conditions")
    # Codex cross-review finding #1 (round 4, 2026-09-12): the previous
    # `payload.get("conditions", {}) or {}` ran the `or {}` fallback BEFORE
    # the isinstance check below ever saw the raw value - `or` treats any
    # falsy value (False, 0, "", [], {}) the same as "absent", so
    # `conditions: false` silently became `{}` and the isinstance(dict) check
    # a few lines down was checking the ALREADY-COERCED value, never the
    # author's actual `false`. Absent (None) is now the only case defaulted;
    # anything else that is not a dict is rejected.
    if conditions is None:
        conditions = {}
    # Codex cross-review finding #9 (2026-09-11): RuleConditions has
    # extra="forbid", but it never got the chance to enforce it - this
    # shorthand-conversion step rebuilt 'conditions' from scratch using only
    # conditions.get("all"/"any"), so a misspelled/unknown key (e.g. "alll")
    # was silently dropped instead of raising, and the rule quietly ended up
    # with an empty (== unconditionally TRIGGERED, since an empty 'all' list
    # is vacuously true) or incomplete condition set instead of the one the
    # author wrote.
    if not isinstance(conditions, dict):
        raise RuleLoadError(
            f"{source}: 'conditions' must be a mapping, got {type(conditions).__name__}"
        )
    unknown_condition_keys = set(conditions) - _CONDITIONS_KEYS
    if unknown_condition_keys:
        # Codex#12 (round 9, 2026-09-12), reproduced exactly as reported:
        # `conditions` is raw, pre-pydantic YAML at this point - safe YAML
        # can produce a mapping with heterogeneous key types (e.g. both an
        # integer and `null`), and `sorted()` on a set of mixed types
        # raises a raw TypeError ("'<' not supported between instances of
        # ...") instead of this function's typed RuleLoadError. Sorting by
        # each key's str() representation is always well-defined,
        # regardless of the mix of types.
        raise RuleLoadError(
            f"{source}: unknown key(s) under 'conditions': "
            f"{sorted(unknown_condition_keys, key=str)}"
            f" (only {sorted(_CONDITIONS_KEYS)} are allowed)"
        )
    payload["conditions"] = {
        "all": [
            parse_clause(c)
            for c in _as_list(conditions.get("all", []), field="conditions.all", source=source)
        ],
        "any": [
            parse_clause(c)
            for c in _as_list(conditions.get("any", []), field="conditions.any", source=source)
        ],
    }
    payload["checks"] = [
        parse_clause(c)
        for c in _as_list(payload.get("checks", []), field="checks", source=source)
    ]

    try:
        rule = RiskRule.model_validate(payload)
    except ValidationError as exc:
        raise RuleLoadError(f"{source}: invalid rule: {format_validation_error(exc)}") from exc

    problems = rule_problems(rule)
    if problems:
        raise RuleLoadError(f"{source}: " + "; ".join(problems))
    return rule


def rule_problems(rule: RiskRule) -> list[str]:
    """Every structural problem with an already-constructed ``RiskRule``,
    independent of how it was built.

    Codex#2 (round 11, 2026-09-13), reproduced exactly as reported:
    ``load_rules()`` enforces all of these for a YAML-sourced rule, but
    ``assess()`` (the public library entry point) accepted a
    ``RuleCatalogue`` built directly in Python with none of them checked -
    a rule referencing a nonexistent fact (``is_unknown`` on it is always
    true) fired deterministically and produced a false ``PASS``.
    Centralizing these checks here, called from both ``_parse_rule()``
    below and ``validate_rule_catalogue()`` (used by ``assess()``), means
    a rule gets the exact same validation regardless of which path built
    it.
    """
    problems: list[str] = []

    # Codex#3 (round 7, 2026-09-12) required `rule.clauses()` (conditions OR
    # checks) to be non-empty, unless manual_review=True - catching a rule
    # with NEITHER conditions nor checks. Codex#1 (round 8, 2026-09-12),
    # reproduced exactly as reported: that check is not tight enough. A rule
    # with a trigger `conditions` block but empty `checks` and
    # manual_review=False still has a non-empty `clauses()` (conditions
    # count) and loaded successfully - but conditions only gate
    # applicability; `evaluate_rule()` only ever emits a finding from
    # `checks` or `manual_review`. When such a rule's conditions matched
    # with evidence fully available, it silently produced zero findings and
    # a PASS, indistinguishable from "nothing worth reporting" rather than
    # "this rule is a no-op". A rule must have at least one CHECK (not just
    # a trigger condition) or manual_review=True to be loadable; see
    # rules/agent/OUT-001.yaml and rules/agent/TOOL-000.yaml (fixed by this
    # same round to add manual_review=True) for the two real rules this
    # caught.
    if not rule.checks and not rule.manual_review:
        problems.append(
            f"[{rule.id}]: rule has no checks or manual_review=True - "
            "a trigger condition alone never produces a finding, so it can never "
            "produce a finding"
        )

    # Codex#3 (round 7, 2026-09-12): RiskRule.id's pattern happens to also
    # match the 'LLM-OBS-' prefix reserved for LLM-origin findings
    # (app/models/risk.py::Finding._enforce_llm_boundary) - a rule file
    # declaring `id: LLM-OBS-00001` loaded successfully here and only
    # crashed with an unhandled ValidationError later, the moment this rule
    # actually fired and a Finding(origin="rule", risk_id="LLM-OBS-00001")
    # was constructed. Reject it at load time instead.
    if rule.id.startswith(LLM_OBS_PREFIX):
        problems.append(
            f"rule id {rule.id!r} uses the reserved {LLM_OBS_PREFIX!r} "
            "prefix (reserved for origin='llm' findings)"
        )

    for clause in rule.clauses():
        try:
            validate_clause(clause)
        except ClauseError as exc:
            problems.append(f"[{rule.id}]: {exc}")

    unknown_evidence = set(rule.required_evidence) - EVIDENCE_KEYS
    if unknown_evidence:
        problems.append(f"[{rule.id}]: unknown required_evidence {sorted(unknown_evidence)}")

    return problems


def validate_rule_catalogue(catalogue: RuleCatalogue) -> list[str]:
    """Every structural problem in an already-built ``RuleCatalogue``,
    including cross-rule duplicate ids - the same checks ``load_rules()``
    already applies to every YAML-sourced rule (Codex#2, round 11,
    2026-09-13), enforced here against a catalogue regardless of how it
    was constructed. Returns an empty list for a fully valid catalogue."""
    problems: list[str] = []
    seen: set[str] = set()
    for rule in catalogue.rules:
        if rule.id in seen:
            problems.append(f"duplicate rule id {rule.id}")
        seen.add(rule.id)
        problems.extend(rule_problems(rule))
    return problems


def load_rules(rules_root: Path | str) -> RuleCatalogue:
    rules_root = Path(rules_root)
    # Codex cross-review finding #1 (2026-09-11): Path.rglob() on a missing or
    # empty directory silently yields nothing - previously that produced an
    # EMPTY catalogue, so every assessment evaluated zero rules and settled on
    # a false PASS. A misconfigured/missing rule root must be a hard load
    # error, never a clean bill of health.
    if not rules_root.is_dir():
        raise RuleLoadError(f"rules root does not exist or is not a directory: {rules_root}")

    # Codex#5 (round 8, 2026-09-12), reproduced exactly as reported: Codex#2
    # (round 7)'s O_NOFOLLOW read protects only the FINAL pathname component
    # - `rglob()`'s own directory walk and the later open both re-resolve
    # the full path from scratch, so a symlinked ANCESTOR directory under
    # rules_root (swapped in transiently, or simply present) was silently
    # followed straight through to a file entirely outside it - the same
    # class of gap app/ingestion/snapshot.py's directory-fd walk already
    # closes for the knowledge corpus (round 7, Codex#2). Snapshotting
    # rules_root the same way removes the live, externally-mutable tree
    # from the read path entirely; snapshot_tree() also already rejects any
    # symlink anywhere in the tree, which is why the old
    # `if path.is_symlink()` check right before the read is gone below.
    try:
        snapshot_root = snapshot_tree(rules_root)
    except OSError as exc:
        raise RuleLoadError(f"{rules_root}: could not safely read the rules directory: {exc}") \
            from exc

    try:
        catalogue = RuleCatalogue()
        seen: dict[str, Path] = {}

        for snap_path in sorted(snapshot_root.rglob("*.yaml")):
            path = rules_root / snap_path.relative_to(snapshot_root)  # for error messages only
            try:
                text = _read_text_no_follow(snap_path)
            except (OSError, FrontMatterError) as exc:
                raise RuleLoadError(f"{path}: {exc}") from exc
            try:
                # Codex#5 (round 7, 2026-09-12): plain yaml.safe_load() had
                # none of the merge-key ban / size cap / RecursionError
                # handling the knowledge front-matter loader already had -
                # ~1,500 nested YAML collections raised an uncaught
                # RecursionError straight out of load_rules(). Reuses the
                # exact same bounded loader.
                raw = safe_load_bounded(text, max_bytes=_MAX_RULE_FILE_BYTES, what="rule file")
            except FrontMatterError as exc:
                raise RuleLoadError(f"{path}: {exc}") from exc
            if not isinstance(raw, dict):
                raise RuleLoadError(f"{path}: a rule file must contain one mapping")

            rule = _parse_rule(raw, path)
            if rule.id in seen:
                raise RuleLoadError(
                    f"duplicate rule id {rule.id} in {path} and {seen[rule.id]}"
                )
            seen[rule.id] = path
            catalogue.rules.append(rule)
    finally:
        shutil.rmtree(snapshot_root, ignore_errors=True)

    if not catalogue.rules:
        raise RuleLoadError(f"no rule files (*.yaml) found under {rules_root}")

    return catalogue
