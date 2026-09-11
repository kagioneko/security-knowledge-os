"""Load and validate the risk-rule catalogue.

Rules are data. A rule file that does not parse, references an unknown fact, uses
an operator that does not fit the fact type, or requires an unknown evidence key
is a hard error - a broken security rule is never silently skipped (fail-closed).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from app.models.risk import RiskRule
from app.models.rule_clause import Clause, Operator
from app.reviewer.clause_eval import ClauseError, validate_clause
from app.reviewer.evidence import EVIDENCE_KEYS

_CLAUSE_KEYS = {"field", "op", "value"}


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
            raise RuleLoadError(f"invalid clause {raw!r}: {exc}") from exc

    if len(raw) != 1:
        raise RuleLoadError(
            f"shorthand clause must have exactly one key, got {sorted(raw)}"
        )
    ((fact_key, literal),) = raw.items()
    return Clause(field=str(fact_key), op=Operator.EQ, value=literal)


def _parse_rule(data: dict[str, Any], source: Path) -> RiskRule:
    payload = dict(data)
    conditions = payload.get("conditions", {}) or {}
    payload["conditions"] = {
        "all": [parse_clause(c) for c in conditions.get("all", [])],
        "any": [parse_clause(c) for c in conditions.get("any", [])],
    }
    payload["checks"] = [parse_clause(c) for c in payload.get("checks", [])]

    try:
        rule = RiskRule.model_validate(payload)
    except ValidationError as exc:
        raise RuleLoadError(f"{source}: invalid rule: {exc}") from exc

    for clause in rule.clauses():
        try:
            validate_clause(clause)
        except ClauseError as exc:
            raise RuleLoadError(f"{source} [{rule.id}]: {exc}") from exc

    unknown_evidence = set(rule.required_evidence) - EVIDENCE_KEYS
    if unknown_evidence:
        raise RuleLoadError(
            f"{source} [{rule.id}]: unknown required_evidence {sorted(unknown_evidence)}"
        )
    return rule


def load_rules(rules_root: Path | str) -> RuleCatalogue:
    rules_root = Path(rules_root)
    # Codex cross-review finding #1 (2026-09-11): Path.rglob() on a missing or
    # empty directory silently yields nothing - previously that produced an
    # EMPTY catalogue, so every assessment evaluated zero rules and settled on
    # a false PASS. A misconfigured/missing rule root must be a hard load
    # error, never a clean bill of health.
    if not rules_root.is_dir():
        raise RuleLoadError(f"rules root does not exist or is not a directory: {rules_root}")

    catalogue = RuleCatalogue()
    seen: dict[str, Path] = {}

    for path in sorted(rules_root.rglob("*.yaml")):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise RuleLoadError(f"{path}: invalid YAML: {exc}") from exc
        if not isinstance(raw, dict):
            raise RuleLoadError(f"{path}: a rule file must contain one mapping")

        rule = _parse_rule(raw, path)
        if rule.id in seen:
            raise RuleLoadError(
                f"duplicate rule id {rule.id} in {path} and {seen[rule.id]}"
            )
        seen[rule.id] = path
        catalogue.rules.append(rule)

    if not catalogue.rules:
        raise RuleLoadError(f"no rule files (*.yaml) found under {rules_root}")

    return catalogue
