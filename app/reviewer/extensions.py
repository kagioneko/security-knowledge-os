"""Turn an input's ``extensions.<pack>`` blocks into facts and evidence.

Values are read verbatim; there is no derivation logic here (a pack's adapter
command computes derived values and writes them into the input). Every
extension block must belong to a pack in the catalogue's vocabulary - data the
operator expected to be assessed is never silently dropped.
"""

from __future__ import annotations

from app.models.assessment import AssessmentInput
from app.reviewer.facts import Fact, FactType
from app.reviewer.vocabulary import Vocabulary, is_pack_name

_UNKNOWN = "unknown"


def extension_problems(inp: AssessmentInput, vocabulary: Vocabulary) -> list[str]:
    """Every reason ``inp.extensions`` does not fit ``vocabulary``.

    Messages name the pack (its shape is already constrained to a short
    identifier) and the key, never the rejected value."""
    problems: list[str] = []
    declared: dict[str, dict[str, str]] = {}
    for fact, where in vocabulary.extension_facts.items():
        declared.setdefault(where.pack, {})[where.key] = fact
    evidence_keys: dict[str, set[str]] = {}
    for _, where in vocabulary.extension_evidence.items():
        evidence_keys.setdefault(where.pack, set()).add(where.key)

    for pack, block in inp.extensions.items():
        label = pack if is_pack_name(pack) else "<invalid>"
        if pack not in vocabulary.packs:
            problems.append(
                f"extensions.{label}: no enabled pack named {label!r} - install/enable it "
                "(`skos packs`), or pass --no-packs to assess without it"
            )
            continue
        facts = declared.get(pack, {})
        evidence = evidence_keys.get(pack, set())
        for key, value in block.items():
            if key in evidence:
                if value is not None and not isinstance(value, str):
                    problems.append(f"extensions.{pack}.{key}: evidence must be a string")
                continue
            fact_name = facts.get(key)
            if fact_name is None:
                problems.append(f"extensions.{pack}.{key}: not declared by pack {pack!r}")
                continue
            problem = _value_problem(fact_name, value, vocabulary)
            if problem:
                problems.append(f"extensions.{pack}.{key}: {problem}")
    return problems


def _value_problem(fact: str, value: object, vocabulary: Vocabulary) -> str | None:
    fact_type = vocabulary.facts[fact]
    if value is None:
        return "a list fact cannot be null" if fact_type is FactType.STR_LIST else None
    if fact_type is FactType.BOOL:
        return None if isinstance(value, bool) else "expected true/false"
    if fact_type is FactType.STR:
        if not isinstance(value, str):
            return "expected a string"
        allowed = vocabulary.fact_values.get(fact)
        if allowed is not None and value != _UNKNOWN and value not in allowed:
            return f"expected one of {sorted(allowed)} (or 'unknown')"
        return None
    if not isinstance(value, list):
        return "expected a list of strings"
    return None


def extension_facts(inp: AssessmentInput, vocabulary: Vocabulary) -> dict[str, Fact]:
    """Pack facts for every pack in ``vocabulary``. An absent key reads as
    "not stated" (``None`` / ``"unknown"``); an absent list is empty, matching
    the core's always-concrete list facts. Call only after
    ``extension_problems()`` returned nothing."""
    facts: dict[str, Fact] = {}
    for fact, where in vocabulary.extension_facts.items():
        value = inp.extensions.get(where.pack, {}).get(where.key)
        fact_type = vocabulary.facts[fact]
        if fact_type is FactType.STR_LIST:
            facts[fact] = sorted(value) if isinstance(value, list) else []
        elif fact_type is FactType.STR:
            facts[fact] = value if isinstance(value, str) else _UNKNOWN
        else:
            facts[fact] = value if isinstance(value, bool) else None
    return facts


def extension_evidence(inp: AssessmentInput, vocabulary: Vocabulary) -> set[str]:
    """Pack evidence keys whose field is present and non-empty."""
    return {
        name
        for name, where in vocabulary.extension_evidence.items()
        if inp.extensions.get(where.pack, {}).get(where.key) not in (None, "")
    }
