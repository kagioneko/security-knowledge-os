"""The set of names a rule may reference: facts, evidence keys, and the
operator-facing prompts for each.

``CORE_VOCABULARY`` is the built-in set. A pack (docs/pack-schema.md) extends it
with ``extend()``, which returns a NEW vocabulary and never lets a pack override
or shadow an existing name - the core vocabulary itself is immutable.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from app.reviewer.evidence import EVIDENCE_KEYS
from app.reviewer.facts import FACT_SPEC, FactType

PACK_NAME_PATTERN = r"^[a-z][a-z0-9]{1,15}$"
# Must equal app.models.assessment.EXTENSION_KEY_PATTERN (a test keeps them in
# sync; importing it here would create an import cycle).
_EXTENSION_KEY = r"^[a-z][a-z0-9_]{0,47}$"


def is_pack_name(value: str) -> bool:
    return re.fullmatch(PACK_NAME_PATTERN, value) is not None

_EVIDENCE_PROMPT = {
    "system_prompt": "Provide the system prompt (or confirm there is none).",
    "developer_prompt": "Provide the developer prompt if one is used.",
    "rag_pipeline": "Describe the RAG configuration: is retrieval enabled, and from which sources?",
    "tool_policy": "List the tools available to the agent.",
    "tool_permissions_specified": "State each tool's permission (read/write/delete/send/shell).",
    "memory_spec": "Describe memory: enabled? persistent? what scope?",
    "outbound_spec": "State whether the agent can send data to external systems.",
    "outbound_destinations": "List the allowed outbound destinations.",
    "credential_storage": "Describe credential storage and whether the model can read secrets.",
    "human_approval_policy": "List which actions require human approval.",
}

# Prompts for undetermined AssessmentContext facts (applicability could not be decided).
_FACT_PROMPT = {
    "external_content_ingestion": "Does the system ingest external or user-supplied content?",
    "memory_persistent": "Is memory persistent across sessions?",
    "memory_enabled": "Does the system keep any memory?",
    "outbound_enabled": "Can the system send data to external destinations?",
    "credential_exposed_to_model": "Can the model or its tools read raw secrets?",
    "credential_storage": "How are credentials stored (env, vault, proxy, none)?",
}


class VocabularyError(ValueError):
    """A pack tried to add a name it is not allowed to add."""


def _frozen[K, V](mapping: Mapping[K, V]) -> Mapping[K, V]:
    return MappingProxyType(dict(mapping))


@dataclass(frozen=True)
class ExtensionField:
    """Where a pack fact or evidence key is read from: ``extensions.<pack>.<key>``."""

    pack: str
    key: str


@dataclass(frozen=True)
class Vocabulary:
    facts: Mapping[str, FactType]
    evidence_keys: frozenset[str]
    fact_prompts: Mapping[str, str]
    evidence_prompts: Mapping[str, str]
    # Enum-constrained str facts (pack facts only): the allowed literals,
    # "unknown" excluded (it is always allowed).
    fact_values: Mapping[str, frozenset[str]] = field(default_factory=lambda: _frozen({}))
    # Pack facts / evidence keys -> the extensions field they are read from.
    extension_facts: Mapping[str, ExtensionField] = field(default_factory=lambda: _frozen({}))
    extension_evidence: Mapping[str, ExtensionField] = field(
        default_factory=lambda: _frozen({})
    )
    packs: frozenset[str] = frozenset()

    def extend(
        self,
        pack: str,
        *,
        facts: Mapping[str, FactType],
        fact_values: Mapping[str, frozenset[str]],
        evidence: Mapping[str, str],
        questions: Mapping[str, str],
    ) -> Vocabulary:
        """Return a new vocabulary with ``pack``'s names added.

        Every new name must carry the ``<pack>_`` prefix and must not already
        exist; a question may only be given for one of the pack's own facts."""
        if not is_pack_name(pack):
            raise VocabularyError("invalid pack name")
        if pack in self.packs:
            raise VocabularyError(f"pack {pack!r} is already part of this vocabulary")
        prefix = f"{pack}_"
        taken = set(self.facts) | set(self.evidence_keys)

        new_facts = dict(self.facts)
        new_values = dict(self.fact_values)
        new_ext_facts = dict(self.extension_facts)
        for name, fact_type in facts.items():
            _check_new_name(name, prefix, taken, what="fact")
            taken.add(name)
            new_facts[name] = fact_type
            new_ext_facts[name] = ExtensionField(pack, name[len(prefix) :])
        for name, allowed in fact_values.items():
            if facts.get(name) is not FactType.STR:
                raise VocabularyError(f"'values' given for {name!r}, which is not a str fact")
            if not allowed or "unknown" in allowed:
                raise VocabularyError(
                    f"'values' for {name!r} must be non-empty and must not list 'unknown'"
                )
            new_values[name] = frozenset(allowed)

        new_ext_evidence = dict(self.extension_evidence)
        new_evidence_prompts = dict(self.evidence_prompts)
        for name, prompt in evidence.items():
            _check_new_name(name, prefix, taken, what="evidence key")
            taken.add(name)
            new_ext_evidence[name] = ExtensionField(pack, name[len(prefix) :])
            new_evidence_prompts[name] = prompt

        new_fact_prompts = dict(self.fact_prompts)
        for name, prompt in questions.items():
            if name not in facts:
                raise VocabularyError(
                    f"question given for {name!r}, which is not one of this pack's facts"
                )
            new_fact_prompts[name] = prompt

        return Vocabulary(
            facts=_frozen(new_facts),
            evidence_keys=self.evidence_keys | frozenset(evidence),
            fact_prompts=_frozen(new_fact_prompts),
            evidence_prompts=_frozen(new_evidence_prompts),
            fact_values=_frozen(new_values),
            extension_facts=_frozen(new_ext_facts),
            extension_evidence=_frozen(new_ext_evidence),
            packs=self.packs | {pack},
        )

    def merge(self, other: Vocabulary) -> Vocabulary:
        """Combine two vocabularies that were each built by extending the
        SAME base (core) with disjoint packs."""
        overlap = self.packs & other.packs
        if overlap:
            raise VocabularyError(f"pack(s) {sorted(overlap)} present in both vocabularies")
        for name in other.facts:
            if name in self.facts and self.facts[name] is not other.facts[name]:
                raise VocabularyError(f"fact {name!r} defined differently")
        own = set(self.extension_facts) | set(self.extension_evidence)
        theirs = set(other.extension_facts) | set(other.extension_evidence)
        if own & theirs:
            raise VocabularyError(f"name(s) {sorted(own & theirs)} defined by two packs")
        return Vocabulary(
            facts=_frozen({**self.facts, **other.facts}),
            evidence_keys=self.evidence_keys | other.evidence_keys,
            fact_prompts=_frozen({**self.fact_prompts, **other.fact_prompts}),
            evidence_prompts=_frozen({**self.evidence_prompts, **other.evidence_prompts}),
            fact_values=_frozen({**self.fact_values, **other.fact_values}),
            extension_facts=_frozen({**self.extension_facts, **other.extension_facts}),
            extension_evidence=_frozen({**self.extension_evidence, **other.extension_evidence}),
            packs=self.packs | other.packs,
        )


def _check_new_name(name: str, prefix: str, taken: set[str], *, what: str) -> None:
    # The part after the prefix is the key in `extensions.<pack>.<key>`, so it
    # must satisfy exactly the input's key rule - otherwise a fact could be
    # declared that no input can ever supply (Codex re-review F23).
    if not name.startswith(prefix) or not re.fullmatch(
        _EXTENSION_KEY, name[len(prefix) :]
    ):
        raise VocabularyError(
            f"{what} {name!r} must be '{prefix}<key>' with <key> matching {_EXTENSION_KEY}"
        )
    if name in taken:
        raise VocabularyError(f"{what} {name!r} already exists and cannot be redefined")


CORE_VOCABULARY = Vocabulary(
    facts=_frozen(FACT_SPEC),
    evidence_keys=EVIDENCE_KEYS,
    fact_prompts=_frozen(_FACT_PROMPT),
    evidence_prompts=_frozen(_EVIDENCE_PROMPT),
)
