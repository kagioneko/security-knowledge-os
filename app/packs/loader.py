"""Merge installed, verified Update Packs into a rule catalogue for assessment.

Every active pack is re-verified from its extracted files on every load
(signature or operator approval, checksums, license, rules). A pack that
fails is an error and the assessment does not run - a broken or tampered rule
set never silently drops out. The one exception is a commercial pack whose
license has expired or is missing: it is skipped and reported, and any input
``extensions`` block for it is then rejected by the assessment itself.
"""

from __future__ import annotations

from datetime import date
from functools import reduce
from pathlib import Path

from app.models.pack import SkippedPack
from app.packs.signing import TrustedKey
from app.packs.store import ActivePack, verify_active
from app.packs.verify import Problem, VerifiedPack
from app.reviewer.rule_loader import RuleCatalogue
from app.reviewer.vocabulary import VocabularyError


class PackLoadError(Exception):
    """An installed pack is broken or tampered with; assessment must not proceed."""


def apply_verified(core: RuleCatalogue, packs: list[VerifiedPack]) -> RuleCatalogue:
    ids = [p.manifest.pack_id for p in packs]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise PackLoadError(f"more than one active pack with id {duplicates}")
    if not packs:
        return core
    try:
        vocabulary = reduce(lambda acc, p: acc.merge(p.catalogue.vocabulary), packs,
                            core.vocabulary)
    except VocabularyError as exc:
        raise PackLoadError(f"packs conflict: {exc}") from None
    merged = RuleCatalogue(
        rules=[*core.rules, *(r for p in packs for r in p.catalogue.rules)],
        vocabulary=vocabulary,
        packs_applied=[p.applied for p in packs],
        report_groups=[g for p in packs for g in p.groups],
    )
    seen: set[str] = set()
    for rule in merged.rules:
        if rule.id in seen:
            raise PackLoadError(f"duplicate rule id {rule.id} across core and packs")
        seen.add(rule.id)
    return merged


def load_with_packs(
    core: RuleCatalogue,
    *,
    home: Path | None = None,
    trusted: dict[str, TrustedKey] | None = None,
    today: date | None = None,
) -> tuple[RuleCatalogue, list[ActivePack]]:
    active = verify_active(home, trusted=trusted, today=today)
    errors = [
        a for a in active
        if a.problem is not None and a.problem.problem is not Problem.LICENSE
    ]
    if errors:
        raise PackLoadError(
            "; ".join(f"pack {a.pack_id!r}: {a.problem}" for a in errors)
            + " - fix it with `skos pack rollback` / `skos pack remove`, or pass --no-packs"
        )
    verified = [a.verified for a in active if a.verified is not None]
    merged = apply_verified(core, verified)
    if merged is core:
        merged = RuleCatalogue(rules=list(core.rules), vocabulary=core.vocabulary)
    merged.packs_skipped = [
        SkippedPack(pack_id=a.pack_id, reason=str(a.problem))
        for a in active
        if a.problem is not None
    ]
    return merged, active


def only_pack(catalogue: RuleCatalogue, pack_id: str) -> RuleCatalogue:
    """Restrict a merged catalogue to one active pack's rules (``--only-pack``).
    The vocabulary is kept whole so every extensions block is still
    validated; the result records the narrowed scope."""
    applied = [p for p in catalogue.packs_applied if p.pack_id == pack_id]
    if not applied:
        raise PackLoadError(f"--only-pack {pack_id}: no active pack with that id")
    prefix = f"{pack_id.upper()}-"
    return RuleCatalogue(
        rules=[r for r in catalogue.rules if r.id.startswith(prefix)],
        vocabulary=catalogue.vocabulary,
        packs_applied=applied,
        report_groups=[g for g in catalogue.report_groups if g.pack == pack_id],
        packs_skipped=list(catalogue.packs_skipped),
        rule_scope=f"pack:{pack_id}",
    )
