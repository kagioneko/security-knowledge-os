"""Verify installed packs and merge the trusted ones into a rule catalogue.

Per pack, in order (docs/pack-schema.md):

1. snapshot the pack directory (symlinks anywhere are refused), so every
   later check reads one stable copy;
2. parse ``pack.yaml``; decide trust: a valid signature by a built-in
   publisher key, or an operator ``enable`` pinned to this manifest's sha256;
3. only for a trusted pack: every file hash, the license (commercial tier),
   the vocabulary extension, the rules and the report groups.

An untrusted pack is reported and skipped. A trusted pack that fails any step
of 3 - and a pack whose signature is present but invalid - is an ERROR, and
loading refuses to continue: a broken or tampered rule set never silently
drops out of an assessment.
"""

from __future__ import annotations

import atexit
import hashlib
import os
import shutil
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum
from functools import reduce
from pathlib import Path

from pydantic import ValidationError

from app.ingestion.parser import FrontMatterError, safe_load_bounded
from app.ingestion.snapshot import snapshot_tree
from app.models.pack import AppliedPack, PackTier, PackTrust, ReportGroup
from app.packs.config import PackConfig, PackConfigError, load_config
from app.packs.discovery import PackCandidate, discover
from app.packs.license import check_license
from app.packs.manifest import (
    MANIFEST_FILE,
    PACK_API,
    RESERVED_FILES,
    SIGNATURE_FILE,
    PackManifest,
)
from app.packs.signing import (
    MANIFEST_DOMAIN,
    SignatureError,
    TrustedKey,
    UnknownKeyError,
    parse_signature_file,
    verify,
)
from app.packs.trusted_keys import TRUSTED_KEYS
from app.reviewer.rule_loader import RuleCatalogue, RuleLoadError, load_rules
from app.reviewer.vocabulary import CORE_VOCABULARY, Vocabulary, VocabularyError
from app.safe_errors import format_validation_error

_MAX_MANIFEST_BYTES = 256_000
_MAX_SIG_BYTES = 4_096
_IGNORED_DIRS = frozenset({"__pycache__"})

_kept_snapshots: list[Path] = []


def _cleanup_snapshots() -> None:
    for path in _kept_snapshots:
        shutil.rmtree(path, ignore_errors=True)


atexit.register(_cleanup_snapshots)


class PackLoadError(Exception):
    """A trusted pack is broken or tampered with; assessment must not proceed."""


class PackState(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    ERROR = "error"


@dataclass
class PackStatus:
    label: str
    source: str
    state: PackState
    reason: str
    manifest: PackManifest | None = None
    manifest_sha256: str | None = None
    trust: PackTrust | None = None
    # The verified snapshot the pack's code is imported from (active packs only).
    snapshot: Path | None = None


@dataclass
class LoadedPack:
    status: PackStatus
    catalogue: RuleCatalogue
    applied: AppliedPack
    groups: list[ReportGroup] = field(default_factory=list)


def _read_bytes(path: Path, limit: int) -> bytes | None:
    try:
        with path.open("rb") as fh:
            data = fh.read(limit + 1)
    except FileNotFoundError:
        return None
    if len(data) > limit:
        raise FrontMatterError(f"{path.name} exceeds {limit} bytes")
    return data


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_problems(root: Path, manifest: PackManifest) -> list[str]:
    actual: dict[str, Path] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _IGNORED_DIRS)
        for name in filenames:
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            if rel not in RESERVED_FILES:
                actual[rel] = full
    problems: list[str] = []
    missing = sorted(set(manifest.files) - set(actual))
    unexpected = set(actual) - set(manifest.files)
    if missing:
        problems.append(f"{len(missing)} listed file(s) missing (first: {missing[0]})")
    if unexpected:
        # Unlisted names are not constrained by the manifest schema - report
        # the count only.
        problems.append(f"{len(unexpected)} file(s) present but not listed in the manifest")
    mismatched = sorted(
        rel for rel, full in actual.items()
        if rel in manifest.files and _sha256_file(full) != manifest.files[rel]
    )
    if mismatched:
        problems.append(f"{len(mismatched)} file(s) fail their sha256 (first: {mismatched[0]})")
    return problems


def _vocabulary_for(manifest: PackManifest) -> Vocabulary:
    return CORE_VOCABULARY.extend(
        manifest.name,
        facts={f"{name}": decl.type for name, decl in manifest.facts.items()},
        fact_values={
            name: frozenset(decl.values)
            for name, decl in manifest.facts.items()
            if decl.values is not None
        },
        evidence=manifest.evidence,
        questions=manifest.questions,
    )


def inspect_pack(
    candidate: PackCandidate,
    config: PackConfig,
    *,
    trusted: dict[str, TrustedKey],
    today: date,
) -> tuple[PackStatus, LoadedPack | None]:
    def status(state: PackState, reason: str) -> PackStatus:
        return PackStatus(candidate.label, candidate.source, state, reason)

    if candidate.problem is not None or candidate.directory is None:
        return status(PackState.DISABLED, candidate.problem or "not located"), None
    try:
        snap = snapshot_tree(candidate.directory)
    except OSError as exc:  # includes SnapshotError (symlink, untrusted ancestor)
        return status(PackState.DISABLED, f"unreadable ({type(exc).__name__})"), None

    keep = False
    try:
        result = _inspect_snapshot(candidate, snap, config, trusted=trusted, today=today)
        keep = result[1] is not None
        if keep:
            result[0].snapshot = snap
            _kept_snapshots.append(snap)
        return result
    finally:
        if not keep:
            shutil.rmtree(snap, ignore_errors=True)


def _inspect_snapshot(
    candidate: PackCandidate,
    snap: Path,
    config: PackConfig,
    *,
    trusted: dict[str, TrustedKey],
    today: date,
) -> tuple[PackStatus, LoadedPack | None]:
    st = PackStatus(candidate.label, candidate.source, PackState.DISABLED, "")

    def done(state: PackState, reason: str) -> tuple[PackStatus, None]:
        st.state, st.reason = state, reason
        return st, None

    try:
        raw = _read_bytes(snap / MANIFEST_FILE, _MAX_MANIFEST_BYTES)
    except (OSError, FrontMatterError) as exc:
        return done(PackState.DISABLED, f"pack.yaml unreadable ({type(exc).__name__})")
    if raw is None:
        return done(PackState.DISABLED, "no pack.yaml")
    st.manifest_sha256 = hashlib.sha256(raw).hexdigest()
    try:
        data = safe_load_bounded(
            raw.decode("utf-8"), max_bytes=_MAX_MANIFEST_BYTES, what="pack.yaml"
        )
        manifest = PackManifest.model_validate(data)
    except UnicodeDecodeError:
        return done(PackState.DISABLED, "pack.yaml is not UTF-8")
    except FrontMatterError as exc:
        return done(PackState.DISABLED, f"invalid pack.yaml: {exc}")
    except ValidationError as exc:
        return done(PackState.DISABLED, f"invalid pack.yaml: {format_validation_error(exc)}")
    st.manifest = manifest

    if candidate.source.startswith("entry-point:") and manifest.name != candidate.label:
        return done(PackState.DISABLED, "manifest name does not match the entry point")
    if manifest.pack_api != PACK_API:  # pragma: no cover - Literal[1] already enforces it
        return done(PackState.DISABLED, f"pack_api {manifest.pack_api} unsupported")
    if manifest.name in config.disabled:
        return done(PackState.DISABLED, "disabled by operator (`skos packs enable` to undo)")

    # --- trust -----------------------------------------------------------
    try:
        sig_raw = _read_bytes(snap / SIGNATURE_FILE, _MAX_SIG_BYTES)
    except (OSError, FrontMatterError) as exc:
        return done(PackState.ERROR, f"pack.sig unreadable ({type(exc).__name__})")
    if sig_raw is not None:
        try:
            verify(
                MANIFEST_DOMAIN, raw, parse_signature_file(sig_raw), trusted,
                publisher=manifest.publisher,
            )
        except UnknownKeyError:
            # A signature from a publisher we do not know is the same as no
            # signature: fall through to the operator's decision.
            pass
        except SignatureError as exc:
            return done(PackState.ERROR, f"signature: {exc}")
        else:
            st.trust = PackTrust.SIGNED
    if st.trust is None:
        pinned = config.enabled.get(manifest.name)
        if pinned == st.manifest_sha256:
            st.trust = PackTrust.USER_ENABLED
        elif pinned is not None:
            return done(
                PackState.DISABLED,
                "manifest changed since it was enabled - review it, then `skos packs enable`",
            )
        else:
            return done(
                PackState.DISABLED,
                "not trusted (unsigned or unknown publisher) - `skos packs enable` to allow",
            )

    # --- a trusted pack from here on: any failure is an ERROR ------------
    problems = _file_problems(snap, manifest)
    if problems:
        return done(PackState.ERROR, "file check failed: " + "; ".join(problems))

    if manifest.tier is PackTier.COMMERCIAL:
        lic = check_license(manifest.name, manifest.publisher, trusted, today)
        if not lic.ok:
            return done(PackState.DISABLED, f"license: {lic.reason}")
        license_note = f" ({lic.reason})"
    else:
        license_note = ""

    try:
        vocabulary = _vocabulary_for(manifest)
    except VocabularyError as exc:
        return done(PackState.ERROR, f"vocabulary: {exc}")

    rules_dir = snap / "rules"
    if not rules_dir.is_dir():
        return done(PackState.ERROR, "a pack must ship a rules/ directory")
    try:
        catalogue = load_rules(rules_dir, vocabulary, id_prefix=manifest.rule_prefix)
    except RuleLoadError as exc:
        # Paths in the message point into the temporary snapshot; show them
        # relative to the pack instead.
        return done(PackState.ERROR, f"rules: {str(exc).replace(str(snap) + '/', '')}")

    rule_ids = {r.id for r in catalogue.rules}
    groups: list[ReportGroup] = []
    for group, ids in manifest.report_groups.items():
        unknown = [i for i in ids if i not in rule_ids]
        if unknown:
            return done(
                PackState.ERROR, f"report group {group!r} names unknown rule(s) {unknown}"
            )
        groups.append(ReportGroup(pack=manifest.name, group=group, rule_ids=tuple(ids)))

    st.state, st.reason = PackState.ACTIVE, f"{st.trust.value}{license_note}"
    applied = AppliedPack(
        name=manifest.name,
        version=manifest.version,
        tier=manifest.tier,
        publisher=manifest.publisher,
        trust=st.trust,
        manifest_sha256=st.manifest_sha256,
    )
    return st, LoadedPack(status=st, catalogue=catalogue, applied=applied, groups=groups)


def inspect_all(
    candidates: Iterable[PackCandidate] | None = None,
    config: PackConfig | None = None,
    *,
    trusted: dict[str, TrustedKey] | None = None,
    today: date | None = None,
) -> list[tuple[PackStatus, LoadedPack | None]]:
    if config is None:
        try:
            config = load_config()
        except PackConfigError as exc:
            raise PackLoadError(str(exc)) from None
    return [
        inspect_pack(
            c,
            config,
            trusted=TRUSTED_KEYS if trusted is None else trusted,
            today=today or date.today(),
        )
        for c in (discover() if candidates is None else candidates)
    ]


def apply_packs(
    core: RuleCatalogue,
    inspected: list[tuple[PackStatus, LoadedPack | None]],
) -> RuleCatalogue:
    """Merge every active pack into ``core``. Raises ``PackLoadError`` if any
    pack is in the ERROR state or two active packs share a name."""
    errors = [s for s, _ in inspected if s.state is PackState.ERROR]
    if errors:
        raise PackLoadError(
            "; ".join(f"pack {s.label!r} ({s.source}): {s.reason}" for s in errors)
        )
    loaded = [p for _, p in inspected if p is not None]
    names = [p.applied.name for p in loaded]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise PackLoadError(f"more than one active pack named {duplicates}")
    if not loaded:
        return core
    try:
        vocabulary = reduce(
            lambda acc, p: acc.merge(p.catalogue.vocabulary), loaded, core.vocabulary
        )
    except VocabularyError as exc:
        raise PackLoadError(f"packs conflict: {exc}") from None
    merged = RuleCatalogue(
        rules=[*core.rules, *(r for p in loaded for r in p.catalogue.rules)],
        vocabulary=vocabulary,
        packs_applied=[p.applied for p in loaded],
        report_groups=[g for p in loaded for g in p.groups],
    )
    seen: set[str] = set()
    for rule in merged.rules:
        if rule.id in seen:
            raise PackLoadError(f"duplicate rule id {rule.id} across core and packs")
        seen.add(rule.id)
    return merged


def load_with_packs(core: RuleCatalogue) -> RuleCatalogue:
    """``core`` plus every installed, trusted pack (the default for `skos assess`)."""
    return apply_packs(core, inspect_all())
