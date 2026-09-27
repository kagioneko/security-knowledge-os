"""Pack Manager state: install / rollback / remove with staging, a smoke test,
atomic activation and an audit log (Update Pack spec sections 7, 8, 14, 15).

Layout under ``$SKOS_HOME`` (default ``~/.local/share/skos``), all 0700/0600:

    packs/<classification>/<pack_id>-<version>.zip   every archive installed
    versions/<pack_id>/<version>/                    verified, extracted files
    active/<pack_id> -> ../versions/<pack_id>/<version>   (symlink, swapped atomically)
    installed.json                                   state (see PackState)
    audit.jsonl                                      one JSON object per action

Nothing is changed unless every step succeeds: a failure before activation
leaves the previous version active and untouched.
"""

from __future__ import annotations

import fcntl
import getpass
import json
import os
import re
import secrets
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app import __version__ as ENGINE_VERSION
from app.config import Settings
from app.ingestion.snapshot import snapshot_tree
from app.models.assessment import AssessmentInput
from app.models.pack import PackClassification, PackTrust
from app.models.report import ReportStatus
from app.packs.archive import MAX_ENTRY_BYTES, read_pack_zip, read_zip_bytes
from app.packs.diff import PackDiff, diff_rules
from app.packs.manifest import allowed_pack_path
from app.packs.signing import TrustedKey
from app.packs.trusted_keys import TRUSTED_KEYS
from app.packs.verify import PackVerifyError, Problem, VerifiedPack, parse_manifest, verify_pack
from app.reviewer.rule_loader import RuleCatalogue
from app.safe_errors import format_validation_error


class PackStoreError(Exception):
    """A pack operation failed; the installed state is unchanged."""


class InstalledPack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str
    manifest_sha256: str
    classification: PackClassification
    trust: PackTrust
    installed_at: datetime
    history: list[str] = Field(default_factory=list)  # versions previously active


class StoreState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    packs: dict[str, InstalledPack] = Field(default_factory=dict)
    # Manifest sha256s the operator approved although unsigned. An installed
    # pack is re-verified on every load; an unsigned one loads only if its
    # manifest is still one of these.
    approved_manifests: list[str] = Field(default_factory=list)


def skos_home() -> Path:
    override = os.environ.get("SKOS_HOME")
    if override:
        return Path(override)
    return Path.home() / ".local" / "share" / "skos"


def _mkdir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def _atomic_write(path: Path, data: bytes) -> None:
    _mkdir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def load_state(home: Path | None = None) -> StoreState:
    path = (home or skos_home()) / "installed.json"
    if not path.exists():
        return StoreState()
    try:
        raw = path.read_bytes()
        if len(raw) > 1_000_000:
            raise PackStoreError("installed.json is too large")
        return StoreState.model_validate_json(raw)
    except ValidationError as exc:
        raise PackStoreError(f"installed.json: {format_validation_error(exc)}") from None
    except OSError as exc:
        raise PackStoreError(f"installed.json unreadable ({type(exc).__name__})") from None


def _save_state(home: Path, state: StoreState) -> None:
    _atomic_write(home / "installed.json", state.model_dump_json(indent=2).encode("utf-8"))


def audit(home: Path, action: str, **fields: Any) -> None:
    """Append one audit record. Never contains file content or secrets - only
    ids, versions, hashes and outcomes."""
    record = {
        "timestamp": datetime.now(UTC).isoformat(),
        "operator": getpass.getuser(),
        "action": action,
        **fields,
    }
    _mkdir(home)
    path = home / "audit.jsonl"
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")


@contextmanager
def _locked(home: Path) -> Iterator[None]:
    _mkdir(home)
    fd = os.open(home / ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise PackStoreError("another pack operation is in progress") from None
        yield
    finally:
        os.close(fd)


def read_pack_dir(directory: Path) -> dict[str, bytes]:
    """Read an extracted pack directory through a no-follow snapshot (a
    symlink anywhere is refused), with the same allowlist and size caps as
    a ZIP."""
    snap = snapshot_tree(directory)
    try:
        files: dict[str, bytes] = {}
        for dirpath, _, filenames in os.walk(snap):
            for name in filenames:
                full = Path(dirpath) / name
                rel = full.relative_to(snap).as_posix()
                if not allowed_pack_path(rel):
                    raise PackVerifyError(Problem.INVALID, f"unexpected file {rel!r} in pack")
                with full.open("rb") as fh:
                    data = fh.read(MAX_ENTRY_BYTES + 1)
                if len(data) > MAX_ENTRY_BYTES:
                    raise PackVerifyError(Problem.INVALID, f"{rel}: too large")
                files[rel] = data
        return files
    finally:
        shutil.rmtree(snap, ignore_errors=True)


def _active_target(home: Path, pack_id: str) -> Path | None:
    link = home / "active" / pack_id
    if not link.is_symlink():
        return None
    target = (link.parent / os.readlink(link)).resolve()
    versions = (home / "versions" / pack_id).resolve()
    if target.parent != versions:
        raise PackStoreError(f"active/{pack_id} points outside versions/{pack_id}")
    return target


def _activate(home: Path, pack_id: str, version: str) -> None:
    active = _mkdir(home / "active")
    tmp = active / f".{pack_id}-{secrets.token_hex(4)}"
    os.symlink(Path("..") / "versions" / pack_id / version, tmp)
    os.replace(tmp, active / pack_id)  # atomic


@dataclass
class ActivePack:
    pack_id: str
    verified: VerifiedPack | None
    problem: PackVerifyError | None = None


def verify_active(
    home: Path | None = None,
    *,
    trusted: dict[str, TrustedKey] | None = None,
    today: date | None = None,
) -> list[ActivePack]:
    """Re-verify every active pack from its extracted files."""
    home = home or skos_home()
    state = load_state(home)
    out: list[ActivePack] = []
    for pack_id in sorted(state.packs):
        try:
            target = _active_target(home, pack_id)
            if target is None:
                raise PackVerifyError(
                    Problem.INVALID, "installed but not active (run `skos pack rollback`)"
                )
            files = read_pack_dir(target)
            verified = verify_pack(
                files,
                trusted=TRUSTED_KEYS if trusted is None else trusted,
                engine_version=ENGINE_VERSION,
                today=today or date.today(),
                approved=frozenset(state.approved_manifests),
            )
            if verified.manifest.pack_id != pack_id:
                raise PackVerifyError(Problem.INVALID, "active pack id does not match")
            out.append(ActivePack(pack_id, verified))
        except PackVerifyError as exc:
            out.append(ActivePack(pack_id, None, exc))
        except (OSError, PackStoreError) as exc:
            out.append(
                ActivePack(
                    pack_id, None, PackVerifyError(Problem.INVALID, f"unreadable: {exc}")
                )
            )
    return out


def _smoke_test(core: RuleCatalogue, packs: list[VerifiedPack]) -> None:
    from app.packs.loader import apply_verified  # local: loader imports store
    from app.reviewer.report import build_report

    catalogue = apply_verified(core, packs)
    # Settings.from_env() resolves the safe-test root like every other entry
    # point (a checkout's safe_tests/, else the copy bundled in the wheel);
    # a bare Settings() is relative to the cwd and broke installs run from
    # anywhere but a source checkout.
    report = build_report(
        AssessmentInput(name="skos-pack-smoke-test"),
        catalogue,
        settings=Settings.from_env(),
    )
    if report.status is not ReportStatus.COMPLETED:
        raise PackStoreError("smoke test failed: an empty assessment did not complete")


@dataclass
class ChangePlan:
    verified: VerifiedPack
    files: dict[str, bytes]
    archive: bytes
    previous: InstalledPack | None
    diff: PackDiff
    needs_approval: list[str]


def plan_install(
    zip_path: Path,
    *,
    home: Path | None = None,
    allow_unsigned: bool = False,
    trusted: dict[str, TrustedKey] | None = None,
    today: date | None = None,
) -> ChangePlan:
    """Steps 1-10: read, verify, and diff against what is active. Changes nothing."""
    home = home or skos_home()
    archive = read_zip_bytes(zip_path)
    files = read_pack_zip(archive)
    verified = verify_pack(
        files,
        trusted=TRUSTED_KEYS if trusted is None else trusted,
        engine_version=ENGINE_VERSION,
        today=today or date.today(),
        allow_unsigned=allow_unsigned,
    )
    state = load_state(home)
    previous = state.packs.get(verified.manifest.pack_id)
    old_rules = []
    if previous is not None:
        target = _active_target(home, verified.manifest.pack_id)
        if target is not None:
            old_files = read_pack_dir(target)
            old = verify_pack(
                old_files,
                trusted=TRUSTED_KEYS if trusted is None else trusted,
                engine_version=ENGINE_VERSION,
                today=today or date.today(),
                approved=frozenset(state.approved_manifests),
                allow_unsigned=True,  # only used for diffing, never activated here
                require_license=False,
            )
            old_rules = old.catalogue.rules
    diff = diff_rules(old_rules, verified.catalogue.rules)
    needs = list(diff.sensitive)
    if verified.manifest.classification is PackClassification.CONFIDENTIAL:
        needs.append("confidential pack (customer-specific)")
    return ChangePlan(verified, files, archive, previous, diff, needs)


def install(
    zip_path: Path,
    core: RuleCatalogue,
    *,
    home: Path | None = None,
    allow_unsigned: bool = False,
    approve_sensitive: bool = False,
    trusted: dict[str, TrustedKey] | None = None,
    today: date | None = None,
) -> ChangePlan:
    home = home or skos_home()
    with _locked(home):
        try:
            plan = plan_install(
                zip_path, home=home, allow_unsigned=allow_unsigned, trusted=trusted, today=today
            )
        except (PackVerifyError, ValueError) as exc:
            audit(home, "install", source=zip_path.name, verification_result=str(exc),
                  install_result="rejected")
            raise
        m = plan.verified.manifest
        audit_base = {
            "pack_id": m.pack_id,
            "old_version": plan.previous.version if plan.previous else None,
            "new_version": m.version,
            "manifest_hash": plan.verified.manifest_sha256,
            "verification_result": "ok",
        }
        if plan.needs_approval and not approve_sensitive:
            audit(home, "install", install_result="needs-approval", **audit_base)
            raise PackStoreError(
                "sensitive change(s) need --approve-sensitive: " + "; ".join(plan.needs_approval)
            )
        state = load_state(home)
        versions = _mkdir(home / "versions" / m.pack_id)
        final = versions / m.version
        if final.exists():
            existing = parse_manifest(read_pack_dir(final))[1]
            if existing != plan.verified.manifest_sha256:
                audit(home, "install", install_result="rejected-version-reuse", **audit_base)
                raise PackStoreError(
                    f"version {m.version} is already installed with different content; "
                    "a released version must never change"
                )
        staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=versions))
        try:
            for rel, data in plan.files.items():
                dest = staging / rel
                _mkdir(dest.parent)
                fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
            # validator: re-verify what actually landed on disk
            restaged = verify_pack(
                read_pack_dir(staging),
                trusted=TRUSTED_KEYS if trusted is None else trusted,
                engine_version=ENGINE_VERSION,
                today=today or date.today(),
                allow_unsigned=allow_unsigned,
            )
            others = [
                a.verified for a in verify_active(home, trusted=trusted, today=today)
                if a.verified is not None and a.pack_id != m.pack_id
            ]
            _smoke_test(core, [*others, restaged])
            if not final.exists():
                os.rename(staging, final)
        except BaseException as exc:
            shutil.rmtree(staging, ignore_errors=True)
            audit(home, "install", install_result=f"failed: {type(exc).__name__}", **audit_base)
            raise
        shutil.rmtree(staging, ignore_errors=True)

        archive = _mkdir(home / "packs" / m.classification.value) / f"{m.pack_id}-{m.version}.zip"
        if not archive.exists():
            _atomic_write(archive, plan.archive)
        _activate(home, m.pack_id, m.version)

        history = list(plan.previous.history) if plan.previous else []
        if plan.previous and plan.previous.version != m.version:
            history.append(plan.previous.version)
        state.packs[m.pack_id] = InstalledPack(
            version=m.version,
            manifest_sha256=plan.verified.manifest_sha256,
            classification=m.classification,
            trust=plan.verified.trust,
            installed_at=datetime.now(UTC),
            history=history,
        )
        if (
            plan.verified.trust is PackTrust.OPERATOR_APPROVED
            and plan.verified.manifest_sha256 not in state.approved_manifests
        ):
            state.approved_manifests.append(plan.verified.manifest_sha256)
        _save_state(home, state)
        audit(home, "install", install_result="ok", **audit_base)
        return plan


def rollback(
    pack_id: str,
    version: str,
    core: RuleCatalogue,
    *,
    home: Path | None = None,
    approve_sensitive: bool = False,
    trusted: dict[str, TrustedKey] | None = None,
    today: date | None = None,
) -> PackDiff:
    home = home or skos_home()
    trusted_keys = TRUSTED_KEYS if trusted is None else trusted
    with _locked(home):
        state = load_state(home)
        current = state.packs.get(pack_id)
        if current is None:
            raise PackStoreError(f"pack {pack_id!r} is not installed")
        if not re.fullmatch(r"\d{4}\.\d{2}\.\d{1,4}", version):
            raise PackStoreError("version must look like YYYY.MM.PATCH")
        target = home / "versions" / pack_id / version
        if not target.is_dir():
            raise PackStoreError(f"version {version!r} of {pack_id!r} is not available")
        base = {"pack_id": pack_id, "old_version": current.version, "new_version": version}
        try:
            verified = verify_pack(
                read_pack_dir(target), trusted=trusted_keys, engine_version=ENGINE_VERSION,
                today=today or date.today(), approved=frozenset(state.approved_manifests),
            )
            active = _active_target(home, pack_id)
            old_rules = []
            if active is not None:
                old_rules = verify_pack(
                    read_pack_dir(active), trusted=trusted_keys, engine_version=ENGINE_VERSION,
                    today=today or date.today(), approved=frozenset(state.approved_manifests),
                    allow_unsigned=True, require_license=False,
                ).catalogue.rules
            diff = diff_rules(old_rules, verified.catalogue.rules)
            if diff.sensitive and not approve_sensitive:
                raise PackStoreError(
                    "sensitive change(s) need --approve-sensitive: " + "; ".join(diff.sensitive)
                )
            others = [
                a.verified for a in verify_active(home, trusted=trusted, today=today)
                if a.verified is not None and a.pack_id != pack_id
            ]
            _smoke_test(core, [*others, verified])
        except (PackVerifyError, PackStoreError, OSError) as exc:
            audit(home, "rollback", rollback_result=f"failed: {exc}", **base)
            raise
        _activate(home, pack_id, version)
        history = [v for v in current.history if v != version] + [current.version]
        state.packs[pack_id] = InstalledPack(
            version=version,
            manifest_sha256=verified.manifest_sha256,
            classification=verified.manifest.classification,
            trust=verified.trust,
            installed_at=datetime.now(UTC),
            history=history,
        )
        _save_state(home, state)
        audit(home, "rollback", manifest_hash=verified.manifest_sha256, rollback_result="ok",
              **base)
        return diff


def remove(pack_id: str, *, home: Path | None = None) -> None:
    """Deactivate a pack. Extracted versions and archives are kept (history)."""
    home = home or skos_home()
    with _locked(home):
        state = load_state(home)
        current = state.packs.pop(pack_id, None)
        if current is None:
            raise PackStoreError(f"pack {pack_id!r} is not installed")
        (home / "active" / pack_id).unlink(missing_ok=True)
        _save_state(home, state)
        audit(home, "remove", pack_id=pack_id, old_version=current.version, new_version=None,
              install_result="ok")
