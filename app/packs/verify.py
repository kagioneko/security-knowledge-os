"""Verify a pack given as ``{path: bytes}`` - the single check used both when a
ZIP is inspected/installed and every time an installed pack is loaded.

Order (Update Pack spec section 7): manifest -> engine compatibility ->
classification -> signature/trust -> checksums -> license -> vocabulary ->
rule schema + risk-id prefix -> report groups. Any failure raises
``PackVerifyError`` and nothing is returned; there is no partial pack.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum
from pathlib import Path

from pydantic import ValidationError

from app.models.pack import AppliedPack, PackClassification, PackTrust, ReportGroup
from app.packs.license import check_license
from app.packs.manifest import (
    CHECKSUMS_FILE,
    MANIFEST_FILE,
    SIGNATURE_FILE,
    UNHASHED_FILES,
    PackManifest,
    checksums_text,
)
from app.packs.signing import (
    MANIFEST_DOMAIN,
    SignatureError,
    TrustedKey,
    UnknownKeyError,
    parse_signature_file,
    verify,
)
from app.reviewer.rule_loader import RuleCatalogue, RuleLoadError, load_rules
from app.reviewer.vocabulary import CORE_VOCABULARY, Vocabulary, VocabularyError
from app.safe_errors import format_validation_error


class Problem(StrEnum):
    INVALID = "invalid"            # malformed, tampered, or violates the pack rules
    INCOMPATIBLE = "incompatible"  # engine version out of range
    UNTRUSTED = "untrusted"        # unsigned / unknown key and not approved by the operator
    LICENSE = "license"            # commercial pack without a valid license


class PackVerifyError(ValueError):
    def __init__(self, problem: Problem, message: str) -> None:
        super().__init__(message)
        self.problem = problem


@dataclass
class VerifiedPack:
    manifest: PackManifest
    manifest_sha256: str
    trust: PackTrust
    catalogue: RuleCatalogue
    groups: list[ReportGroup] = field(default_factory=list)
    license_note: str = ""

    @property
    def applied(self) -> AppliedPack:
        m = self.manifest
        return AppliedPack(
            pack_id=m.pack_id,
            version=m.version,
            classification=m.classification,
            publisher=m.publisher,
            trust=self.trust,
            manifest_sha256=self.manifest_sha256,
        )


def parse_manifest(files: dict[str, bytes]) -> tuple[PackManifest, str]:
    raw = files.get(MANIFEST_FILE)
    if raw is None:
        raise PackVerifyError(Problem.INVALID, "manifest.json is missing")
    sha = hashlib.sha256(raw).hexdigest()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise PackVerifyError(Problem.INVALID, "manifest.json is not valid UTF-8 JSON") from None
    if isinstance(data, dict) and data.get("classification") == "secret":
        raise PackVerifyError(Problem.INVALID, "secret-classified material is never packed")
    try:
        return PackManifest.model_validate(data), sha
    except ValidationError as exc:
        raise PackVerifyError(
            Problem.INVALID, f"invalid manifest.json: {format_validation_error(exc)}"
        ) from None


def _trust(
    files: dict[str, bytes],
    manifest: PackManifest,
    manifest_sha: str,
    *,
    trusted: dict[str, TrustedKey],
    approved: frozenset[str],
    allow_unsigned: bool,
) -> PackTrust:
    sig_raw = files.get(SIGNATURE_FILE)
    if sig_raw is not None:
        try:
            verify(
                MANIFEST_DOMAIN, files[MANIFEST_FILE], parse_signature_file(sig_raw), trusted,
                publisher=manifest.publisher,
            )
        except UnknownKeyError:
            pass  # a key we do not know is the same as no signature
        except SignatureError as exc:
            raise PackVerifyError(Problem.INVALID, f"signature: {exc}") from None
        else:
            return PackTrust.SIGNED
    if allow_unsigned or manifest_sha in approved:
        return PackTrust.OPERATOR_APPROVED
    raise PackVerifyError(
        Problem.UNTRUSTED,
        "pack is unsigned or signed by an unknown publisher; install it with "
        "--allow-unsigned only if you have reviewed its contents",
    )


def _checksum_problems(files: dict[str, bytes], manifest: PackManifest) -> list[str]:
    hashed = {p: d for p, d in files.items() if p not in UNHASHED_FILES}
    problems: list[str] = []
    missing = sorted(set(manifest.files) - set(hashed))
    unexpected = sorted(set(hashed) - set(manifest.files))
    if missing:
        problems.append(f"{len(missing)} listed file(s) missing (first: {missing[0]})")
    if unexpected:
        problems.append(f"{len(unexpected)} file(s) not listed in the manifest")
    bad = sorted(
        p for p, d in hashed.items()
        if p in manifest.files and hashlib.sha256(d).hexdigest() != manifest.files[p]
    )
    if bad:
        problems.append(f"{len(bad)} file(s) fail their sha256 (first: {bad[0]})")
    listing = files.get(CHECKSUMS_FILE)
    if listing is not None and listing.decode("utf-8", "replace") != checksums_text(
        manifest.files
    ):
        problems.append("checksums.sha256 does not match the manifest")
    return problems


def _vocabulary_for(manifest: PackManifest) -> Vocabulary:
    return CORE_VOCABULARY.extend(
        manifest.pack_id,
        facts={name: decl.type for name, decl in manifest.facts.items()},
        fact_values={
            name: frozenset(decl.values)
            for name, decl in manifest.facts.items()
            if decl.values is not None
        },
        evidence=manifest.evidence,
        questions=manifest.questions,
    )


def _load_rules(
    files: dict[str, bytes], manifest: PackManifest, vocabulary: Vocabulary
) -> RuleCatalogue:
    tmp = Path(tempfile.mkdtemp(prefix="skos-pack-rules-"))
    try:
        rules = tmp / "rules"
        rules.mkdir()
        for path, data in files.items():
            if path.startswith("rules/"):
                (rules / path[len("rules/") :]).write_bytes(data)
        try:
            return load_rules(rules, vocabulary, id_prefix=manifest.rule_prefix)
        except RuleLoadError as exc:
            raise PackVerifyError(
                Problem.INVALID, f"rules: {str(exc).replace(str(tmp) + '/', '')}"
            ) from None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def verify_pack(
    files: dict[str, bytes],
    *,
    trusted: dict[str, TrustedKey],
    engine_version: str,
    today: date,
    approved: frozenset[str] = frozenset(),
    allow_unsigned: bool = False,
    require_license: bool = True,
) -> VerifiedPack:
    """``require_license=False`` is only for reading an already-installed
    version to diff against; such a result is never activated."""
    manifest, manifest_sha = parse_manifest(files)
    incompatible = manifest.engine_problem(engine_version)
    if incompatible:
        raise PackVerifyError(Problem.INCOMPATIBLE, incompatible)
    trust = _trust(
        files, manifest, manifest_sha,
        trusted=trusted, approved=approved, allow_unsigned=allow_unsigned,
    )
    problems = _checksum_problems(files, manifest)
    if problems:
        raise PackVerifyError(Problem.INVALID, "checksum: " + "; ".join(problems))

    license_note = ""
    if manifest.classification is PackClassification.COMMERCIAL and require_license:
        lic = check_license(manifest.pack_id, manifest.publisher, trusted, today)
        if not lic.ok:
            raise PackVerifyError(Problem.LICENSE, f"license: {lic.reason}")
        license_note = lic.reason

    try:
        vocabulary = _vocabulary_for(manifest)
    except VocabularyError as exc:
        raise PackVerifyError(Problem.INVALID, f"vocabulary: {exc}") from None
    catalogue = _load_rules(files, manifest, vocabulary)

    rule_ids = {r.id for r in catalogue.rules}
    groups: list[ReportGroup] = []
    for group, ids in manifest.report_groups.items():
        unknown = [i for i in ids if i not in rule_ids]
        if unknown:
            raise PackVerifyError(
                Problem.INVALID, f"report group {group!r} names unknown rule(s) {unknown}"
            )
        groups.append(ReportGroup(pack=manifest.pack_id, group=group, rule_ids=tuple(ids)))

    return VerifiedPack(
        manifest=manifest,
        manifest_sha256=manifest_sha,
        trust=trust,
        catalogue=catalogue,
        groups=groups,
        license_note=license_note,
    )
