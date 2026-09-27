"""Publisher-side tooling (Update Pack spec sections 19-20): build a pack ZIP
from a source directory, sign it, and issue license files.

The ZIP is reproducible: entries are sorted, timestamps and permissions are
fixed, and the manifest is written canonically - the same source and key
always give the same bytes. Private keys are passed in by the caller (read
from Vault via stdin); nothing here stores one.

Source directory layout (everything else is refused):

    manifest.json        without `files` (it is generated)
    rules/*.yaml
    changelog.md, LICENSE.txt, README.md   (optional)
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import os
import zipfile
from datetime import date
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.packs.manifest import (
    CHECKSUMS_FILE,
    MANIFEST_FILE,
    SIGNATURE_FILE,
    UNHASHED_FILES,
    allowed_pack_path,
    checksums_text,
)
from app.packs.signing import LICENSE_DOMAIN, MANIFEST_DOMAIN, signature_file_bytes
from app.packs.verify import PackVerifyError, parse_manifest

_FIXED_TIME = (1980, 1, 1, 0, 0, 0)


class BuildError(ValueError):
    pass


def private_key_from_b64(text: str) -> Ed25519PrivateKey:
    try:
        seed = base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise BuildError("private key is not valid base64") from None
    if len(seed) != 32:
        raise BuildError("an Ed25519 private key seed is 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def _source_files(src: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for name in sorted(filenames):
            if name.startswith("."):
                continue
            full = Path(dirpath) / name
            rel = full.relative_to(src).as_posix()
            if full.is_symlink():
                raise BuildError(f"symlink in pack source: {rel}")
            if rel in UNHASHED_FILES - {MANIFEST_FILE}:
                continue  # generated
            if not allowed_pack_path(rel):
                raise BuildError(f"{rel}: not allowed in a pack (data files only)")
            files[rel] = full.read_bytes()
    if MANIFEST_FILE not in files:
        raise BuildError("manifest.json is missing from the pack source")
    return files


def build_pack(
    src: Path,
    out_dir: Path,
    *,
    version: str | None = None,
    key: Ed25519PrivateKey | None = None,
    key_id: str | None = None,
) -> Path:
    """Write ``<out_dir>/<pack_id>-<version>.zip`` and return its path."""
    files = _source_files(src)
    try:
        manifest = json.loads(files.pop(MANIFEST_FILE).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise BuildError("manifest.json is not valid UTF-8 JSON") from None
    if not isinstance(manifest, dict):
        raise BuildError("manifest.json must be an object")
    if version is not None:
        manifest["version"] = version
    manifest["files"] = {
        rel: hashlib.sha256(data).hexdigest() for rel, data in sorted(files.items())
    }
    manifest_bytes = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    entries = dict(files)
    entries[MANIFEST_FILE] = manifest_bytes
    entries[CHECKSUMS_FILE] = checksums_text(manifest["files"]).encode("utf-8")
    if key is not None:
        if not key_id:
            raise BuildError("a key id is required to sign")
        signature = key.sign(MANIFEST_DOMAIN + manifest_bytes)
        entries[SIGNATURE_FILE] = signature_file_bytes(key_id, signature)
    try:
        parsed, _ = parse_manifest(entries)
    except PackVerifyError as exc:
        raise BuildError(str(exc)) from None

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel in sorted(entries):
            info = zipfile.ZipInfo(rel, date_time=_FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            zf.writestr(info, entries[rel])
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{parsed.pack_id}-{parsed.version}.zip"
    out.write_bytes(buf.getvalue())
    return out


def issue_license(
    out_dir: Path,
    *,
    pack: str,
    license_id: str,
    licensee: str,
    issued: date,
    expires: date,
    key: Ed25519PrivateKey,
    key_id: str,
) -> Path:
    body = (
        json.dumps(
            {
                "license_id": license_id,
                "licensee": licensee,
                "packs": [pack],
                "issued": issued.isoformat(),
                "expires": expires.isoformat(),
            },
            indent=2,
        )
        + "\n"
    ).encode("utf-8")
    out_dir.mkdir(parents=True, exist_ok=True)
    lic = out_dir / f"{pack}.lic"
    lic.write_bytes(body)
    (out_dir / f"{pack}.lic.sig").write_bytes(
        signature_file_bytes(key_id, key.sign(LICENSE_DOMAIN + body))
    )
    return lic
