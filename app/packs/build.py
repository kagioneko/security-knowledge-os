"""Publisher-side helpers: hash a pack's files into its manifest, sign the
manifest, and issue license files. Used by scripts/sign_pack.py and
scripts/issue_license.py, and by the tests. Private keys are passed in by the
caller (read from Vault/stdin); nothing here stores one.

The manifest's ``files:`` mapping must be its LAST top-level key: it is
regenerated in place, which keeps every comment above it intact.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from datetime import date
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.packs.manifest import MANIFEST_FILE, RESERVED_FILES, SIGNATURE_FILE
from app.packs.signing import LICENSE_DOMAIN, MANIFEST_DOMAIN, signature_file_bytes

_IGNORED_DIRS = {"__pycache__"}


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


def file_hashes(pack_dir: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(pack_dir):
        dirnames[:] = sorted(d for d in dirnames if d not in _IGNORED_DIRS)
        for name in sorted(filenames):
            full = Path(dirpath) / name
            if full.is_symlink():
                raise BuildError(f"symlink in pack: {full.relative_to(pack_dir)}")
            rel = full.relative_to(pack_dir).as_posix()
            if rel in RESERVED_FILES:
                continue
            hashes[rel] = hashlib.sha256(full.read_bytes()).hexdigest()
    return dict(sorted(hashes.items()))


def update_manifest_files(pack_dir: Path) -> bytes:
    """Rewrite the trailing ``files:`` block of ``pack.yaml`` with the current
    hashes; returns the new manifest bytes."""
    path = pack_dir / MANIFEST_FILE
    lines = path.read_text(encoding="utf-8").splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.startswith("files:"))
    except StopIteration:
        start = len(lines)
    for line in lines[start + 1 :]:
        if line and not line.startswith((" ", "#")):
            raise BuildError("'files:' must be the last top-level key in pack.yaml")
    block = ["files:"] + [f"  {rel}: {sha}" for rel, sha in file_hashes(pack_dir).items()]
    data = ("\n".join(lines[:start] + block) + "\n").encode("utf-8")
    path.write_bytes(data)
    return data


def sign_manifest(pack_dir: Path, key: Ed25519PrivateKey, key_id: str) -> None:
    manifest = (pack_dir / MANIFEST_FILE).read_bytes()
    signature = key.sign(MANIFEST_DOMAIN + manifest)
    (pack_dir / SIGNATURE_FILE).write_bytes(signature_file_bytes(key_id, signature))


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
