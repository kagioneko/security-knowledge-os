"""Offline license check for ``tier: commercial`` packs.

    <config dir>/licenses/<pack>.lic       JSON, see LicenseFile
    <config dir>/licenses/<pack>.lic.sig   Ed25519 by the pack's publisher

Nothing here contacts a network service. Rules shipped as YAML are readable
by whoever installs them, so this identifies a legitimate customer; it does
not prevent copying (docs/pack-schema.md, "Commercial tier").
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from app.packs.signing import (
    LICENSE_DOMAIN,
    SignatureError,
    TrustedKey,
    parse_signature_file,
    verify,
)

_MAX_LICENSE_BYTES = 16_000


def config_dir() -> Path:
    """``$SKOS_CONFIG_DIR`` or ``~/.config/skos``; licenses live in ``licenses/``."""
    override = os.environ.get("SKOS_CONFIG_DIR")
    return Path(override) if override else Path.home() / ".config" / "skos"


class LicenseFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    license_id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9-]{1,64}$")]
    licensee: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    packs: list[Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9]{1,15}$")]] = Field(
        min_length=1, max_length=50
    )
    issued: date
    expires: date


@dataclass(frozen=True)
class LicenseCheck:
    ok: bool
    reason: str  # "licensed to <licensee> until <date>" or why not
    license: LicenseFile | None = None


def _read_bounded(path_name: str, limit: int) -> bytes | None:
    path = config_dir() / "licenses" / path_name
    try:
        with path.open("rb") as fh:
            data = fh.read(limit + 1)
    except FileNotFoundError:
        return None
    if len(data) > limit:
        raise SignatureError(f"{path_name} is too large")
    return data


def check_license(
    pack: str, publisher: str, trusted: dict[str, TrustedKey], today: date
) -> LicenseCheck:
    try:
        raw = _read_bounded(f"{pack}.lic", _MAX_LICENSE_BYTES)
        sig_raw = _read_bounded(f"{pack}.lic.sig", 4_096)
    except (OSError, SignatureError) as exc:
        return LicenseCheck(False, f"license unreadable ({type(exc).__name__})")
    if raw is None:
        return LicenseCheck(False, "no license file")
    if sig_raw is None:
        return LicenseCheck(False, "license is not signed")
    try:
        verify(LICENSE_DOMAIN, raw, parse_signature_file(sig_raw), trusted, publisher=publisher)
    except SignatureError as exc:
        return LicenseCheck(False, f"license signature: {exc}")
    try:
        lic = LicenseFile.model_validate(json.loads(raw.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError):
        return LicenseCheck(False, "license file is malformed")
    if pack not in lic.packs:
        return LicenseCheck(False, "license does not cover this pack")
    if today < lic.issued:
        return LicenseCheck(False, "license is not yet valid")
    if today > lic.expires:
        return LicenseCheck(False, f"license expired on {lic.expires.isoformat()}")
    return LicenseCheck(True, f"licensed until {lic.expires.isoformat()}", lic)
