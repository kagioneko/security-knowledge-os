"""The operator's local pack decisions: ``<config dir>/packs.yaml``.

    enabled:            # operator-trusted packs, pinned to one manifest
      mcp: <manifest sha256>
    disabled: [other]   # packs switched off even though they are trusted

The config dir is ``$SKOS_CONFIG_DIR`` or ``~/.config/skos``.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Annotated

import yaml
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from app.ingestion.parser import FrontMatterError, read_text_bounded, safe_load_bounded
from app.safe_errors import format_validation_error

_MAX_CONFIG_BYTES = 64_000
_Name = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9]{1,15}$")]
_Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class PackConfigError(ValueError):
    """``packs.yaml`` is unreadable or malformed."""


class PackConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: dict[_Name, _Sha256] = Field(default_factory=dict, max_length=200)
    disabled: list[_Name] = Field(default_factory=list, max_length=200)


def config_dir() -> Path:
    override = os.environ.get("SKOS_CONFIG_DIR")
    if override:
        return Path(override)
    return Path.home() / ".config" / "skos"


def _config_path() -> Path:
    return config_dir() / "packs.yaml"


def load_config() -> PackConfig:
    path = _config_path()
    if not path.exists():
        return PackConfig()
    try:
        raw = safe_load_bounded(
            read_text_bounded(path, max_bytes=_MAX_CONFIG_BYTES, what="packs.yaml"),
            max_bytes=_MAX_CONFIG_BYTES,
            what="packs.yaml",
        )
    except (OSError, FrontMatterError) as exc:
        raise PackConfigError(f"{path}: {exc}") from None
    if raw is None:
        return PackConfig()
    try:
        return PackConfig.model_validate(raw)
    except ValidationError as exc:
        raise PackConfigError(f"{path}: {format_validation_error(exc)}") from None


def save_config(config: PackConfig) -> Path:
    """Write atomically, owner-only (0700 dir / 0600 file)."""
    path = _config_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    text = yaml.safe_dump(config.model_dump(), sort_keys=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".packs-", suffix=".yaml")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return path
