"""The Update Pack manifest (``manifest.json``) and the pack's file layout -
docs/pack-schema.md, following the Update Pack / Distribution spec v0.1."""

from __future__ import annotations

import re
from datetime import date
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from app.models.pack import PackClassification
from app.reviewer.facts import FactType

PACK_API = 1

MANIFEST_FILE = "manifest.json"
SIGNATURE_FILE = "signature.sig"
CHECKSUMS_FILE = "checksums.sha256"
# Files outside the manifest's own `files` map: the manifest itself, its
# signature, and the checksum list derived from `files`.
UNHASHED_FILES = frozenset({MANIFEST_FILE, SIGNATURE_FILE, CHECKSUMS_FILE})

# Pack API 1 carries data only. Anything else - in particular any executable
# or script - is refused at inspect time, before a byte is written to disk.
_ALLOWED_TOP_FILES = frozenset({"changelog.md", "LICENSE.txt", "README.md"}) | UNHASHED_FILES
_RULE_FILE = r"^rules/[A-Za-z0-9_-]{1,64}\.yaml$"

_PackId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9]{1,15}$")]
_Ident = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
_Prose = Annotated[str, StringConstraints(min_length=1, max_length=500)]
_Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
_RuleId = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*-\d{3,}$")]
_EngineVersion = Annotated[str, StringConstraints(pattern=r"^\d{1,4}\.\d{1,4}\.\d{1,4}$")]
# YYYY.MM.PATCH (spec section 10)
_PackVersion = Annotated[str, StringConstraints(pattern=r"^\d{4}\.(0[1-9]|1[0-2])\.\d{1,4}$")]


def allowed_pack_path(path: str) -> bool:
    return path in _ALLOWED_TOP_FILES or re.fullmatch(_RULE_FILE, path) is not None


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


class FactDecl(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    type: FactType
    values: list[_Ident] | None = Field(default=None, min_length=1, max_length=50)


class PackManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    pack_api: Literal[1]
    pack_id: _PackId
    name: _Prose
    version: _PackVersion
    release_date: date
    min_engine_version: _EngineVersion
    max_engine_version: _EngineVersion | None = None
    classification: PackClassification
    publisher: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9-]{1,31}$")]
    license: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9.+-]{1,100}$")]
    description: _Prose
    changelog: Literal["changelog.md"] | None = None
    facts: dict[_Ident, FactDecl] = Field(default_factory=dict, max_length=200)
    evidence: dict[_Ident, _Prose] = Field(default_factory=dict, max_length=100)
    questions: dict[_Ident, _Prose] = Field(default_factory=dict, max_length=200)
    report_groups: dict[_Ident, list[_RuleId]] = Field(default_factory=dict, max_length=20)
    hash_algorithm: Literal["sha256"] = "sha256"
    files: dict[str, _Sha256] = Field(max_length=2_000)

    @model_validator(mode="after")
    def _consistent(self) -> PackManifest:
        for path in self.files:
            if path in UNHASHED_FILES or not allowed_pack_path(path):
                raise ValueError(
                    "'files' may list only rules/*.yaml, changelog.md, LICENSE.txt and README.md"
                )
        if not any(path.startswith("rules/") for path in self.files):
            raise ValueError("a pack must contain at least one rules/*.yaml file")
        if self.changelog is not None and self.changelog not in self.files:
            raise ValueError("'changelog' names a file that is not in 'files'")
        for decl_name, decl in self.facts.items():
            if decl.values is not None and decl.type is not FactType.STR:
                raise ValueError(f"fact {decl_name!r}: 'values' is only valid for a str fact")
        if self.max_engine_version is not None and version_key(
            self.max_engine_version
        ) < version_key(self.min_engine_version):
            raise ValueError("max_engine_version is lower than min_engine_version")
        return self

    @property
    def rule_prefix(self) -> str:
        return f"{self.pack_id.upper()}-"

    def engine_problem(self, engine_version: str) -> str | None:
        current = version_key(engine_version)
        if current < version_key(self.min_engine_version):
            return f"needs engine >= {self.min_engine_version} (this is {engine_version})"
        if self.max_engine_version and current > version_key(self.max_engine_version):
            return f"needs engine <= {self.max_engine_version} (this is {engine_version})"
        return None


def checksums_text(files: dict[str, str]) -> str:
    """``sha256sum``-compatible listing of every hashed file."""
    return "".join(f"{sha}  {path}\n" for path, sha in sorted(files.items()))
