"""The pack manifest (``pack.yaml``) schema - docs/pack-schema.md."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from app.models.pack import PackTier
from app.reviewer.facts import FactType

PACK_API = 1

MANIFEST_FILE = "pack.yaml"
SIGNATURE_FILE = "pack.sig"
RESERVED_FILES = frozenset({MANIFEST_FILE, SIGNATURE_FILE})

_Name = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9]{1,15}$")]
_Ident = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
_Prose = Annotated[str, StringConstraints(min_length=1, max_length=500)]
# A relative path inside the pack directory: plain segments only, no "..",
# no leading "/" or ".", no backslashes.
_RelPath = Annotated[
    str,
    StringConstraints(
        pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}(/[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}){0,15}$",
    ),
]
_Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
_RuleId = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*-\d{3,}$")]
_Command = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}(\.[a-z][a-z0-9_]{0,63}){1,4}:[a-z_][a-z0-9_]{0,63}$"),
]


class FactDecl(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    type: FactType
    values: list[_Ident] | None = Field(default=None, min_length=1, max_length=50)


class PackManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    pack_api: Literal[1]
    name: _Name
    version: Annotated[
        str, StringConstraints(pattern=r"^\d{1,4}\.\d{1,4}\.\d{1,4}([.-][0-9A-Za-z.]{1,32})?$")
    ]
    tier: PackTier
    publisher: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9-]{1,31}$")]
    license: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9.+-]{1,100}$")]
    description: _Prose
    facts: dict[_Ident, FactDecl] = Field(default_factory=dict, max_length=200)
    evidence: dict[_Ident, _Prose] = Field(default_factory=dict, max_length=100)
    questions: dict[_Ident, _Prose] = Field(default_factory=dict, max_length=200)
    report_groups: dict[_Ident, list[_RuleId]] = Field(default_factory=dict, max_length=20)
    commands: dict[_Ident, _Command] = Field(default_factory=dict, max_length=20)
    files: dict[_RelPath, _Sha256] = Field(max_length=2_000)

    @model_validator(mode="after")
    def _consistent(self) -> PackManifest:
        for path in self.files:
            if path in RESERVED_FILES or any(seg == ".." for seg in path.split("/")):
                raise ValueError("'files' must not list pack.yaml, pack.sig or '..' segments")
        for decl_name, decl in self.facts.items():
            if decl.values is not None and decl.type is not FactType.STR:
                raise ValueError(f"fact {decl_name!r}: 'values' is only valid for a str fact")
        for command in self.commands.values():
            if command.split(".", 1)[0] != self.package:
                raise ValueError("every command must live inside the pack's own package")
        return self

    @property
    def package(self) -> str:
        """The import package the pack's code lives in (``skos_pack_<name>``)."""
        return f"skos_pack_{self.name}"

    @property
    def rule_prefix(self) -> str:
        return f"{self.name.upper()}-"
