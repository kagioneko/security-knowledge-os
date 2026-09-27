"""Pack provenance recorded on every assessment result (docs/pack-schema.md)."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.models.risk import FindingStatus


class PackTier(StrEnum):
    FREE = "free"
    COMMERCIAL = "commercial"


class PackTrust(StrEnum):
    SIGNED = "signed"              # signature verified against a built-in publisher key
    USER_ENABLED = "user-enabled"  # the operator enabled this exact manifest


class AppliedPack(BaseModel):
    """A pack whose rules took part in an assessment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    version: str
    tier: PackTier
    publisher: str
    trust: PackTrust
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ReportGroup(BaseModel):
    """A named group of rule ids declared by a pack, e.g. ``mcp`` / ``exposure``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pack: str
    group: str
    rule_ids: tuple[str, ...]


class GroupSummary(BaseModel):
    """Per-group roll-up: the worst finding status among the group's rules
    (``None`` when none of them produced a finding) and how many did."""

    model_config = ConfigDict(extra="forbid")

    pack: str
    group: str
    worst_status: FindingStatus | None = None
    finding_count: int = 0
