"""Update Pack provenance recorded on every assessment result
(docs/pack-schema.md)."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.models.risk import FindingStatus


class PackClassification(StrEnum):
    """Who may receive a pack (Update Pack spec section 6). ``secret`` is
    deliberately absent: secret material is never packed."""

    PUBLIC = "public"              # anyone
    COMMERCIAL = "commercial"      # licensees only - a signed license file is required
    INTERNAL = "internal"          # the publisher's own organization
    CONFIDENTIAL = "confidential"  # one customer / engagement - install needs explicit approval


class PackTrust(StrEnum):
    SIGNED = "signed"                        # signature verified against a built-in key
    OPERATOR_APPROVED = "operator-approved"  # unsigned; the operator approved this manifest


class AppliedPack(BaseModel):
    """A pack whose rules took part in an assessment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pack_id: str
    version: str
    classification: PackClassification
    publisher: str
    trust: PackTrust
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SkippedPack(BaseModel):
    """An installed pack that did NOT take part (e.g. its license expired)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pack_id: str
    reason: str


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
