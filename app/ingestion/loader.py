"""Load a knowledge root into validated, chunked units (spec Section 10, steps 1-6).

Units with validation ERRORs are skipped and recorded. Secret-classified units are
skipped by defence in depth even if validation somehow passed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from app.ingestion.chunker import Section, split_sections
from app.ingestion.parser import FrontMatterError, read_markdown
from app.ingestion.validator import (
    Level,
    ValidationIssue,
    check_containment,
    iter_knowledge_files,
    validate_content,
)
from app.models.knowledge import KnowledgeUnitFrontMatter
from app.policy.classification import PolicyBlocked, assert_indexable


@dataclass(frozen=True)
class LoadedUnit:
    front_matter: KnowledgeUnitFrontMatter
    body: str
    source_path: str
    sections: list[Section]


@dataclass
class LoadReport:
    units: list[LoadedUnit] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def warning_count(self) -> int:
        return sum(1 for issue in self.issues if issue.level is Level.WARNING)


def load_corpus(knowledge_root: Path) -> LoadReport:
    """Codex#3 (round 5, 2026-09-12), reproduced exactly as reported: this
    used to call ``validate_tree()`` - a full separate read+validate pass
    over every file - purely to decide which paths to skip, then read each
    surviving path AGAIN below to actually build it. A file replaced between
    those two reads (same path, same total file count, itself a valid
    public KU) passed the first read's validation and was indexed from the
    SECOND read's different, attacker-controlled content - this function had
    no way to know the two reads disagreed. Reading and validating each file
    exactly once removes that window entirely: there is no earlier read left
    to diverge from.
    """
    report = LoadReport()
    seen_ids: set[str] = set()

    for md_path in iter_knowledge_files(knowledge_root):
        location = str(md_path)

        contain_issue = check_containment(md_path, knowledge_root)
        if contain_issue is not None:
            report.issues.append(contain_issue)
            report.skipped.append(
                (location, f"{contain_issue.code}: {contain_issue.message}")
            )
            continue

        try:
            front_matter_dict, body = read_markdown(md_path)
        except FrontMatterError as exc:
            # Codex#3 / finding #4 sub-point 2 (round 5, 2026-09-12): a file
            # that validated cleanly earlier but was changed to something
            # unparseable by the time this read runs (TOCTOU) used to raise
            # here uncaught instead of the same skip-and-continue treatment
            # every other per-file problem gets.
            report.issues.append(ValidationIssue(Level.ERROR, "front-matter", str(exc), location))
            report.skipped.append((location, f"front-matter: {exc}"))
            continue

        issues, front_matter = validate_content(md_path, knowledge_root, front_matter_dict, body)
        report.issues.extend(issues)
        errors = [i for i in issues if i.level is Level.ERROR]
        if front_matter is None or errors:
            report.skipped.append(
                (location, "; ".join(f"{i.code}: {i.message}" for i in errors))
            )
            continue

        try:
            assert_indexable(front_matter.classification)
        except PolicyBlocked as exc:
            report.skipped.append((location, str(exc)))
            continue

        if front_matter.id in seen_ids:
            report.skipped.append((location, f"duplicate id {front_matter.id}"))
            continue
        seen_ids.add(front_matter.id)

        report.units.append(
            LoadedUnit(front_matter, body, location, split_sections(body))
        )

    return report


def compute_knowledge_revision(units: list[LoadedUnit]) -> str:
    digest = hashlib.sha256()
    for unit in sorted(units, key=lambda u: u.front_matter.id):
        digest.update(unit.front_matter.id.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(unit.front_matter.version.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(hashlib.sha256(unit.body.encode("utf-8")).digest())
    return digest.hexdigest()
