"""Load a knowledge root into validated, chunked units (spec Section 10, steps 1-6).

Units with validation ERRORs are skipped and recorded. Secret-classified units are
skipped by defence in depth even if validation somehow passed.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from app.ingestion.chunker import Section, split_sections
from app.ingestion.parser import read_markdown
from app.ingestion.validator import (
    Level,
    ValidationIssue,
    iter_knowledge_files,
    validate_tree,
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
    report = LoadReport(issues=validate_tree(knowledge_root))

    errors_by_path: dict[str, list[str]] = defaultdict(list)
    for issue in report.issues:
        if issue.level is Level.ERROR:
            errors_by_path[issue.path].append(f"{issue.code}: {issue.message}")

    seen_ids: set[str] = set()
    for md_path in iter_knowledge_files(knowledge_root):
        location = str(md_path)
        if location in errors_by_path:
            report.skipped.append((location, "; ".join(errors_by_path[location])))
            continue

        front_matter_dict, body = read_markdown(md_path)
        front_matter = KnowledgeUnitFrontMatter.model_validate(front_matter_dict)

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
