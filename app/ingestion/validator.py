"""Knowledge Unit validation (spec Section 10, step 2; decision A1).

``validate_file`` checks one KU file; ``validate_tree`` walks a knowledge root and
adds cross-file checks (duplicate ids). Errors block ingestion; warnings do not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from pydantic import ValidationError

from app.ingestion.parser import FrontMatterError, read_markdown, split_front_matter
from app.models.knowledge import Classification, KnowledgeCategory, KnowledgeUnitFrontMatter
from app.models.risk import RULE_ID_PATTERN
from app.policy.classification import expected_relative_dir

_RULE_ID_RE = re.compile(RULE_ID_PATTERN)

RECOMMENDED_SECTIONS: tuple[str, ...] = (
    "Summary",
    "Conditions",
    "Risk",
    "Evidence",
    "Failure Mode",
    "Detection Clues",
    "Mitigations",
    "Safe Test",
    "Limitations",
    "Related Knowledge",
)

CATEGORY_DIR: dict[KnowledgeCategory, str] = {
    KnowledgeCategory.PROMPT_SECURITY: "prompt-security",
    KnowledgeCategory.RAG_SECURITY: "rag-security",
    KnowledgeCategory.AGENT_SECURITY: "agent-security",
    KnowledgeCategory.MEMORY_SECURITY: "memory-security",
    KnowledgeCategory.CREDENTIAL_SECURITY: "credential-security",
    KnowledgeCategory.INCIDENT: "incidents",
    KnowledgeCategory.METHODOLOGY: "methodology",
    KnowledgeCategory.GOVERNANCE: "governance",
}


class Level(StrEnum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True)
class ValidationIssue:
    level: Level
    code: str
    message: str
    path: str

    def __str__(self) -> str:
        head = f"[{self.level.upper():7}] {self.code:22} {self.path}"
        return f"{head}\n          {self.message}"


def has_errors(issues: list[ValidationIssue]) -> bool:
    return any(issue.level is Level.ERROR for issue in issues)


def _headings(body: str) -> set[str]:
    found: set[str] = set()
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            found.add(stripped.lstrip("#").strip().casefold())
    return found


def _relative_posix(path: Path, knowledge_root: Path) -> str | None:
    try:
        return path.resolve().relative_to(knowledge_root.resolve()).as_posix()
    except ValueError:
        return None


def validate_markdown(text: str, *, source: str = "<input>") -> list[ValidationIssue]:
    """Validate one Knowledge Unit given as text (no filesystem, no path check).

    Used by the read-only ``POST /v1/knowledge/validate`` endpoint - it never
    writes anything."""
    issues: list[ValidationIssue] = []
    try:
        front_matter, body = split_front_matter(text)
    except FrontMatterError as exc:
        return [ValidationIssue(Level.ERROR, "front-matter", str(exc), source)]

    try:
        model = KnowledgeUnitFrontMatter.model_validate(front_matter)
    except ValidationError as exc:
        for err in exc.errors():
            loc = ".".join(str(part) for part in err["loc"]) or "<root>"
            issues.append(ValidationIssue(Level.ERROR, "schema", f"{loc}: {err['msg']}", source))
        return issues

    if model.classification is Classification.SECRET:
        issues.append(
            ValidationIssue(
                Level.ERROR,
                "secret-in-repo",
                "classification 'secret' must live outside the repository",
                source,
            )
        )
        return issues

    for rid in model.risk_ids:
        if not _RULE_ID_RE.match(rid):
            issues.append(
                ValidationIssue(
                    Level.WARNING, "risk-id-format", f"risk id '{rid}' malformed", source
                )
            )
    present = _headings(body)
    for section in RECOMMENDED_SECTIONS:
        if section.casefold() not in present:
            issues.append(
                ValidationIssue(
                    Level.WARNING, "missing-section", f"'## {section}' is absent", source
                )
            )
    return issues


def validate_file(path: Path, knowledge_root: Path) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    location = str(path)

    # --- containment (decision A1 / Codex cross-review finding #2, 2026-09-11) #
    # Checked BEFORE reading any content. A symlinked file is rejected outright
    # regardless of where it points (it could resolve to an in-root file with a
    # DIFFERENT declared classification, which the directory check below cannot
    # catch since it trusts the resolved target's own front matter). A file
    # whose real (resolved) location is outside the root is rejected too. Both
    # used to be only a WARNING and the file was still loaded into the corpus -
    # a classification/confinement bypass.
    if path.is_symlink():
        return [
            ValidationIssue(
                Level.ERROR,
                "symlink-not-allowed",
                "Knowledge Unit files must be plain files, not symlinks (a symlink "
                "can point outside the knowledge root or at a differently "
                "classified file)",
                location,
            )
        ]
    if _relative_posix(path, knowledge_root) is None:
        return [
            ValidationIssue(
                Level.ERROR,
                "outside-root",
                f"file is not under the knowledge root {knowledge_root}",
                location,
            )
        ]

    try:
        front_matter, body = read_markdown(path)
    except FrontMatterError as exc:
        return [ValidationIssue(Level.ERROR, "front-matter", str(exc), location)]

    try:
        model = KnowledgeUnitFrontMatter.model_validate(front_matter)
    except ValidationError as exc:
        for err in exc.errors():
            loc = ".".join(str(part) for part in err["loc"]) or "<root>"
            issues.append(
                ValidationIssue(Level.ERROR, "schema", f"{loc}: {err['msg']}", location)
            )
        return issues

    # --- classification / location (decision A1) --------------------------- #
    if model.classification is Classification.SECRET:
        issues.append(
            ValidationIssue(
                Level.ERROR,
                "secret-in-repo",
                "classification 'secret' must live outside the repository "
                "(separate root); it is never indexed or sent to an LLM",
                location,
            )
        )
        return issues

    # containment was already enforced above (hard error, before any read); rel
    # is guaranteed non-None here.
    rel = _relative_posix(path, knowledge_root)
    assert rel is not None
    expected = expected_relative_dir(model.classification)
    if not (rel == f"{expected}/{path.name}" or rel.startswith(f"{expected}/")):
        issues.append(
            ValidationIssue(
                Level.ERROR,
                "wrong-directory",
                f"classification '{model.classification.value}' requires a location "
                f"under '{expected}/', found '{rel}'",
                location,
            )
        )
    elif model.classification is Classification.PUBLIC:
        parts = rel.split("/")
        if len(parts) >= 3 and parts[1] != CATEGORY_DIR[model.category]:
            issues.append(
                ValidationIssue(
                    Level.WARNING,
                    "category-dir-mismatch",
                    f"category '{model.category.value}' expects sub-directory "
                    f"'{CATEGORY_DIR[model.category]}/', found '{parts[1]}/'",
                    location,
                )
            )

    # --- risk_ids format -------------------------------------------------- #
    for rid in model.risk_ids:
        if not _RULE_ID_RE.match(rid):
            issues.append(
                ValidationIssue(
                    Level.WARNING,
                    "risk-id-format",
                    f"risk id '{rid}' does not match {RULE_ID_PATTERN}",
                    location,
                )
            )

    # --- recommended body sections -------------------------------------- #
    present = _headings(body)
    for section in RECOMMENDED_SECTIONS:
        if section.casefold() not in present:
            issues.append(
                ValidationIssue(
                    Level.WARNING,
                    "missing-section",
                    f"recommended section '## {section}' is absent",
                    location,
                )
            )

    return issues


# Markdown files that are documentation, not Knowledge Units.
_NON_KU_FILENAMES = {"readme.md", "index.md", "_index.md"}


def iter_knowledge_files(knowledge_root: Path) -> list[Path]:
    return [
        p
        for p in sorted(knowledge_root.rglob("*.md"))
        if p.name.casefold() not in _NON_KU_FILENAMES
    ]


def validate_tree(knowledge_root: Path) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    seen_ids: dict[str, str] = {}

    for md_path in iter_knowledge_files(knowledge_root):
        issues.extend(validate_file(md_path, knowledge_root))
        try:
            front_matter, _ = read_markdown(md_path)
        except FrontMatterError:
            continue
        ku_id = front_matter.get("id")
        if isinstance(ku_id, str):
            if ku_id in seen_ids:
                issues.append(
                    ValidationIssue(
                        Level.ERROR,
                        "duplicate-id",
                        f"id '{ku_id}' is already used by {seen_ids[ku_id]}",
                        str(md_path),
                    )
                )
            else:
                seen_ids[ku_id] = str(md_path)

    return issues
