"""Knowledge Unit validation (spec Section 10, step 2; decision A1).

``validate_file`` checks one KU file; ``validate_tree`` walks a knowledge root and
adds cross-file checks (duplicate ids). Errors block ingestion; warnings do not.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path

from pydantic import ValidationError

from app.ingestion.parser import FrontMatterError, read_markdown, split_front_matter
from app.ingestion.snapshot import snapshot_tree
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


def check_containment(path: Path, knowledge_root: Path) -> ValidationIssue | None:
    """The symlink / outside-root check (decision A1 / Codex cross-review
    finding #2, 2026-09-11), split out from ``validate_file`` so a caller
    that reads file content exactly once (``load_corpus``, Codex#3 round 5,
    2026-09-12) can run this pre-read check itself instead of going through
    ``validate_file``'s own separate ``read_markdown`` call. Checked BEFORE
    reading any content. A symlinked file is rejected outright regardless of
    where it points (it could resolve to an in-root file with a DIFFERENT
    declared classification, which the directory check below cannot catch
    since it trusts the resolved target's own front matter). A file whose
    real (resolved) location is outside the root is rejected too."""
    if path.is_symlink():
        return ValidationIssue(
            Level.ERROR,
            "symlink-not-allowed",
            "Knowledge Unit files must be plain files, not symlinks (a symlink "
            "can point outside the knowledge root or at a differently "
            "classified file)",
            str(path),
        )
    if _relative_posix(path, knowledge_root) is None:
        return ValidationIssue(
            Level.ERROR,
            "outside-root",
            f"file is not under the knowledge root {knowledge_root}",
            str(path),
        )
    return None


def validate_content(
    path: Path,
    knowledge_root: Path,
    front_matter: dict[str, object],
    body: str,
) -> tuple[list[ValidationIssue], KnowledgeUnitFrontMatter | None]:
    """Validate ALREADY-READ front matter/body for one file at ``path``.

    Split out of ``validate_file`` (Codex#3, round 5, 2026-09-12) so
    ``load_corpus`` can validate the exact same read it uses to build the
    ``LoadedUnit`` from, instead of ``validate_file``'s own separate
    ``read_markdown`` call - closing the TOCTOU window between "the file
    that was validated" and "the file that was indexed". Returns the
    validated model too, so a caller does not need to parse it a second
    time; a schema failure returns ``(issues, None)``. Assumes
    ``check_containment`` has already passed for ``path``.
    """
    issues: list[ValidationIssue] = []
    location = str(path)

    try:
        model = KnowledgeUnitFrontMatter.model_validate(front_matter)
    except ValidationError as exc:
        for err in exc.errors():
            loc = ".".join(str(part) for part in err["loc"]) or "<root>"
            issues.append(
                ValidationIssue(Level.ERROR, "schema", f"{loc}: {err['msg']}", location)
            )
        return issues, None

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
        return issues, None

    # containment was already enforced by the caller (hard error, before any
    # read); rel is guaranteed non-None here.
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

    return issues, model


def validate_file(path: Path, knowledge_root: Path) -> list[ValidationIssue]:
    contain_issue = check_containment(path, knowledge_root)
    if contain_issue is not None:
        return [contain_issue]

    try:
        front_matter, body = read_markdown(path)
    except FrontMatterError as exc:
        return [ValidationIssue(Level.ERROR, "front-matter", str(exc), str(path))]

    issues, _ = validate_content(path, knowledge_root, front_matter, body)
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
    # Codex cross-review finding #4 (2026-09-11): a missing/non-directory root
    # used to produce zero issues (rglob on it silently yields nothing) - a
    # "clean" validation result. reindex_atomic() treats "no ERROR-level
    # issues" as the green light to build and swap in the index, so a typo'd
    # or unmounted knowledge root would replace a real index with an empty one
    # that still passes integrity checking (0 chunks is internally consistent).
    if not knowledge_root.is_dir():
        return [
            ValidationIssue(
                Level.ERROR,
                "missing-root",
                f"knowledge root does not exist or is not a directory: {knowledge_root}",
                str(knowledge_root),
            )
        ]

    # Codex#10 (round 11, 2026-09-13), reproduced exactly as reported: this
    # used to walk `knowledge_root` LIVE via `iter_knowledge_files()`'s own
    # `rglob()`, then read each clean file a SECOND time below (this loop's
    # own `read_markdown()` call, for the duplicate-id check) after
    # `validate_file()` had already read it once for content validation -
    # two independent reads of the same externally-mutable path, each
    # protected only against a swapped FINAL component
    # (`check_containment()` / O_NOFOLLOW), never an ancestor directory
    # swapped to an outside-root symlink between `check_containment()`
    # succeeding and either read actually happening. Snapshotting first -
    # the same directory-fd, no-follow-at-every-level walk every other
    # loader already uses (`app/ingestion/snapshot.py`) - removes the live,
    # externally-mutable tree from the read path entirely, and reading each
    # file's front matter/body exactly once (reused for both content
    # validation and the duplicate-id check, the same restructuring
    # `load_corpus()` got in round 5) removes the second read outright.
    # Issue paths are rewritten from the snapshot prefix back to the
    # `knowledge_root` prefix actually passed in, so callers never see the
    # ephemeral temp directory path.
    try:
        snapshot_root = snapshot_tree(knowledge_root)
    except OSError as exc:
        return [
            ValidationIssue(
                Level.ERROR,
                "snapshot-failed",
                f"could not safely read the knowledge root: {exc}",
                str(knowledge_root),
            )
        ]

    try:
        issues: list[ValidationIssue] = []
        seen_ids: dict[str, str] = {}

        for snap_path in iter_knowledge_files(snapshot_root):
            location = str(knowledge_root / snap_path.relative_to(snapshot_root))

            contain_issue = check_containment(snap_path, snapshot_root)
            if contain_issue is not None:
                issues.append(replace(contain_issue, path=location))
                continue

            try:
                front_matter, body = read_markdown(snap_path)
            except FrontMatterError as exc:
                issues.append(
                    ValidationIssue(Level.ERROR, "front-matter", str(exc), location)
                )
                continue

            file_issues, model = validate_content(snap_path, snapshot_root, front_matter, body)
            file_issues = [replace(issue, path=location) for issue in file_issues]
            issues.extend(file_issues)

            if model is None or any(issue.level is Level.ERROR for issue in file_issues):
                continue

            ku_id = model.id
            if ku_id in seen_ids:
                issues.append(
                    ValidationIssue(
                        Level.ERROR,
                        "duplicate-id",
                        f"id '{ku_id}' is already used by {seen_ids[ku_id]}",
                        location,
                    )
                )
            else:
                seen_ids[ku_id] = location

        return issues
    finally:
        shutil.rmtree(snapshot_root, ignore_errors=True)
