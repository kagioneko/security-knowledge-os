"""M1 / AC-01: Knowledge Unit schema validation."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.ingestion.parser import read_markdown
from app.ingestion.validator import Level, has_errors, validate_file
from app.models.knowledge import Classification, KnowledgeUnitFrontMatter


def _front_matter(root: Path, rel: str) -> dict:
    data, _ = read_markdown(root / rel)
    return data


def test_valid_public_ku_parses(fixture_knowledge_root: Path) -> None:
    fm = _front_matter(
        fixture_knowledge_root, "public/prompt-security/KU-0001-instruction-hierarchy.md"
    )
    model = KnowledgeUnitFrontMatter.model_validate(fm)
    assert model.id == "KU-0001"
    assert model.classification is Classification.PUBLIC
    assert model.last_reviewed == date(2026, 9, 10)
    assert model.risk_ids == ["PI-001"]


def test_valid_public_ku_has_no_errors(fixture_knowledge_root: Path) -> None:
    # AC-01
    issues = validate_file(
        fixture_knowledge_root / "public/prompt-security/KU-0001-instruction-hierarchy.md",
        fixture_knowledge_root,
    )
    assert not has_errors(issues), issues


def test_valid_internal_ku_has_no_errors(fixture_knowledge_root: Path) -> None:
    issues = validate_file(
        fixture_knowledge_root / "private/internal/KU-0002-internal-note.md",
        fixture_knowledge_root,
    )
    assert not has_errors(issues), issues


@pytest.mark.parametrize(
    "rel",
    ["invalid/bad-id.md", "invalid/missing-fields.md", "invalid/bad-classification.md"],
)
def test_schema_violations_rejected_by_model(fixture_knowledge_root: Path, rel: str) -> None:
    fm = _front_matter(fixture_knowledge_root, rel)
    with pytest.raises(ValidationError):
        KnowledgeUnitFrontMatter.model_validate(fm)


@pytest.mark.parametrize(
    "rel",
    ["invalid/bad-id.md", "invalid/missing-fields.md", "invalid/bad-classification.md"],
)
def test_schema_violations_reported_by_validator(
    fixture_knowledge_root: Path, rel: str
) -> None:
    issues = validate_file(fixture_knowledge_root / rel, fixture_knowledge_root)
    assert any(i.level is Level.ERROR and i.code == "schema" for i in issues), issues


def test_missing_front_matter_is_error(fixture_knowledge_root: Path) -> None:
    issues = validate_file(
        fixture_knowledge_root / "invalid/no-front-matter.md", fixture_knowledge_root
    )
    assert [i.code for i in issues] == ["front-matter"]
    assert issues[0].level is Level.ERROR


def test_missing_recommended_sections_warn_only(fixture_knowledge_root: Path) -> None:
    issues = validate_file(
        fixture_knowledge_root / "public/methodology/KU-0003-sparse.md",
        fixture_knowledge_root,
    )
    assert not has_errors(issues), issues
    assert any(i.code == "missing-section" and i.level is Level.WARNING for i in issues)


def test_version_must_be_string_not_float() -> None:
    base = {
        "id": "KU-0001",
        "title": "x",
        "category": "prompt-security",
        "source_type": "manual",
        "source_ref": "ref",
        "classification": "public",
        "status": "reviewed",
        "risk_ids": [],
        "version": 0.1,
        "last_reviewed": "2026-09-10",
        "requires_ip_review": False,
    }
    with pytest.raises(ValidationError):
        KnowledgeUnitFrontMatter.model_validate(base)


def test_unknown_front_matter_key_rejected() -> None:
    base = {
        "id": "KU-0001",
        "title": "x",
        "category": "prompt-security",
        "source_type": "manual",
        "source_ref": "ref",
        "classification": "public",
        "status": "reviewed",
        "risk_ids": [],
        "version": "0.1",
        "last_reviewed": "2026-09-10",
        "requires_ip_review": False,
        "typo_field": "oops",
    }
    with pytest.raises(ValidationError):
        KnowledgeUnitFrontMatter.model_validate(base)
