"""M7: the shipped public Knowledge corpus (MVP DoD: >= 12 reviewed public KUs)."""

from __future__ import annotations

from pathlib import Path

from app.ingestion.loader import load_corpus
from app.ingestion.validator import has_errors, validate_tree
from app.models.knowledge import Classification, KnowledgeStatus

KNOWLEDGE = Path(__file__).resolve().parents[2] / "knowledge"


def test_corpus_validates_clean() -> None:
    issues = validate_tree(KNOWLEDGE)
    assert not has_errors(issues), issues
    assert not issues, f"warnings: {issues}"


def test_at_least_12_reviewed_public_units() -> None:
    report = load_corpus(KNOWLEDGE)
    public_reviewed = [
        u
        for u in report.units
        if u.front_matter.classification is Classification.PUBLIC
        and u.front_matter.status is KnowledgeStatus.REVIEWED
    ]
    assert len(public_reviewed) >= 12, [u.front_matter.id for u in public_reviewed]


def test_every_unit_is_public() -> None:
    report = load_corpus(KNOWLEDGE)
    assert all(
        u.front_matter.classification is Classification.PUBLIC for u in report.units
    )


def test_every_unit_cites_a_source() -> None:
    report = load_corpus(KNOWLEDGE)
    for u in report.units:
        assert u.front_matter.source_ref.strip()
        assert u.front_matter.source_type.value in {"standard", "note", "github", "manual"}


def test_rule_knowledge_refs_resolve(catalogue) -> None:
    report = load_corpus(KNOWLEDGE)
    ku_ids = {u.front_matter.id for u in report.units}
    for rule in catalogue.rules:
        for ref in rule.knowledge_refs:
            assert ref in ku_ids, f"{rule.id} references missing {ref}"
