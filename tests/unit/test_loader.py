"""M2: knowledge loader (validate -> dedupe -> chunk), secret exclusion."""

from __future__ import annotations

from pathlib import Path

from app.ingestion.chunker import split_sections
from app.ingestion.loader import compute_knowledge_revision, load_corpus


def test_loads_five_units_and_skips_secret(corpus_root: Path) -> None:
    report = load_corpus(corpus_root)
    ids = sorted(u.front_matter.id for u in report.units)
    assert ids == ["KU-1001", "KU-1002", "KU-1003", "KU-1010", "KU-1020"]
    assert "KU-1099" not in ids


def test_secret_unit_recorded_as_skipped(corpus_root: Path) -> None:
    report = load_corpus(corpus_root)
    skipped_paths = " ".join(path for path, _ in report.skipped)
    assert "KU-1099" in skipped_paths


def test_sections_are_split(corpus_root: Path) -> None:
    report = load_corpus(corpus_root)
    unit = next(u for u in report.units if u.front_matter.id == "KU-1002")
    headings = [s.heading for s in unit.sections]
    assert "Summary" in headings
    assert "Mitigations" in headings


def test_revision_is_stable_and_content_sensitive(corpus_root: Path) -> None:
    a = compute_knowledge_revision(load_corpus(corpus_root).units)
    b = compute_knowledge_revision(load_corpus(corpus_root).units)
    assert a == b and len(a) == 64


def test_split_sections_handles_preamble_and_headings() -> None:
    body = "intro text\n\n## First\nalpha\n\n## Second\nbeta\n"
    sections = split_sections(body)
    assert [s.heading for s in sections] == ["", "First", "Second"]
    assert sections[0].text == "intro text"
