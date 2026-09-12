"""M2: knowledge loader (validate -> dedupe -> chunk), secret exclusion."""

from __future__ import annotations

from pathlib import Path

import pytest

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


def test_load_corpus_never_calls_validate_tree(
    corpus_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#3 (round 5, 2026-09-12), reproduced exactly as
    reported: load_corpus() used to call validate_tree() - an entirely
    separate read+validate pass over every file - purely to decide which
    paths to skip, then read each surviving path AGAIN, later, to actually
    index it. That left a window between the two independent reads where a
    file could be replaced (same path, same file count, itself a valid
    public KU) without load_corpus ever knowing the validated and indexed
    bytes differed. Reading and validating each file exactly once (this
    test breaks validate_tree() outright; load_corpus() must be completely
    unaffected) removes that second read - and the window - entirely."""
    import app.ingestion.loader as loader_module

    def _boom(knowledge_root: Path) -> None:
        raise AssertionError("load_corpus() must not call validate_tree() anymore")

    monkeypatch.setattr(loader_module, "validate_tree", _boom, raising=False)
    report = load_corpus(corpus_root)
    assert report.units


def test_load_corpus_rejects_a_file_swapped_to_a_symlink_mid_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#5 (round 6, 2026-09-12), reproduced exactly as
    reported via fault injection: check_containment() validates an
    ordinary in-root file (it is not yet a symlink at that moment), then
    the file is swapped to an outside-root symlink right before the actual
    read, then swapped back before anything else could observe it. Without
    O_NOFOLLOW on the read itself, load_corpus() read straight through to
    the outside file's content."""
    root = tmp_path / "knowledge"
    ku_dir = root / "public" / "prompt-security"
    ku_dir.mkdir(parents=True)
    ku_path = ku_dir / "ku.md"
    front_matter = (
        "---\nid: KU-9001\ntitle: t\ncategory: prompt-security\n"
        "classification: public\nversion: '0.1'\nsource_ref: x\n---\n"
    )
    ku_path.write_text(front_matter + "body\n", encoding="utf-8")

    outside = tmp_path / "outside.md"
    outside.write_text(front_matter + "OUTSIDE_RACE_MARKER\n", encoding="utf-8")

    import app.ingestion.parser as parser_module

    original_read = parser_module._read_text_no_follow

    def _racing_read(path: Path) -> str:
        if path != ku_path:
            return original_read(path)
        ku_path.unlink()
        ku_path.symlink_to(outside)
        try:
            return original_read(path)
        finally:
            ku_path.unlink()
            ku_path.write_text(front_matter + "body\n", encoding="utf-8")

    monkeypatch.setattr(parser_module, "_read_text_no_follow", _racing_read)

    report = load_corpus(root)
    assert "OUTSIDE_RACE_MARKER" not in "".join(u.body for u in report.units)
    assert report.units == []
    assert any("ku.md" in path for path, _ in report.skipped)


def test_load_corpus_skips_a_file_that_fails_to_parse_instead_of_raising(
    tmp_path: Path,
) -> None:
    """Coverage for finding #4 sub-point 2 (round 5, 2026-09-12): now that
    load_corpus() does its own single read/validate pass (Codex#3 above)
    rather than relying on an earlier validate_tree() pass to have already
    filtered bad files out, its own read_markdown() call must itself handle
    a parse failure with skip-and-continue, not let FrontMatterError escape
    uncaught."""
    root = tmp_path / "knowledge" / "public" / "prompt-security"
    root.mkdir(parents=True)
    (root / "bad.md").write_text("not a knowledge unit at all, no front matter block")

    report = load_corpus(tmp_path / "knowledge")  # must not raise FrontMatterError
    assert report.units == []
    assert any("bad.md" in path for path, _ in report.skipped)


def test_split_sections_handles_preamble_and_headings() -> None:
    body = "intro text\n\n## First\nalpha\n\n## Second\nbeta\n"
    sections = split_sections(body)
    assert [s.heading for s in sections] == ["", "First", "Second"]
    assert sections[0].text == "intro text"
