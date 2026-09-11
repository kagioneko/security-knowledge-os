"""M1 / AC-02: classification violations are blocked."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.config import Mode
from app.ingestion.validator import Level, has_errors, validate_file, validate_tree
from app.models.knowledge import Classification
from app.policy.classification import (
    PolicyBlocked,
    assert_indexable,
    expected_relative_dir,
    is_retrievable,
)


def test_secret_ku_in_repo_is_error(fixture_knowledge_root: Path) -> None:
    # AC-02
    issues = validate_file(
        fixture_knowledge_root / "secret/KU-0009-secret.md", fixture_knowledge_root
    )
    assert has_errors(issues)
    assert any(i.code == "secret-in-repo" and i.level is Level.ERROR for i in issues)


def test_validate_tree_flags_secret(fixture_knowledge_root: Path) -> None:
    issues = validate_tree(fixture_knowledge_root)
    assert any(i.code == "secret-in-repo" for i in issues)


def test_assert_indexable_blocks_secret_only() -> None:
    with pytest.raises(PolicyBlocked):
        assert_indexable(Classification.SECRET)
    for classification in (
        Classification.PUBLIC,
        Classification.INTERNAL,
        Classification.CONFIDENTIAL,
    ):
        assert_indexable(classification)  # must not raise


def test_expected_dir_for_secret_raises() -> None:
    with pytest.raises(PolicyBlocked):
        expected_relative_dir(Classification.SECRET)


def test_expected_dir_mapping() -> None:
    assert expected_relative_dir(Classification.PUBLIC) == "public"
    assert expected_relative_dir(Classification.INTERNAL) == "private/internal"
    assert expected_relative_dir(Classification.CONFIDENTIAL) == "private/confidential"


def test_mislabeled_public_ku_outside_public_dir_is_error(
    fixture_knowledge_root: Path,
) -> None:
    issues = validate_file(
        fixture_knowledge_root / "invalid/KU-0010-mislabeled.md", fixture_knowledge_root
    )
    assert any(i.code == "wrong-directory" and i.level is Level.ERROR for i in issues)


# --- Codex cross-review finding #2 (2026-09-11): confinement must be checked
# BEFORE any read, and must be a hard ERROR (it used to be a WARNING and the
# file was still loaded into the corpus).

def test_symlinked_ku_is_a_hard_error(tmp_path: Path, corpus_alt_root: Path) -> None:
    real_target = next(corpus_alt_root.glob("public/**/*.md"))
    root = tmp_path / "knowledge"
    (root / "public" / "prompt-security").mkdir(parents=True)
    link = root / "public" / "prompt-security" / "evil.md"
    link.symlink_to(real_target)

    issues = validate_file(link, root)
    assert has_errors(issues)
    assert any(i.code == "symlink-not-allowed" and i.level is Level.ERROR for i in issues)


def test_symlinked_ku_is_never_loaded_into_the_corpus(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    from app.ingestion.loader import load_corpus

    real_target = next(corpus_alt_root.glob("public/**/*.md"))
    root = tmp_path / "knowledge"
    (root / "public" / "prompt-security").mkdir(parents=True)
    link = root / "public" / "prompt-security" / "evil.md"
    link.symlink_to(real_target)

    report = load_corpus(root)
    assert report.units == []
    assert any("evil.md" in path for path, _ in report.skipped)


def test_missing_knowledge_root_is_a_hard_error(tmp_path: Path) -> None:
    """Codex cross-review finding #4 (2026-09-11): validate_tree() on a missing
    root used to return zero issues (a false "clean" result)."""
    issues = validate_tree(tmp_path / "no-such-root")
    assert has_errors(issues)
    assert any(i.code == "missing-root" and i.level is Level.ERROR for i in issues)


def test_out_of_root_ku_is_a_hard_error(tmp_path: Path) -> None:
    outside = tmp_path / "outside.md"
    outside.write_text("id: X\n", encoding="utf-8")
    root = tmp_path / "knowledge"
    (root / "public" / "prompt-security").mkdir(parents=True)

    issues = validate_file(outside, root)
    assert has_errors(issues)
    assert any(i.code == "outside-root" and i.level is Level.ERROR for i in issues)


@pytest.mark.parametrize(
    ("classification", "mode", "allow_confidential", "expected"),
    [
        (Classification.PUBLIC, Mode.PUBLIC, False, True),
        (Classification.INTERNAL, Mode.PUBLIC, False, False),
        (Classification.CONFIDENTIAL, Mode.PUBLIC, True, False),
        (Classification.SECRET, Mode.PUBLIC, True, False),
        (Classification.PUBLIC, Mode.PRIVATE, False, True),
        (Classification.INTERNAL, Mode.PRIVATE, False, True),
        (Classification.CONFIDENTIAL, Mode.PRIVATE, False, False),
        (Classification.CONFIDENTIAL, Mode.PRIVATE, True, True),
        (Classification.SECRET, Mode.PRIVATE, True, False),
    ],
)
def test_is_retrievable_matrix(
    classification: Classification,
    mode: Mode,
    allow_confidential: bool,
    expected: bool,
) -> None:
    assert (
        is_retrievable(classification, mode, allow_confidential=allow_confidential)
        is expected
    )
