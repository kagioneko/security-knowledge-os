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

    # Codex#3 (round 10, 2026-09-13): load_corpus() now snapshots
    # knowledge_root up front (see load_corpus()'s own docstring) - a
    # symlink ANYWHERE in the tree now fails the whole snapshot rather than
    # being skipped as a single bad file, so this is now a whole-corpus
    # refusal (report.issues), not a per-file entry in report.skipped.
    report = load_corpus(root)
    assert report.units == []
    assert report.skipped == []
    assert any("evil.md" in issue.message for issue in report.issues)


def test_validate_tree_never_reopens_a_rejected_symlink(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for SKOS-ADV-10 / Codex#4 (round 2, 2026-09-11): validate_file()
    rejects a symlinked candidate as an ERROR before reading it, but
    validate_tree()'s own duplicate-id pass unconditionally called
    read_markdown() on the same path again right after - reopening (and
    reading through) the very file that was just rejected.

    Codex#10 (round 11, 2026-09-13): validate_tree() now snapshots the
    whole tree up front (the same directory-fd walk load_corpus() already
    uses) - a symlink ANYWHERE in the tree now fails the whole snapshot
    (never opened at all, by construction) rather than being individually
    rejected per-file, the same behaviour change load_corpus() got in
    round 10 (see test_symlinked_ku_is_never_loaded_into_the_corpus)."""
    import app.ingestion.validator as validator_module

    real_target = next(corpus_alt_root.glob("public/**/*.md"))
    root = tmp_path / "knowledge"
    (root / "public" / "prompt-security").mkdir(parents=True)
    link = root / "public" / "prompt-security" / "evil.md"
    link.symlink_to(real_target)

    read_paths: list[str] = []
    original_read = validator_module.read_markdown

    def _spy(path: Path):  # type: ignore[no-untyped-def]
        read_paths.append(str(path))
        return original_read(path)

    validator_module.read_markdown = _spy  # type: ignore[assignment]
    try:
        issues = validate_tree(root)
    finally:
        validator_module.read_markdown = original_read  # type: ignore[assignment]

    assert any(i.code == "snapshot-failed" and "evil.md" in i.message for i in issues)
    assert not any("evil.md" in p for p in read_paths)


def test_validate_tree_ancestor_directory_confinement_is_enforced(tmp_path: Path) -> None:
    """Regression for Codex#10 (round 11, 2026-09-13), reproduced exactly as
    reported: `check_containment()`'s O_NOFOLLOW protects only the FINAL
    pathname component - validate_tree()'s own `rglob()` walk (via
    `iter_knowledge_files()`) and its reads both re-resolved the full path
    from scratch, so an ANCESTOR directory swapped to an outside-root
    symlink between `check_containment()` succeeding and the actual read
    was followed straight through, the same class of gap round 7/8 already
    closed for the reindex path and for `load_rules()`/`load_safe_tests()`.
    validate_tree() now snapshots `knowledge_root` the same
    no-follow-at-every-level way those already do, closing this the same
    way: the ancestor symlink itself is rejected during the snapshot walk,
    before any file under it is ever opened.

    NOTE: deliberately not named with "symlink" in it - see
    test_ancestor_directory_confinement_is_enforced in test_rule_loader.py
    for why (pytest's tmp_path fixture names the temp dir after the test
    function itself, so a "...symlinked..." name would make a message
    match on "symlink" trivially, spuriously pass pre-fix)."""
    root = tmp_path / "knowledge"
    root.mkdir()
    outside = tmp_path / "outside" / "public" / "prompt-security"
    outside.mkdir(parents=True)
    (outside / "ku.md").write_text(
        "---\nid: OUT-901\ntitle: t\nclassification: public\n"
        "category: prompt-security\nversion: 1\n---\nbody\n",
        encoding="utf-8",
    )
    (root / "public").symlink_to(outside.parent, target_is_directory=True)

    issues = validate_tree(root)
    assert any(i.code == "snapshot-failed" for i in issues)


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
