"""app/ingestion/snapshot.py: directory-fd, no-follow-at-every-level copy."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from app.ingestion.snapshot import SnapshotError, snapshot_tree


def test_copies_a_clean_tree_faithfully(tmp_path: Path) -> None:
    root = tmp_path / "src"
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "b" / "leaf.md").write_text("hello", encoding="utf-8")
    (root / "top.md").write_text("world", encoding="utf-8")

    dest = snapshot_tree(root)
    try:
        assert (dest / "a" / "b" / "leaf.md").read_text(encoding="utf-8") == "hello"
        assert (dest / "top.md").read_text(encoding="utf-8") == "world"
    finally:
        shutil.rmtree(dest, ignore_errors=True)


def test_rejects_a_symlinked_leaf_file(tmp_path: Path) -> None:
    root = tmp_path / "src"
    root.mkdir()
    outside = tmp_path / "outside.md"
    outside.write_text("OUTSIDE_CONTENT_MARKER", encoding="utf-8")
    (root / "link.md").symlink_to(outside)

    with pytest.raises(SnapshotError):
        snapshot_tree(root)


def test_rejects_a_symlinked_ancestor_directory(tmp_path: Path) -> None:
    """Regression for Codex#2 (round 7, 2026-09-12), reproduced exactly as
    reported: O_NOFOLLOW (round 6, Codex#5) protects only the FINAL
    pathname component of a read - an ANCESTOR directory swapped to an
    outside-the-root symlink was never checked. snapshot_tree()'s
    directory-fd walk opens every level (including intermediate
    directories) with O_NOFOLLOW relative to its already-verified parent,
    so a symlinked ancestor is rejected regardless of depth."""
    root = tmp_path / "knowledge"
    (root / "public").mkdir(parents=True)
    outside = tmp_path / "outside-dir"
    outside.mkdir()
    (outside / "ku.md").write_text("OUTSIDE_CONTENT_MARKER", encoding="utf-8")
    (root / "public" / "prompt-security").symlink_to(outside, target_is_directory=True)

    with pytest.raises(SnapshotError):
        snapshot_tree(root)


def test_rejects_a_file_mutated_during_the_copy_itself(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#2 (round 8, 2026-09-12), reproduced exactly as
    reported: the existing "immune to later mutation" test below only
    mutates the source AFTER snapshot_tree() has fully returned - it never
    exercises a write landing DURING the read inside
    `_copy_file_no_follow()`. Monkeypatching shutil.copyfileobj to mutate
    the source file (via a separate open(), not the already-open fd)
    right after the read simulates exactly that: the bytes already read
    into the snapshot may or may not reflect a state that ever existed as
    a stable, observable version of the file. The before/after fstat
    comparison on the same fd must detect this and refuse to publish
    rather than silently keeping whatever bytes were read."""
    import shutil as shutil_module

    root = tmp_path / "src"
    root.mkdir()
    ku = root / "ku.md"
    ku.write_text("original", encoding="utf-8")

    real_copyfileobj = shutil_module.copyfileobj

    def racy_copyfileobj(src: object, dst: object, *a: object, **kw: object) -> None:
        real_copyfileobj(src, dst, *a, **kw)  # type: ignore[arg-type]
        ku.write_text("mutated-during-the-copy-window", encoding="utf-8")

    monkeypatch.setattr(shutil_module, "copyfileobj", racy_copyfileobj)

    with pytest.raises(SnapshotError, match="changed while being copied"):
        snapshot_tree(root)


def test_rejects_a_directory_whose_entries_changed_during_the_walk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#2 (round 8, 2026-09-12), reproduced exactly as
    reported: a file added to (or removed from) a directory while
    `_walk_no_follow()` was still copying the entries it saw at the start
    produces a mixed-time snapshot. Monkeypatching `_copy_file_no_follow`
    to add a new file to the source directory as a side effect of copying
    the first one simulates exactly that."""
    import app.ingestion.snapshot as snapshot_module

    root = tmp_path / "src"
    root.mkdir()
    (root / "first.md").write_text("first", encoding="utf-8")

    real_copy = snapshot_module._copy_file_no_follow

    def racy_copy(name: str, dir_fd: int, dest: Path) -> None:
        real_copy(name, dir_fd, dest)
        (root / "added-during-walk.md").write_text("surprise", encoding="utf-8")

    monkeypatch.setattr(snapshot_module, "_copy_file_no_follow", racy_copy)

    with pytest.raises(SnapshotError, match="directory entries changed"):
        snapshot_tree(root)


def test_snapshot_is_a_private_copy_immune_to_later_source_mutation(tmp_path: Path) -> None:
    root = tmp_path / "src"
    root.mkdir()
    ku = root / "ku.md"
    ku.write_text("original", encoding="utf-8")

    dest = snapshot_tree(root)
    try:
        ku.write_text("mutated after the snapshot was taken", encoding="utf-8")
        assert (dest / "ku.md").read_text(encoding="utf-8") == "original"
    finally:
        shutil.rmtree(dest, ignore_errors=True)
