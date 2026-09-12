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
