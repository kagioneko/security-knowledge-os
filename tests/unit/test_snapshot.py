"""app/ingestion/snapshot.py: directory-fd, no-follow-at-every-level copy."""

from __future__ import annotations

import os
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


def test_rejects_a_fifo_in_place_of_a_regular_file(tmp_path: Path) -> None:
    """Regression for Codex#3 (round 12, 2026-09-13), reproduced exactly as
    reported: a FIFO (or socket, or device file) replacing a real rule/
    knowledge/safe-test file used to be silently SKIPPED during the
    snapshot walk - a rule file replaced by a FIFO was then
    indistinguishable from an intentionally deleted rule, and the
    resulting catalogue silently lost coverage with no error anywhere."""
    root = tmp_path / "src"
    root.mkdir()
    os.mkfifo(root / "TOOL-001.yaml")

    with pytest.raises(SnapshotError, match="not a regular file"):
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
    `_copy_file_no_follow()`. Wraps the fd's read() (round 14, Codex#4:
    the copy is now a chunked loop, not a single shutil.copyfileobj()
    call) to mutate the source file (via a separate open(), not the
    already-open fd) right after the first chunk is read, simulating
    exactly that: the bytes already read into the snapshot may or may not
    reflect a state that ever existed as a stable, observable version of
    the file. The before/after fstat comparison on the same fd must
    detect this and refuse to publish rather than silently keeping
    whatever bytes were read."""
    import os as os_module

    root = tmp_path / "src"
    root.mkdir()
    ku = root / "ku.md"
    ku.write_text("original", encoding="utf-8")

    real_fdopen = os_module.fdopen
    mutated = {"done": False}

    class _RacyReader:
        def __init__(self, real_file: object) -> None:
            self._real = real_file

        def read(self, *a: object, **kw: object) -> bytes:
            chunk: bytes = self._real.read(*a, **kw)  # type: ignore[attr-defined]
            if chunk and not mutated["done"]:
                mutated["done"] = True
                ku.write_text("mutated-during-the-copy-window", encoding="utf-8")
            return chunk

        def __enter__(self) -> _RacyReader:
            return self

        def __exit__(self, *exc: object) -> bool:
            self._real.close()  # type: ignore[attr-defined]
            return False

    def racy_fdopen(fd: int, *a: object, **kw: object) -> object:
        return _RacyReader(real_fdopen(fd, *a, **kw))

    monkeypatch.setattr(os_module, "fdopen", racy_fdopen)

    with pytest.raises(SnapshotError, match="changed while being copied"):
        snapshot_tree(root)


def test_rejects_a_file_swapped_for_a_different_regular_file_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#1 (round 9, 2026-09-12), reproduced exactly as
    reported: os.scandir() observes one entry (an lstat cached at SCAN
    time); _copy_file_no_follow() then re-resolves the same NAME with a
    fresh os.open() - a writer able to replace a regular file with a
    DIFFERENT regular file of the same name, between the scan and that
    open, was completely undetected (O_NOFOLLOW only refuses a symlink,
    and the round-8 before/after fstat check only covers the window from
    the open onward, not the scan-to-open window before it). Monkeypatching
    os.open (called by _copy_file_no_follow after the DirEntry's stat is
    already cached) to swap the file's CONTENT via a separate path-based
    open first simulates exactly that - same name, different inode."""
    import app.ingestion.snapshot as snapshot_module

    root = tmp_path / "src"
    root.mkdir()
    target = root / "safe.yaml"
    target.write_text("original", encoding="utf-8")
    # a pre-existing, already-allocated file with its OWN distinct inode -
    # os.replace() just re-points the name at it, unlike unlink()+recreate
    # on the same filesystem, which the allocator can (and on tmpfs/ext4
    # reliably does, for a single quick free/alloc cycle) satisfy by
    # reusing the SAME inode number, defeating this test's premise.
    poisoned = tmp_path / "poisoned.yaml"
    poisoned.write_text("swapped-to-a-different-inode", encoding="utf-8")

    real_open = os.open

    def swap_then_open(path: object, flags: int, *a: object, **kw: object) -> int:
        if path == "safe.yaml":
            os.replace(poisoned, target)
        return real_open(path, flags, *a, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(snapshot_module.os, "open", swap_then_open)

    with pytest.raises(SnapshotError, match="different inode"):
        snapshot_module.snapshot_tree(root)


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

    def racy_copy(entry: os.DirEntry[str], dir_fd: int, dest: Path, budget: object) -> None:
        real_copy(entry, dir_fd, dest, budget)
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


def test_rejects_a_file_over_the_per_file_snapshot_size_limit(tmp_path: Path) -> None:
    """Regression for Codex#7 (round 11, 2026-09-13), reproduced exactly as
    reported: a multi-gigabyte file placed anywhere under a configured
    rules/safe-tests/knowledge root used to be copied into a fresh /tmp
    directory in full, unconditionally, on every resource load - even
    though every real per-file content cap downstream (the largest today
    is 50 KB) would reject it immediately afterward. The size is checked
    on the opened file's own fstat, before a single byte is copied."""
    import app.ingestion.snapshot as snapshot_module

    root = tmp_path / "src"
    root.mkdir()
    oversized = root / "junk.bin"
    with oversized.open("wb") as f:
        f.seek(snapshot_module._MAX_SNAPSHOT_FILE_BYTES)
        f.write(b"\0")

    with pytest.raises(SnapshotError, match="per-file snapshot limit"):
        snapshot_tree(root)


def test_rejects_a_file_that_grows_past_the_limit_during_the_copy_itself(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#4 (round 14, 2026-09-13), reproduced exactly
    as reported: the per-file size limit above was checked ONCE, on the
    fd's fstat, BEFORE a single byte was copied - if the file grew after
    that check but during the (previously unbounded)
    shutil.copyfileobj() call, every new byte was copied in full before
    the post-copy metadata check caught the growth, after the disk/IO
    cost was already paid. A fault-injected repro copied 5,000,002 bytes
    from a source that was one byte at the time of the size check. The
    chunked copy loop must catch this WHILE copying (a running count of
    ACTUAL bytes read, checked every chunk), not after the whole grown
    file has already been copied."""
    import os as os_module

    import app.ingestion.snapshot as snapshot_module

    root = tmp_path / "src"
    root.mkdir()
    growing = root / "growing.bin"
    growing.write_bytes(b"\0")  # 1 byte - passes the pre-copy fstat check

    real_fdopen = os_module.fdopen
    grown = {"done": False}

    class _GrowingReader:
        def __init__(self, real_file: object) -> None:
            self._real = real_file

        def read(self, *a: object, **kw: object) -> bytes:
            if not grown["done"]:
                grown["done"] = True
                with growing.open("ab") as f:
                    f.write(b"\0" * (snapshot_module._MAX_SNAPSHOT_FILE_BYTES + 2))
            chunk: bytes = self._real.read(*a, **kw)  # type: ignore[attr-defined]
            return chunk

        def __enter__(self) -> _GrowingReader:
            return self

        def __exit__(self, *exc: object) -> bool:
            self._real.close()  # type: ignore[attr-defined]
            return False

    def growing_fdopen(fd: int, *a: object, **kw: object) -> object:
        return _GrowingReader(real_fdopen(fd, *a, **kw))

    monkeypatch.setattr(os_module, "fdopen", growing_fdopen)

    with pytest.raises(SnapshotError, match="grew past"):
        snapshot_tree(root)


def test_rejects_more_files_than_the_snapshot_count_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same protection as the size limit above, for file COUNT - a
    directory with an enormous number of tiny files is an equally real
    disk/inode exhaustion vector the size cap alone does not bound."""
    import app.ingestion.snapshot as snapshot_module

    monkeypatch.setattr(snapshot_module, "_MAX_SNAPSHOT_FILES", 3)
    root = tmp_path / "src"
    root.mkdir()
    for i in range(5):
        (root / f"f{i}.md").write_text("x", encoding="utf-8")

    with pytest.raises(SnapshotError, match="files under this root"):
        snapshot_tree(root)


def test_rejects_a_tree_deeper_than_the_snapshot_depth_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same protection, for directory NESTING depth - each level recurses
    _walk_no_follow() once; an unbounded depth is an unbounded stack/
    inode-open cost regardless of how few files are actually at the
    bottom."""
    import app.ingestion.snapshot as snapshot_module

    monkeypatch.setattr(snapshot_module, "_MAX_SNAPSHOT_DEPTH", 3)
    root = tmp_path / "src"
    nested = root
    for _ in range(6):
        nested = nested / "d"
    nested.mkdir(parents=True)

    with pytest.raises(SnapshotError, match="snapshot depth limit"):
        snapshot_tree(root)
