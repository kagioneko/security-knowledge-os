"""A private, immutable, no-follow-verified copy of a knowledge root.

Codex#1/#2 (round 7, 2026-09-12), reproduced exactly as reported: two
related TOCTOU gaps in the reindex publish path, both about reading a LIVE,
externally-mutable directory tree:

  - a valid file changed transiently during the build and restored right
    after still passed integrity, because its hash describes whatever was
    read at that moment, not what was there just before/after (#1);
  - ``O_NOFOLLOW`` (round 6, Codex#5) protects only the FINAL pathname
    component of a read - an ancestor directory swapped to an
    outside-the-root symlink between ``check_containment()`` and the
    actual read was never checked (#2).

Both close the same way: read the entire tree exactly ONCE, through a
directory-fd walk that never re-resolves a pathname from scratch (each
level is opened with ``O_NOFOLLOW`` relative to its already-open,
already-verified PARENT fd, so a later rename/symlink-swap of anything
already walked cannot retroactively change what was read), into a private,
uniquely-named temporary directory that only this process knows about.
Every later step (validation, chunking, hashing) operates on that snapshot,
not on the original, externally-mutable path - there is no live tree left
to race against by the time any of that runs.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import stat
import tempfile
from pathlib import Path

from app.storage.db import untrusted_ancestor_chain_reason, untrusted_directory_reason


class SnapshotError(OSError):
    """The knowledge root could not be safely snapshotted."""


# Codex#7 (round 11, 2026-09-13), reproduced exactly as reported: this walk
# copied every regular file it found with no count, size, or depth bound -
# a multi-gigabyte file placed anywhere under a configured rules/
# safe-tests/knowledge root was copied into a fresh /tmp directory on
# EVERY resource load (every /v1/assessments and /v1/assessments/*/answers
# request now that main.py loads resources per request), even though
# per-file content bounds elsewhere (e.g. rule_loader.py's 50 KB rule-file
# cap) would reject it immediately afterward - the disk/IO cost of the
# copy itself happens first, unconditionally. These bounds are generous
# relative to every real per-file cap already enforced downstream (the
# largest today is 50 KB) while still making a planted oversized file (or
# a huge number of small ones) fail fast instead of exhausting disk.
_MAX_SNAPSHOT_FILES = 20_000
_MAX_SNAPSHOT_FILE_BYTES = 5_000_000
_MAX_SNAPSHOT_TOTAL_BYTES = 200_000_000
_MAX_SNAPSHOT_DEPTH = 64


class _Budget:
    """Mutable running totals threaded through the recursive walk below -
    a plain int can't be updated by a callee and observed by its caller
    without either this or a `nonlocal` per recursion level."""

    __slots__ = ("files", "bytes_copied")

    def __init__(self) -> None:
        self.files = 0
        self.bytes_copied = 0


def _open_dir_no_follow(name: str, dir_fd: int | None = None) -> int:
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)


def _check_identity_unchanged(scanned: os.stat_result, opened: os.stat_result, what: str) -> None:
    """Codex#1 (round 9, 2026-09-12), reproduced exactly as reported:
    `os.scandir()` observes one entry (a `DirEntry`, whose `.is_symlink()`/
    `.is_file()`/`.is_dir()` calls populate and cache an lstat taken AT
    SCAN TIME); `_copy_file_no_follow()`/`_open_dir_no_follow()` then
    re-resolve the same NAME by a fresh `os.open()` - a writer able to
    replace a regular file (or directory) with a different one of the
    same type, under the same name, between those two points is
    completely undetected: O_NOFOLLOW only refuses a symlink, and the
    round-8 before/after fstat check only covers the window from THIS
    open onward, not the scan-to-open window before it. Comparing
    (st_dev, st_ino) from the cached scan-time stat against fstat() on
    the freshly opened descriptor catches exactly that substitution -
    two different inodes can never share both a device and inode number.
    """
    if (scanned.st_dev, scanned.st_ino) != (opened.st_dev, opened.st_ino):
        raise SnapshotError(f"{what}: replaced with a different inode between scan and open")


def _copy_file_no_follow(
    entry: os.DirEntry[str], dir_fd: int, dest: Path, budget: _Budget
) -> None:
    scanned = entry.stat(follow_symlinks=False)
    fd = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise SnapshotError(f"{dest.name}: not a regular file")
        _check_identity_unchanged(scanned, before, dest.name)
        # Codex#7 (round 11, 2026-09-13): checked on the fd's own fstat (not
        # the pre-open scandir() size, which could itself be spoofed by a
        # substitution the identity check above didn't happen to catch),
        # BEFORE copying a single byte - an oversized file fails fast
        # instead of paying its full read/write cost first.
        if before.st_size > _MAX_SNAPSHOT_FILE_BYTES:
            raise SnapshotError(
                f"{dest.name}: {before.st_size} bytes exceeds the "
                f"{_MAX_SNAPSHOT_FILE_BYTES}-byte per-file snapshot limit"
            )
        budget.files += 1
        if budget.files > _MAX_SNAPSHOT_FILES:
            raise SnapshotError(
                f"more than {_MAX_SNAPSHOT_FILES} files under this root; refusing to snapshot"
            )
        budget.bytes_copied += before.st_size
        if budget.bytes_copied > _MAX_SNAPSHOT_TOTAL_BYTES:
            raise SnapshotError(
                f"more than {_MAX_SNAPSHOT_TOTAL_BYTES} total bytes under this root; "
                "refusing to snapshot"
            )
        with os.fdopen(fd, "rb", closefd=False) as src, open(dest, "wb") as out:
            shutil.copyfileobj(src, out)
        # Codex#2 (round 8, 2026-09-12), reproduced exactly as reported:
        # shutil.copyfileobj above has now read the entire file, but that
        # read is not atomic against a concurrent writer to the SAME inode
        # - a write that lands (and is even reverted right after) between
        # open() and the read completing can leave copied bytes that never
        # existed on disk at any single instant an outside observer could
        # see. Comparing metadata taken on the SAME fd (not by
        # re-resolving `name`, which could itself have been swapped to a
        # different regular file in the meantime) before and after the
        # read at least detects that the inode changed during the window
        # we were reading it, and refuses to publish a snapshot that
        # cannot be trusted rather than silently keeping whatever bytes
        # happened to be read.
        after = os.fstat(fd)
        if (before.st_mtime_ns, before.st_ctime_ns, before.st_size) != (
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_size,
        ):
            raise SnapshotError(f"{dest.name}: changed while being copied")
    finally:
        with contextlib.suppress(OSError):
            os.close(fd)


def _walk_no_follow(
    src_dir_fd: int, display: str, dest: Path, budget: _Budget, depth: int = 0
) -> None:
    # Codex#7 (round 11, 2026-09-13): an attacker-controlled or accidentally
    # very deep directory tree recurses this function once per level - a
    # depth bound caps the stack/inode-open cost the same way the
    # count/size bounds cap the copy cost.
    if depth > _MAX_SNAPSHOT_DEPTH:
        raise SnapshotError(
            f"{display}: exceeds the {_MAX_SNAPSHOT_DEPTH}-level snapshot depth limit"
        )
    dest.mkdir(exist_ok=True)
    entries = list(os.scandir(src_dir_fd))
    before_names = {entry.name for entry in entries}
    for entry in entries:
        child_display = f"{display}/{entry.name}"
        if entry.is_symlink():
            raise SnapshotError(f"{child_display}: symlinks are not allowed")
        if entry.is_dir(follow_symlinks=False):
            scanned = entry.stat(follow_symlinks=False)
            child_fd = _open_dir_no_follow(entry.name, dir_fd=src_dir_fd)
            try:
                _check_identity_unchanged(scanned, os.fstat(child_fd), child_display)
                _walk_no_follow(child_fd, child_display, dest / entry.name, budget, depth + 1)
            finally:
                os.close(child_fd)
        elif entry.is_file(follow_symlinks=False):
            _copy_file_no_follow(entry, src_dir_fd, dest / entry.name, budget)
        else:
            # Codex#3 (round 12, 2026-09-13), reproduced exactly as
            # reported: a FIFO, socket, or device file replacing a real
            # rule/knowledge/safe-test file used to be silently SKIPPED
            # here (this comment used to justify that by pointing at
            # iter_knowledge_files() only looking for `*.md` - but
            # load_rules()/load_safe_tests() glob other suffixes over this
            # SAME snapshot, and none of them re-verify that a name they
            # expected to see is still a regular file). A rule replaced by
            # a FIFO is then indistinguishable from an intentionally
            # deleted rule - the catalogue silently loses coverage with no
            # error anywhere. Fail the whole snapshot instead: every
            # caller already treats a raised SnapshotError as "could not
            # safely read this root", the correct outcome for a directory
            # entry this loader cannot account for at all.
            raise SnapshotError(f"{child_display}: not a regular file or directory")
    # Codex#2 (round 8, 2026-09-12), reproduced exactly as reported:
    # entries can be added or removed by a concurrent writer while this
    # loop was copying the ones seen at the start, producing a mixed-time
    # snapshot (some files reflect "before", a newly-added file reflects
    # "during", a removed one is silently just absent either way). This
    # cannot recover which state is correct, but re-listing the same
    # directory fd after the loop and refusing to publish on any
    # difference at least surfaces that the source tree was not quiescent
    # during the copy.
    after_names = {entry.name for entry in os.scandir(src_dir_fd)}
    if before_names != after_names:
        raise SnapshotError(f"{display}: directory entries changed while being copied")


def snapshot_tree(root: Path) -> Path:
    """Copy `root` into a fresh, private temp directory via a directory-fd,
    no-follow-at-every-level walk, and return the copy's path. The caller
    owns the returned directory and must remove it (``shutil.rmtree``)
    when done. Raises ``SnapshotError`` (a symlink anywhere in the tree, or
    an untrusted ancestor above ``root``) or ``OSError`` (root missing, a
    file vanished mid-walk, ...).
    """
    # Codex#4 (round 12, 2026-09-13), reproduced exactly as reported:
    # `_open_dir_no_follow(str(root))` below protects `root` ITSELF from
    # being a symlink (O_NOFOLLOW on the final pathname component), but
    # every ANCESTOR of `root` is still resolved the normal way - an
    # attacker able to rename one of them (which needs write access only
    # to THAT ancestor's own parent, not to `root` or anything under it)
    # can substitute the entire tree this function is about to walk.
    # Shared with app.storage.db.untrusted_state_dir_reason() (round 11),
    # which has the identical gap for db_path's own ancestors.
    untrusted = untrusted_ancestor_chain_reason(root)
    if untrusted is not None:
        raise SnapshotError(untrusted)
    # Codex#4 (round 13, 2026-09-13), reproduced exactly as reported: the
    # check above verifies every ANCESTOR of `root` but never `root`
    # ITSELF - a root directly writable by an untrusted group/other
    # (without the sticky bit) can be substituted the same way, without
    # needing to touch anything above it.
    untrusted = untrusted_directory_reason(root)
    if untrusted is not None:
        raise SnapshotError(untrusted)

    dest = Path(tempfile.mkdtemp(prefix="skos-snapshot-"))
    try:
        root_fd = _open_dir_no_follow(str(root))
        try:
            _walk_no_follow(root_fd, str(root), dest, _Budget())
        finally:
            os.close(root_fd)
    except BaseException:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return dest
