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


class SnapshotError(OSError):
    """The knowledge root could not be safely snapshotted."""


def _open_dir_no_follow(name: str, dir_fd: int | None = None) -> int:
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)


def _copy_file_no_follow(name: str, dir_fd: int, dest: Path) -> None:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise SnapshotError(f"{dest.name}: not a regular file")
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


def _walk_no_follow(src_dir_fd: int, display: str, dest: Path) -> None:
    dest.mkdir(exist_ok=True)
    entries = list(os.scandir(src_dir_fd))
    before_names = {entry.name for entry in entries}
    for entry in entries:
        child_display = f"{display}/{entry.name}"
        if entry.is_symlink():
            raise SnapshotError(f"{child_display}: symlinks are not allowed")
        if entry.is_dir(follow_symlinks=False):
            child_fd = _open_dir_no_follow(entry.name, dir_fd=src_dir_fd)
            try:
                _walk_no_follow(child_fd, child_display, dest / entry.name)
            finally:
                os.close(child_fd)
        elif entry.is_file(follow_symlinks=False):
            _copy_file_no_follow(entry.name, src_dir_fd, dest / entry.name)
        # any other type (fifo, socket, device, ...) is silently skipped -
        # iter_knowledge_files() only ever looks for plain `*.md` files.
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
    when done. Raises ``SnapshotError`` (a symlink anywhere in the tree)
    or ``OSError`` (root missing, a file vanished mid-walk, ...).
    """
    dest = Path(tempfile.mkdtemp(prefix="skos-snapshot-"))
    try:
        root_fd = _open_dir_no_follow(str(root))
        try:
            _walk_no_follow(root_fd, str(root), dest)
        finally:
            os.close(root_fd)
    except BaseException:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return dest
