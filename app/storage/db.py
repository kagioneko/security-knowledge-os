"""SQLite connection and schema for the knowledge index.

The full-text search uses the FTS5 extension (BM25 ranking). The index is rebuilt
from scratch on every ingest, so the FTS table is contentless.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import stat
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS chunks (
    rowid          INTEGER PRIMARY KEY,
    chunk_id       TEXT UNIQUE NOT NULL,
    knowledge_id   TEXT NOT NULL,
    title          TEXT NOT NULL,
    source_ref     TEXT NOT NULL,
    classification TEXT NOT NULL,
    category       TEXT NOT NULL,
    version        TEXT NOT NULL,
    section        TEXT NOT NULL,
    text           TEXT NOT NULL,
    hash           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
    search_text,
    content='',
    tokenize='trigram'
);
"""
# The 'trigram' tokenizer gives substring matching for both English and CJK text
# (SQLite >= 3.34). It is why a Japanese query can reach a Japanese Knowledge Unit
# (JA-R01) without a language-specific segmenter.


# Codex#4 (round 6, 2026-09-12), reproduced exactly as reported: this
# database's identity was checked only by querying meta(key,value) -
# `CREATE TABLE IF NOT EXISTS` is idempotent, so ANY unrelated SQLite file
# that happens to already have a compatible `meta` table (created by
# something else entirely) was silently adopted as "an existing SKOS
# index" and then atomically overwritten by reindex_atomic(). SQLite's
# `application_id` pragma is a 4-byte header field reserved by SQLite
# itself for exactly this "which application owns this file" purpose
# (https://www.sqlite.org/pragma.html#pragma_application_id) - set once on
# a genuinely fresh file, and checked on every later open of an existing
# one. b"SKOS" as big-endian bytes; comfortably inside the signed-32-bit
# range PRAGMA application_id accepts.
_APPLICATION_ID = int.from_bytes(b"SKOS", "big")


class ForeignDatabaseError(RuntimeError):
    """db_path already contains tables, but they are not a Security
    Knowledge OS index - refusing to write into an unrelated database."""


class UntrustedStateDirectoryError(RuntimeError):
    """db_path's parent directory is not owned by this process, or is
    writable by anyone else with a local account - see
    untrusted_state_dir_reason()."""


def untrusted_state_dir_reason(parent: Path) -> str | None:
    """Codex#6 (round 11, 2026-09-13), reproduced exactly as reported: the
    write-path identity check in connect() below (pre-open O_NOFOLLOW
    stat, sqlite3.connect(), post-open PRAGMA database_list + os.stat())
    can be defeated by an ABA race - rename the verified file aside,
    substitute a symlink, let SQLite open and write through it, then
    restore the original pathname BEFORE the post-check runs. The
    post-check's `os.stat(opened_path)` re-resolves the pathname from
    scratch, at a point in time AFTER the restore - it observes the
    correctly-restored identity and passes, even though SQLite already
    wrote its schema to the symlink's target moments earlier. No
    stdlib sqlite3 API exposes the actual file descriptor SQLite has
    open, so there is no fd to verify against instead.

    Every such substitution requires an attacker able to write in
    db_path's parent directory - the same precondition
    app/retrieval/index.py's reindex_atomic() already verifies before
    doing any of its own publish-path writes (round 11, Codex#3). Sharing
    that check here closes the identical class of gap for connect()'s
    write path directly, covering every caller of connect() (a direct
    build_index()/scripts/build_index.py call, not just reindex_atomic()),
    not by trying to detect a substitution that can be timed around the
    check, but by refusing to write into a directory an untrusted writer
    could already reach. Returns None if the directory passes.
    """
    try:
        st = parent.stat()
    except OSError as exc:
        return f"could not verify ownership/permissions of {parent}: {exc}"
    if st.st_uid != os.geteuid():
        return f"{parent} is not owned by this process (uid {st.st_uid}); refusing to write"
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return (
            f"{parent} is group- or world-writable (mode {oct(stat.S_IMODE(st.st_mode))}); "
            "refusing to write"
        )
    return untrusted_ancestor_chain_reason(parent)


def _group_is_private(gid: int) -> bool:
    """Codex#4 (round 13, 2026-09-13), reproduced exactly as reported: the
    round-12 fix trusted a group-writable ancestor whenever the group's
    GID merely equalled this process's own effective GID - that does not
    establish the group is actually PRIVATE. Another local account that
    happens to share the same group (a real, common setup - project
    groups, `docker`, `adm`, ...) could rename an ancestor and substitute
    a directory between this check and the caller's later open, exactly
    the ABA this whole check exists to close.

    A group is genuinely private (matches the "user-private group" UPG
    convention this project's own deployment relies on) only when NO
    account other than this process's own euid can write as that group:
    no explicit secondary member (``grp`` entry's ``gr_mem``), and no
    OTHER account has it as a PRIMARY group either (``gr_mem`` alone
    misses that - a user's primary group membership lives in ``/etc/
    passwd``'s gid field, not in ``/etc/group``'s member list). Any
    lookup failure (unknown gid, no traditional passwd/group database at
    all) is treated as NOT private - this only ever loosens a check that
    would otherwise reject the ancestor outright, never the reverse.
    """
    import grp
    import pwd

    try:
        group = grp.getgrgid(gid)
    except (KeyError, OSError):
        return False
    if group.gr_mem:
        return False
    try:
        primary_members = {entry.pw_uid for entry in pwd.getpwall() if entry.pw_gid == gid}
    except OSError:
        return False
    return primary_members == {os.geteuid()}


def untrusted_ancestor_chain_reason(path: Path) -> str | None:
    """Codex#4 (round 12, 2026-09-13), reproduced exactly as reported: the
    check above (and the identical no-follow-at-the-root check
    `app.ingestion.snapshot.snapshot_tree()` does for its own root) only
    ever verified the directory being written into ITSELF - never
    anything above it. Substituting the whole configured directory does
    not require write access inside it at all: renaming a directory's OWN
    entry only requires write access to *its parent*, so an attacker able
    to write into any ANCESTOR of an otherwise perfectly-owned, mode-0700
    directory can still rename that directory aside and put a symlink (or
    a different directory) in its place.

    Every ancestor from `path`'s parent up to the filesystem root must
    therefore refuse an untrusted writer too - but "owned by this
    process" is the wrong bar to raise that high: ordinary system
    directories several levels up (``/``, ``/home``, ...) are root-owned,
    not owned by this process, and are correctly, safely shared; so, in
    the common single-user-workstation "user-private group" layout, is
    this project's OWN parent directory, typically group-writable by a
    group whose only member is this same user. Requiring exact ownership
    at every level made this check reject the project's own real
    deployment directory outright (round 12 self-review caught this
    before it ever reached Codex) - matching OpenSSH's own StrictModes
    rule for exactly this situation (``sshd(8)``: a group-writable
    ancestor is accepted when its group matches the user's own), a
    directory is flagged only when it is writable by OTHER, or writable
    by a group that is not PROVEN PRIVATE to this process's own account
    (Codex#4, round 13, 2026-09-13 - matching only the *GID*, as round 12
    did, does not prove no one else can write as that group). The other
    property that matters is the same one the kernel itself uses to
    decide whether ``/tmp`` (world-writable) is safe to share: writable-
    by-untrusted is only dangerous WITHOUT the sticky bit (``S_ISVTX``) -
    with it set, only the entry's owner, the directory's owner, or root
    can rename or unlink an entry, so a shared, world-writable ancestor
    with the sticky bit is not a substitution vector either. Resolves
    symlinks along the way deliberately (this is a pass/fail precondition
    check on the trust of the path a caller is ABOUT to use, not a
    race-proof no-follow read itself).
    """
    current = path.resolve(strict=False)
    while True:
        ancestor = current.parent
        if ancestor == current:
            return None  # reached the filesystem root
        reason = _untrusted_directory_stat_reason(ancestor)
        if reason is not None:
            return f"{reason}; an ancestor directory of {path} could be renamed out from under it"
        current = ancestor


def _untrusted_directory_stat_reason(directory: Path) -> str | None:
    """The single-directory half of `untrusted_ancestor_chain_reason()`'s
    check - writable by OTHER, or by a group not proven private to this
    process, without the sticky bit. Shared so a caller that also needs
    to check a directory ITSELF (not just its ancestors) - see
    `app.ingestion.snapshot.snapshot_tree()`'s use on `root`, Codex#4
    round 13, 2026-09-13 - gets the identical rule."""
    try:
        st = directory.stat()
    except OSError as exc:
        return f"could not verify ownership/permissions of {directory}: {exc}"
    writable_by_untrusted = bool(st.st_mode & stat.S_IWOTH) or (
        bool(st.st_mode & stat.S_IWGRP) and not _group_is_private(st.st_gid)
    )
    sticky = bool(st.st_mode & stat.S_ISVTX)
    if writable_by_untrusted and not sticky:
        return (
            f"{directory} is writable by a group or user other than this "
            f"process, without the sticky bit (mode {oct(stat.S_IMODE(st.st_mode))}, "
            f"gid {st.st_gid})"
        )
    return None


def untrusted_directory_reason(directory: Path) -> str | None:
    """Codex#4 (round 13, 2026-09-13), reproduced exactly as reported:
    `snapshot_tree()` checked `root`'s ANCESTORS (via
    `untrusted_ancestor_chain_reason()`, round 12) but never `root`
    ITSELF - a root that is directly writable by an untrusted group/other
    (without the sticky bit) can be substituted the same way an ancestor
    can, without needing to touch anything above it. Public entry point
    for the single-directory half of that same check, resolving symlinks
    the same deliberate way (a pass/fail precondition check on trust, not
    a race-proof no-follow read)."""
    return _untrusted_directory_stat_reason(directory.resolve(strict=False))


# Codex#4 (round 8, 2026-09-12), reproduced exactly as reported: `os.chmod`
# resolves its path argument the normal way, following a symlink at that
# exact path - precreating a state file (the db path or the reindex lock
# file) as a symlink to an unrelated file caused chmod() to silently
# re-permission that unrelated TARGET (e.g. to 0600), not the state file
# itself. `open(path, mode)` has the same problem when creating the file:
# it happily creates/writes through a pre-existing symlink. Opening with
# O_NOFOLLOW instead makes the open itself fail (ELOOP) if the final path
# component is a symlink, and fchmod() on that verified descriptor can
# never be redirected by a later swap of the path.
def open_no_follow(path: str | Path, mode: int) -> int:
    """Open (creating if missing) with O_NOFOLLOW; the returned fd is both
    verified-not-a-symlink and safe to fchmod()."""
    return os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, mode)


def chmod_no_follow(path: str | Path, mode: int) -> None:
    """Set `mode` on `path` without ever following a symlink planted there -
    see `open_no_follow` above. Raises OSError (including ELOOP for a
    symlink) rather than silently chmod'ing whatever the symlink points to;
    callers that consider a chmod failure non-fatal wrap this themselves."""
    fd = open_no_follow(path, mode)
    try:
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def verify_application_id(conn: sqlite3.Connection, db_path: str | Path) -> None:
    """Raise ForeignDatabaseError unless `conn` is either a brand new/empty
    database or already carries this app's `application_id`. Shared by
    `connect()`'s own write-path check below and by
    `app.retrieval.index._current_revision()`, which reads an EXISTING
    `db_path` read-only before `reindex_atomic()` decides whether to
    replace it - `connect()`'s write-path check alone does not cover that:
    reindex_atomic() never opens the final `db_path` for writing at all, it
    replaces it wholesale with `os.replace(staging, db_path)` (Codex#4,
    round 6, 2026-09-12)."""
    app_id = conn.execute("PRAGMA application_id").fetchone()[0]
    if app_id != _APPLICATION_ID:
        raise ForeignDatabaseError(
            f"{db_path} exists but is not a Security Knowledge OS index "
            f"(application_id={app_id}, expected {_APPLICATION_ID}); refusing to "
            "treat it as one"
        )


class FTS5Unavailable(RuntimeError):
    """The linked SQLite build has no FTS5 extension."""


def _has_fts5(conn: sqlite3.Connection) -> bool:
    try:
        conn.execute("CREATE VIRTUAL TABLE temp._skos_fts_probe USING fts5(x)")
        conn.execute("DROP TABLE temp._skos_fts_probe")
    except sqlite3.OperationalError:
        return False
    return True


def _read_only_uri(db_path: str | Path) -> str:
    # Codex cross-review finding #5 (2026-09-11): a bare f"file:{db_path}?mode=ro"
    # is not a properly constructed URI. If db_path contains '#', everything from
    # '#' onward (including '?mode=ro') is parsed as the URI *fragment* and
    # discarded - read-only silently stops being requested at all, and a '?'/'%'
    # in the path can likewise be misparsed as query syntax. Path.as_uri()
    # percent-encodes special characters correctly.
    if str(db_path) == ":memory:":
        return "file::memory:?mode=ro"
    return f"{Path(db_path).resolve().as_uri()}?mode=ro"


def connect(db_path: str | Path, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        conn = sqlite3.connect(_read_only_uri(db_path), uri=True)
        conn.row_factory = sqlite3.Row
        if not _has_fts5(conn):
            conn.close()
            raise FTS5Unavailable("SQLite FTS5 is required but not available in this Python build")
        return conn

    if str(db_path) != ":memory:":
        # Codex#4 (round 7, 2026-09-12), reproduced exactly as reported: the
        # index can hold every non-secret classification, including
        # `confidential`, even when runtime retrieval never returns
        # confidential results - a local build produced a world-readable
        # (0o644) db and directory. Another local user reading the SQLite
        # file directly bypasses the classification filter entirely.
        #
        # Codex#4 (round 8, 2026-09-12), reproduced exactly as reported:
        # this chmod ran unconditionally, even when `parent` already
        # existed and was not ours to re-permission (a shared directory
        # the caller passed in, or - for a bare relative db_path like
        # "index.sqlite" - the current working directory itself, since
        # `Path("index.sqlite").parent == Path(".")`, which always
        # "exists"). Only chmod a directory this call actually created.
        parent = Path(db_path).parent
        parent_already_existed = parent.exists()
        parent.mkdir(parents=True, exist_ok=True)
        if not parent_already_existed:
            with contextlib.suppress(OSError):  # best-effort: no POSIX perms on this fs
                os.chmod(parent, 0o700)
        # Codex#6 (round 11, 2026-09-13): see untrusted_state_dir_reason()'s
        # own comment - the pre/post identity check further down can be
        # defeated by an ABA race (substitute, let SQLite write, restore
        # before the check runs); refusing to write at all into a
        # directory an untrusted writer could reach closes the actual
        # threat instead.
        untrusted = untrusted_state_dir_reason(parent)
        if untrusted is not None:
            raise UntrustedStateDirectoryError(untrusted)
        # Codex#4 (round 8, 2026-09-12): verify db_path's final component
        # is not a symlink (and is regular-file-safe to chmod) BEFORE
        # sqlite3 ever opens it - `open_no_follow` raises OSError (ELOOP)
        # rather than silently creating/opening through a planted symlink.
        #
        # Codex#3 (round 9, 2026-09-12), reproduced exactly as reported:
        # this descriptor was immediately closed, and `sqlite3.connect()`
        # below re-opens the same PATHNAME from scratch - a parent
        # directory an attacker can write to could substitute a symlink
        # or a different regular file for db_path in that window, and
        # Python's stdlib `sqlite3` module has no API to connect through
        # an already-open, already-verified file descriptor the way
        # `open_no_follow`'s own no-follow check can. Recording the
        # verified (st_dev, st_ino) here and comparing it against what
        # SQLite actually ended up opening (below, once connected) cannot
        # eliminate the race - no fd-based API is available to do that -
        # but it detects a substitution that happened in this window
        # instead of silently trusting whatever sqlite3.connect() found.
        pre_fd = open_no_follow(db_path, 0o600)
        pre_stat = os.fstat(pre_fd)
        pre_identity = (pre_stat.st_dev, pre_stat.st_ino)
        os.close(pre_fd)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    if str(db_path) != ":memory:":
        opened_path = conn.execute("PRAGMA database_list").fetchone()[2]
        post_stat = os.stat(opened_path)
        post_identity = (post_stat.st_dev, post_stat.st_ino)
        if pre_identity != post_identity:
            conn.close()
            raise ForeignDatabaseError(
                f"{db_path}: opened a different file than the one just verified "
                "(possible symlink/file substitution between check and use)"
            )
    if not _has_fts5(conn):
        conn.close()
        raise FTS5Unavailable(
            "SQLite FTS5 is required but not available in this Python build"
        )

    has_existing_content = (
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type IN ('table', 'view') LIMIT 1"
        ).fetchone()
        is not None
    )
    if has_existing_content:
        try:
            verify_application_id(conn, db_path)
        except ForeignDatabaseError:
            conn.close()
            raise
    else:
        # a genuinely fresh file (or an existing empty one) - safe to claim.
        conn.execute(f"PRAGMA application_id = {_APPLICATION_ID}")

    # Codex#4 (round 8, 2026-09-12), reproduced exactly as reported: the
    # chmod used to run right after sqlite3.connect() opened the file -
    # BEFORE the foreign-database check above had a chance to refuse it -
    # so a database this call was about to reject as "not ours" had
    # already had its permissions silently changed. Only touch permissions
    # once we know this file is either freshly ours or already verified.
    if str(db_path) != ":memory:":
        with contextlib.suppress(OSError):
            chmod_no_follow(db_path, 0o600)

    conn.executescript(SCHEMA)
    return conn
