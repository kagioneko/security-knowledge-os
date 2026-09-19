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
    with the sticky bit is not a substitution vector either.

    Follows symlinks along the way deliberately (this remains a pass/fail
    precondition check on the trust of the path a caller is ABOUT to use,
    not a race-proof no-follow read itself) - but does so one lexical
    component at a time (Codex#1, round 15, 2026-09-14), NOT via a single
    upfront `path.resolve()` as this used to. `.resolve()` silently erases
    evidence that a lexical ancestor was itself a symlink: given a
    world-writable `exposed/` containing `exposed/link -> elsewhere/`, the
    old check resolved straight through to `elsewhere` and only ever
    walked up FROM THERE, never once looking at `exposed` even though
    `exposed/link` is exactly the entry an attacker holding `exposed` can
    repoint at will. Walking lexically means every directory actually
    traversed - including the ones a symlink points through - gets
    checked, and the directory CONTAINING a symlink is checked before the
    symlink is followed (an untrusted writer there can repoint it).
    """
    components = [p for p in path.absolute().parts[1:] if p != ""]
    _, reason = _walk_lexical_ancestors(components[:-1], origin=path, hops=0)
    return reason


def existing_ancestors_untrusted_reason(path: Path) -> str | None:
    """Codex#3 / Antigravity SKOS-ADV-18 (round 17, 2026-09-14),
    reproduced exactly as reported: `connect()`/`reindex_atomic()` called
    `path.parent.mkdir(parents=True, exist_ok=True)` to create any
    missing ancestor directories BEFORE `untrusted_state_dir_reason()`
    ever ran - `mkdir(parents=True)` resolves and creates through an
    EXISTING symlink exactly like a normal `mkdir -p` would, so an
    attacker-owned `/tmp/skos-link -> /home/victim` with a configured db
    path of `/tmp/skos-link/new/index.sqlite` got `/home/victim/new`
    CREATED before the later trust check ever ran and refused to WRITE
    there - fail-closed on the write, but not on the side effect of
    having created a directory outside the intended lexical path at all.

    Callers use this to validate whatever CURRENTLY EXISTS along `path`'s
    ancestor chain is trustworthy BEFORE calling `mkdir(parents=True,
    exist_ok=True)` to create the rest - unlike
    `untrusted_ancestor_chain_reason()` above, a component that does not
    exist YET is not a failure here (there is nothing there yet for an
    attacker to have planted), it simply ends the walk at that boundary;
    everything that DOES already exist is still checked exactly the same
    way (ownership, write bits, symlink-entry ownership).
    """
    components = [p for p in path.absolute().parts[1:] if p != ""]
    _, reason = _walk_lexical_ancestors(
        components[:-1], origin=path, hops=0, stop_at_missing=True
    )
    return reason


def _is_trusted_symlink_owner(uid: int) -> bool:
    """A pre-existing symlink component is only followed when this process
    or root created it - the same rule `_walk_lexical_ancestors` applies.
    A function of its own so the race-injection tests can make a symlink
    they can only create as themselves look foreign."""
    return uid in (os.geteuid(), 0)


def make_dirs_no_follow(path: Path, mode: int = 0o700) -> None:
    """`mkdir -p`, but a component that appears between the caller's trust
    check and this call can not redirect the creation.

    Codex#3 (round 23, 2026-09-20), reproduced exactly as reported:
    `existing_ancestors_untrusted_reason()` validates what exists NOW,
    then `Path.mkdir(parents=True, exist_ok=True)` re-resolves the whole
    pathname. A component that did not exist at check time but was
    replaced by a symlink in between (a sticky /tmp lets anyone create
    entries) was followed by that `mkdir`, so `os.mkdir(parent)` created
    `/target/new` OUTSIDE the intended path - the later trust check
    refused the write, but only after the directory had been created.

    Each level is created with `mkdirat` relative to the already-open fd of
    its parent: `mkdirat` never follows a symlink in the final position
    (EEXIST), and a directory THIS call created is entered with
    O_NOFOLLOW. A component that already exists is entered normally, unless
    it is a symlink owned by neither this process nor root - refused before
    anything is created below it. (A symlink owned by this process can
    only be planted by the same uid, which can already write the state
    directory directly; that case is outside this threat model.)"""
    parts = [p for p in path.absolute().parts[1:] if p not in ("", ".")]
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in parts:
            created = False
            try:
                os.mkdir(name, mode, dir_fd=fd)
                created = True
            except OSError as mkdir_error:
                try:
                    st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except OSError:
                    # neither created nor present: a real failure (EACCES, EROFS, ...)
                    raise mkdir_error from None
                if stat.S_ISLNK(st.st_mode) and not _is_trusted_symlink_owner(st.st_uid):
                    raise UntrustedStateDirectoryError(
                        f"{name!r} on the path to {path} is a symlink owned by uid "
                        f"{st.st_uid} (neither this process nor root); refusing to "
                        "create anything through it"
                    ) from None
            flags = os.O_RDONLY | os.O_DIRECTORY | (os.O_NOFOLLOW if created else 0)
            next_fd = os.open(name, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
    finally:
        os.close(fd)


_MAX_SYMLINK_HOPS = 40  # matches a typical kernel ELOOP bound


def _walk_lexical_ancestors(
    components: list[str], *, origin: Path, hops: int, stop_at_missing: bool = False
) -> tuple[Path, str | None]:
    """Walk `components` (absolute, from the filesystem root) one entry at
    a time using `lstat` - never `.resolve()` - checking every directory
    actually traversed for untrusted-writability. `.`/`..` are resolved
    against the REAL current location as they are encountered, not
    stripped lexically ahead of time (a `..` following a symlink must
    apply to the symlink's TARGET directory, not the literal string
    before it). A symlink is followed only after its containing directory
    passes the check; its target's own components are then walked the
    same way, recursively, bounded by `_MAX_SYMLINK_HOPS` the same way the
    kernel bounds a resolution loop (ELOOP). A component that cannot be
    stat'd fails CLOSED, matching `_untrusted_directory_stat_reason`'s own
    OSError handling below - returning None here would let an
    unverifiable ancestor pass silently - UNLESS `stop_at_missing` is set
    and the failure is specifically "does not exist yet"
    (`FileNotFoundError`), in which case the walk stops cleanly at that
    boundary instead of failing (see `existing_ancestors_untrusted_reason`
    above for why: nothing exists there yet for an attacker to have
    planted). Any OTHER stat failure (permission denied, not a directory,
    ...) still fails closed even with `stop_at_missing` set.
    """
    if hops > _MAX_SYMLINK_HOPS:
        return Path("/"), f"too many levels of symbolic links resolving {origin}"
    current = Path("/")
    for name in components:
        if name in ("", "."):
            continue
        if name == "..":
            current = current.parent
            continue
        candidate = current / name
        try:
            st = candidate.lstat()
        except FileNotFoundError as exc:
            if stop_at_missing:
                return current, None
            return candidate, f"could not verify ownership/permissions of {candidate}: {exc}"
        except OSError as exc:
            return candidate, f"could not verify ownership/permissions of {candidate}: {exc}"
        if stat.S_ISLNK(st.st_mode):
            reason = _untrusted_directory_stat_reason(current)
            if reason is not None:
                return candidate, f"{reason}; contains a symlink on the path to {origin}"
            # Codex#1 / Antigravity SKOS-ADV-16 (round 16, 2026-09-14),
            # reproduced exactly as reported: checking only the
            # CONTAINING directory misses a symlink ENTRY an attacker
            # planted themselves inside a shared STICKY directory (e.g.
            # /tmp) - the sticky bit stops others from renaming/deleting
            # an entry they do not own, but it never stops them from
            # CREATING a new one, and says nothing about what a symlink
            # someone else made actually points to. The symlink entry
            # itself must be owned by this process or root too, checked
            # via the same `lstat` already taken above (never re-stat'd
            # through the link).
            if st.st_uid not in (os.geteuid(), 0):
                return candidate, (
                    f"{candidate} is a symlink owned by uid {st.st_uid} (neither "
                    "this process nor root); refusing to follow it, even inside "
                    f"a sticky directory, on the path to {origin}"
                )
            link_target = Path(os.readlink(candidate))
            if link_target.is_absolute():
                target_components = [p for p in link_target.parts[1:] if p != ""]
            else:
                target_components = [p for p in (current / link_target).parts[1:] if p != ""]
            resolved, reason = _walk_lexical_ancestors(
                target_components, origin=origin, hops=hops + 1, stop_at_missing=stop_at_missing
            )
            if reason is not None:
                return resolved, reason
            current = resolved
            continue
        reason = _untrusted_directory_stat_reason(candidate)
        if reason is not None:
            return candidate, (
                f"{reason}; an ancestor directory of {origin} could be renamed out from under it"
            )
        current = candidate
    return current, None


def _untrusted_directory_stat_reason(directory: Path) -> str | None:
    """The single-directory half of `untrusted_ancestor_chain_reason()`'s
    check - owned by an untrusted uid, or writable by OTHER, or by a
    group not proven private to this process, without the sticky bit.
    Shared so a caller that also needs to check a directory ITSELF (not
    just its ancestors) - see `app.ingestion.snapshot.snapshot_tree()`'s
    use on `root`, Codex#4 round 13, 2026-09-13 - gets the identical
    rule.

    Codex#1 / Antigravity SKOS-ADV-16 (round 16, 2026-09-14), reproduced
    exactly as reported: this only ever checked CURRENT write bits
    (group/other), never OWNERSHIP - a directory owned by a different,
    untrusted local account but currently mode 0755 (no group/other
    write bit) passed outright, even though that owner can chmod it
    writable, or replace/rename its contents outright, at any later
    time regardless of the bits observed a moment ago. Ownership, not
    today's permission bits, is what actually bounds who can ever make
    a directory unsafe - matching sshd(8)'s own StrictModes (every path
    component up to a trusted root must be owned by the target user or
    root)."""
    try:
        st = directory.stat()
    except OSError as exc:
        return f"could not verify ownership/permissions of {directory}: {exc}"
    if st.st_uid not in (os.geteuid(), 0):
        return (
            f"{directory} is owned by uid {st.st_uid} (neither this process "
            "nor root); refusing to trust it regardless of its current permission bits"
        )
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
    a race-proof no-follow read).

    Codex#4 / Antigravity SKOS-ADV-28 (round 20, 2026-09-15), reproduced
    exactly as reported: `Path.resolve(strict=False)` raises `RuntimeError`
    (not `OSError`) for a self-referential symlink loop (e.g. `ln -s
    skos-loop skos-loop`). Every caller of this function - directly or via
    `snapshot_tree()` - only catches `OSError`, expecting a typed
    `SnapshotError`/validation issue/`POLICY_BLOCKED` outcome; the raw
    `RuntimeError` escaped all of them, becoming a generic 500 instead of
    the fail-closed rejection this function exists to produce. A symlink
    loop is exactly as untrusted as any other directory this function
    already rejects by returning a reason string - report it the same
    way instead of letting resolution's own exception type leak through."""
    try:
        resolved = directory.resolve(strict=False)
    except RuntimeError as exc:
        return f"{directory}: could not be resolved (possible symlink loop): {exc}"
    return _untrusted_directory_stat_reason(resolved)


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
        #
        # Codex#2 (round 15, 2026-09-14), reproduced exactly as reported:
        # "only chmod if we created it" was itself still check-then-act -
        # `parent.exists()` (check) followed by `parent.mkdir(exist_ok=True)`
        # (act) leaves a window where an attacker able to write into
        # parent's own parent can plant a symlink to an unrelated,
        # differently-owned directory in between. `Path.mkdir(exist_ok=True)`
        # silently accepts a pre-existing symlink-to-a-directory (it only
        # checks `is_dir()`, which follows symlinks) instead of raising, so
        # the "not already existed" branch still ran - and `os.chmod()`
        # follows symlinks by default, re-permissioning whatever the
        # attacker's target was, not `parent` itself. Fixed by making
        # creation atomic (bare `os.mkdir`, which raises EEXIST for a
        # symlink exactly like it would for a real directory - no
        # exist_ok to silently swallow that) and only ever chmod'ing
        # through an fd opened O_DIRECTORY|O_NOFOLLOW - if a symlink (or
        # non-directory) is ever in that spot, the open itself fails
        # instead of chmod silently following it.
        parent = Path(db_path).parent
        # Codex#3 / Antigravity SKOS-ADV-18 (round 17, 2026-09-14),
        # reproduced exactly as reported: `parent.parent.mkdir(parents=
        # True, exist_ok=True)` resolves and creates through an EXISTING
        # symlink exactly like a normal `mkdir -p` would - an attacker-
        # owned `/tmp/skos-link -> /home/victim` with db_path configured
        # as `/tmp/skos-link/new/index.sqlite` got `/home/victim/new`
        # CREATED before `untrusted_state_dir_reason()` below ever ran and
        # refused to WRITE there. Fail-closed on the write, but not on the
        # side effect of having created a directory outside the intended
        # lexical path. Validating whatever currently EXISTS along the
        # ancestor chain first - before creating anything - closes this:
        # a pre-planted symlink is caught here, before mkdir ever touches it.
        untrusted = existing_ancestors_untrusted_reason(parent)
        if untrusted is not None:
            raise UntrustedStateDirectoryError(untrusted)
        make_dirs_no_follow(parent.parent)  # Codex#3 (round 23): race-safe `mkdir -p`
        try:
            os.mkdir(parent, 0o700)
            created_parent = True
        except FileExistsError:
            created_parent = False
        try:
            parent_fd = os.open(parent, os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as exc:
            raise UntrustedStateDirectoryError(
                f"state directory {parent} could not be safely opened "
                f"(may be a symlink or not a directory): {exc}"
            ) from exc
        try:
            if created_parent:
                with contextlib.suppress(OSError):  # best-effort: no POSIX perms on this fs
                    os.fchmod(parent_fd, 0o700)
        finally:
            os.close(parent_fd)
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

    # Codex#1 / Antigravity SKOS-ADV-26 (round 20, 2026-09-15): "close the
    # connection on every setup exception" - everything from here through
    # `conn.executescript(SCHEMA)` below used to leave `conn` open on any
    # exception the code didn't anticipate by name (e.g. a locked file
    # raising `sqlite3.OperationalError` out of a SELECT/PRAGMA call, or a
    # corrupt/non-sqlite file raising `sqlite3.DatabaseError`).
    #
    # Codex#5 (round 21, 2026-09-15), reproduced exactly as reported: the
    # round-20 fix only wrapped the has_existing_content check ONWARD -
    # the identity-verification `os.stat(opened_path)` call and the
    # `_has_fts5()` probe just above it (both added in earlier rounds,
    # each with their OWN explicit `conn.close()` before their OWN
    # anticipated raise) were still OUTSIDE any try/except: an unrelated,
    # unanticipated OSError from `os.stat(opened_path)` itself (the file
    # vanishing between connect() and this stat, say) propagated with
    # `conn` never closed. Moving the try to start immediately after
    # `sqlite3.connect()` covers the identity check and the FTS5 probe
    # too - closing `conn` a second time (via the explicit closes those
    # two checks already perform on their own anticipated failure) is a
    # documented no-op in sqlite3, so nothing needs to change about them;
    # this is now the single guarantee that ANY exception, anticipated by
    # name or not, from ANY setup step after connect() closes `conn`
    # before propagating.
    try:
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
            verify_application_id(conn, db_path)
        else:
            # Codex#1 / Antigravity SKOS-ADV-31 (round 21, 2026-09-15),
            # reproduced exactly as reported: "no tables/views" used to be
            # treated as sufficient proof this file was safe to claim as
            # a fresh index - but a file with an EMPTY schema can still
            # already carry a foreign, nonzero `application_id` (an
            # external application that stamped its own ID before ever
            # creating a table). Overwriting that ID and building the
            # SKOS schema into it silently hijacked a database that was
            # never ours to take. A genuinely fresh file's application_id
            # is 0 (SQLite's own default when never set); anything else
            # nonzero and not already ours is exactly as foreign as a
            # populated database with the wrong ID, and must be rejected
            # the same way.
            app_id = conn.execute("PRAGMA application_id").fetchone()[0]
            if app_id not in (0, _APPLICATION_ID):
                raise ForeignDatabaseError(
                    f"{db_path} has no tables but already carries a foreign "
                    f"application_id={app_id} (expected 0 or {_APPLICATION_ID}); "
                    "refusing to claim it as a fresh Security Knowledge OS index"
                )
            conn.execute(f"PRAGMA application_id = {_APPLICATION_ID}")

        # Codex#1 (round 19, 2026-09-14), reproduced exactly as reported:
        # `reindex_atomic()` copies/replaces db_path's MAIN file only -
        # SQLite's WAL sidecar (`<path>-wal`) and shared-memory file
        # (`<path>-shm`) are separate files it never touches. If a prior
        # writer (this project's own code has never set WAL explicitly,
        # but journal_mode is a property PERSISTED IN THE DATABASE FILE
        # ITSELF, so anything with write access to db_path - including an
        # untrusted process on a shared account - could) left db_path in
        # WAL mode with un-checkpointed pages sitting in `<path>-wal`,
        # that content survives a reindex untouched, and a later
        # connection that ends up in WAL mode for any reason would read
        # through it - the exact "reindex_atomic reports one revision, a
        # reader sees a different one" gap Codex reproduced (reported
        # revision A, visible revision C, `verify_chunk_hashes` still
        # ALLOWED because C was itself an internally-consistent,
        # previously-built valid index). Forcing every WRITE connection
        # this project ever opens back to the classic `DELETE`
        # rollback-journal mode - which SQLite implements as "checkpoint
        # everything in the WAL into the main file, then remove the
        # -wal/-shm sidecars", never as data loss - closes this at its
        # root: this project's own connections can never leave a
        # database in WAL mode for a later open (ours or anyone else's)
        # to be confused by, regardless of what mode a PRIOR writer left
        # it in.
        #
        # Codex#1 / Antigravity SKOS-ADV-26 (round 20, 2026-09-15),
        # reproduced exactly as reported: this PRAGMA used to run BEFORE
        # the verify_application_id() check just above - a persistent,
        # mutating operation (it checkpoints a WAL database's pending
        # pages into the main file and deletes its `-wal`/`-shm`
        # sidecars) executed against ANY database this function opened,
        # including one about to be rejected as foreign a few lines
        # later. Opening someone else's unrelated SQLite database (not
        # even a Security Knowledge OS index) in write mode silently
        # mutated it before `ForeignDatabaseError` was ever raised. This
        # is the exact same class of bug the chmod below was already
        # fixed for in round 8 (see that comment) - only touch the file
        # once we know this connection is either ours already or being
        # freshly claimed as ours.
        if str(db_path) != ":memory:":
            conn.execute("PRAGMA journal_mode = DELETE")

        # Codex#4 (round 8, 2026-09-12), reproduced exactly as reported:
        # the chmod used to run right after sqlite3.connect() opened the
        # file - BEFORE the foreign-database check above had a chance to
        # refuse it - so a database this call was about to reject as
        # "not ours" had already had its permissions silently changed.
        # Only touch permissions once we know this file is either
        # freshly ours or already verified.
        if str(db_path) != ":memory:":
            with contextlib.suppress(OSError):
                chmod_no_follow(db_path, 0o600)

        conn.executescript(SCHEMA)
    except BaseException:
        conn.close()
        raise

    return conn
