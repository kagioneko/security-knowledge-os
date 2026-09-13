"""app/storage/db.py: connection construction, read-only enforcement.

Regression for Codex cross-review finding #5 (2026-09-11): the read-only URI
used to be a bare f"file:{db_path}?mode=ro". A '#' in the path starts the URI
*fragment*, silently dropping "?mode=ro" (read-only stops being requested at
all) and truncating the path SQLite actually opens (a different file than
intended). '?' and '%' in the path have similar misparsing risks.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from urllib.request import url2pathname

import pytest

from app.storage.db import ForeignDatabaseError, FTS5Unavailable, _read_only_uri, connect


@pytest.mark.parametrize(
    "name",
    [
        "plain.sqlite",
        "has#hash.sqlite",
        "has?question.sqlite",
        "has%percent.sqlite",
        "has space.sqlite",
        "has#?%mixed and space.sqlite",
    ],
)
def test_read_only_uri_round_trips_special_characters(tmp_path: Path, name: str) -> None:
    db_path = tmp_path / name
    uri = _read_only_uri(db_path)
    parts = urlsplit(uri)

    assert parts.fragment == "", "a character leaked into the URI fragment"
    assert parse_qs(parts.query) == {"mode": ["ro"]}, "mode=ro must survive as a real query param"
    assert Path(url2pathname(parts.path)).resolve() == db_path.resolve()


def test_read_only_uri_memory_special_case() -> None:
    assert _read_only_uri(":memory:") == "file::memory:?mode=ro"


def test_connect_read_only_opens_the_intended_file_despite_hash(tmp_path: Path) -> None:
    db_path = tmp_path / "idx#with a?weird%name.sqlite"
    conn = connect(db_path)  # read-write: creates the schema
    conn.execute("INSERT INTO meta (key, value) VALUES ('probe', 'yes')")
    conn.commit()
    conn.close()

    ro = connect(db_path, read_only=True)
    try:
        row = ro.execute("SELECT value FROM meta WHERE key = 'probe'").fetchone()
        assert row is not None and row[0] == "yes"
    finally:
        ro.close()


def test_missing_fts5_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import app.storage.db as db_module

    monkeypatch.setattr(db_module, "_has_fts5", lambda conn: False)
    with pytest.raises(FTS5Unavailable):
        connect(tmp_path / "no-fts5.sqlite")


def test_connect_does_not_chmod_a_preexisting_parent_directory(tmp_path: Path) -> None:
    """Regression for Codex#4 (round 8, 2026-09-12), reproduced exactly as
    reported: `connect()` chmod'd `db_path.parent` to 0o700 unconditionally,
    even when that directory already existed and was not this call's to
    re-permission - a database placed inside an existing, deliberately
    0o755 shared directory silently had that directory's permissions
    changed."""
    parent = tmp_path / "shared"
    parent.mkdir(mode=0o755)
    os.chmod(parent, 0o755)  # mkdir's mode is umask-adjusted; force the exact value

    connect(parent / "idx.sqlite").close()

    assert stat.S_IMODE(parent.stat().st_mode) == 0o755


def test_connect_refuses_to_write_into_a_world_writable_directory(tmp_path: Path) -> None:
    """Regression for Codex#6 (round 11, 2026-09-13), reproduced exactly as
    reported: connect()'s write-path identity check (pre-open O_NOFOLLOW
    stat, sqlite3.connect(), post-open PRAGMA database_list + os.stat())
    can be defeated by an ABA race - substitute a symlink, let SQLite
    write through it, then restore the original pathname BEFORE the
    post-check runs; the post-check re-resolves the pathname AFTER the
    restore and observes the (by then correct) identity. Every such
    substitution needs an attacker able to write in db_path's parent
    directory - connect() now refuses outright to write into one that is
    group- or world-writable, closing the actual threat rather than
    continuing to chase an unwinnable stat-then-open race. This is the
    same check reindex_atomic() applies to itself (round 11, Codex#3),
    now shared so every direct connect() write-path caller gets it too,
    not just the reindex path."""
    from app.storage.db import UntrustedStateDirectoryError

    parent = tmp_path / "shared"
    parent.mkdir()
    os.chmod(parent, 0o777)

    with pytest.raises(UntrustedStateDirectoryError):
        connect(parent / "idx.sqlite")

    assert not (parent / "idx.sqlite").exists()


def test_connect_rejects_a_symlinked_db_path(tmp_path: Path) -> None:
    """Regression for Codex#4 (round 8, 2026-09-12), reproduced exactly as
    reported: `os.chmod(db_path, ...)` follows a symlink at that exact
    path - precreating db_path as a symlink to an unrelated file caused
    the chmod to silently re-permission that unrelated TARGET. connect()
    must refuse a symlinked db_path outright rather than open or chmod
    through it."""
    target = tmp_path / "unrelated.txt"
    target.write_text("not a database", encoding="utf-8")
    os.chmod(target, 0o644)
    db_path = tmp_path / "idx.sqlite"
    db_path.symlink_to(target)

    with pytest.raises(OSError):
        connect(db_path)

    assert stat.S_IMODE(target.stat().st_mode) == 0o644, "the symlink TARGET must be untouched"


def test_connect_detects_a_file_swapped_between_verification_and_sqlite_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#3 (round 9, 2026-09-12), reproduced exactly as
    reported: connect() opens db_path with O_NOFOLLOW, immediately closes
    that descriptor, and then reopens the same PATHNAME through
    sqlite3.connect() - a parent directory an attacker can write to could
    substitute a different file for db_path in that window; nothing
    detected it. Monkeypatching sqlite3.connect (called immediately after
    the verified descriptor is closed) to swap the file first simulates
    exactly that."""
    import sqlite3 as sqlite3_module

    import app.storage.db as db_module

    db_path = tmp_path / "idx.sqlite"
    connect(db_path).close()  # a real, pre-existing SKOS index

    # a DIFFERENT file that is ALSO a legitimate SKOS index (correct
    # application_id) - the substitution must be caught by identity
    # (st_dev, st_ino) alone, not by the pre-existing application_id
    # check (Codex#4, round 6), which this file would satisfy too.
    other = tmp_path / "other.sqlite"
    connect(other).close()

    real_connect = sqlite3_module.connect

    def swap_then_connect(path: str, *a: object, **kw: object) -> sqlite3_module.Connection:
        if path == str(db_path):
            os.replace(other, db_path)
        return real_connect(path, *a, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(db_module.sqlite3, "connect", swap_then_connect)

    with pytest.raises(ForeignDatabaseError, match="different file"):
        connect(db_path)


def test_connect_does_not_chmod_a_foreign_database_before_rejecting_it(
    tmp_path: Path,
) -> None:
    """Regression for Codex#4 (round 8, 2026-09-12), reproduced exactly as
    reported: the chmod used to run immediately after sqlite3.connect()
    opened the file - BEFORE the foreign-database (application_id) check
    had a chance to refuse it - so a database this call was about to
    reject as "not ours" had already had its permissions silently
    changed."""
    import sqlite3

    db_path = tmp_path / "foreign.sqlite"
    foreign = sqlite3.connect(str(db_path))
    foreign.execute("CREATE TABLE unrelated (x INTEGER)")
    foreign.commit()
    foreign.close()
    os.chmod(db_path, 0o644)

    with pytest.raises(ForeignDatabaseError):
        connect(db_path)

    assert stat.S_IMODE(db_path.stat().st_mode) == 0o644, "a rejected foreign db must be untouched"


def test_untrusted_ancestor_chain_flags_a_world_writable_ancestor_without_sticky(
    tmp_path: Path,
) -> None:
    """Regression for Codex#4 (round 12, 2026-09-13), reproduced exactly as
    reported: untrusted_state_dir_reason() (and the identical no-follow-at-
    the-root check in app.ingestion.snapshot.snapshot_tree()) only ever
    checked the directory itself, never anything above it - an attacker
    able to rename an ANCESTOR (which needs write access only to that
    ancestor's own parent, not to the perfectly-owned, mode-0700 directory
    itself) could still substitute the whole tree."""
    from app.storage.db import untrusted_ancestor_chain_reason

    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o777)
    state = shared / "state"
    state.mkdir()
    os.chmod(state, 0o700)

    reason = untrusted_ancestor_chain_reason(state / "idx.sqlite")
    assert reason is not None
    assert str(shared) in reason


def test_untrusted_ancestor_chain_allows_a_sticky_world_writable_ancestor(
    tmp_path: Path,
) -> None:
    """A world-writable ancestor with the sticky bit set (like /tmp itself)
    is not a substitution vector - only the entry's owner, the directory's
    owner, or root can rename/unlink an entry inside it."""
    from app.storage.db import untrusted_ancestor_chain_reason

    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o1777)
    state = shared / "state"
    state.mkdir()
    os.chmod(state, 0o700)

    assert untrusted_ancestor_chain_reason(state / "idx.sqlite") is None


def test_untrusted_ancestor_chain_allows_group_writable_by_our_own_group(
    tmp_path: Path,
) -> None:
    """Regression for the round-12 self-review fix: a group-writable
    ancestor whose group IS this process's own primary group (the common
    single-user-workstation "user-private group" layout - this project's
    own repository directory is exactly this shape) must not be flagged;
    only a group OTHER than our own, or world-writable, is untrusted."""
    from app.storage.db import untrusted_ancestor_chain_reason

    project = tmp_path / "project"
    project.mkdir()
    os.chmod(project, 0o775)
    state = project / "state"
    state.mkdir()
    os.chmod(state, 0o700)

    assert untrusted_ancestor_chain_reason(state / "idx.sqlite") is None


def test_untrusted_ancestor_chain_flags_group_writable_by_a_different_group(
    tmp_path: Path, monkeypatch
) -> None:
    """A group-writable ancestor whose group is NOT this process's own is
    exactly the shared-with-untrusted-others case the check exists for."""
    import app.storage.db as db_module

    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o775)
    state = shared / "state"
    state.mkdir()
    os.chmod(state, 0o700)

    monkeypatch.setattr(db_module.os, "getegid", lambda: shared.stat().st_gid + 1)

    reason = db_module.untrusted_ancestor_chain_reason(state / "idx.sqlite")
    assert reason is not None
    assert str(shared) in reason


def test_connect_refuses_to_write_when_an_ancestor_is_untrusted(tmp_path: Path) -> None:
    """Integration regression for Codex#4 (round 12, 2026-09-13): connect()
    only ever checked db_path's IMMEDIATE parent via
    untrusted_state_dir_reason() - a correctly-owned, mode-0700 parent
    below a world-writable grandparent used to pass outright."""
    from app.storage.db import UntrustedStateDirectoryError

    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o777)
    state = shared / "state"
    state.mkdir()
    os.chmod(state, 0o700)

    with pytest.raises(UntrustedStateDirectoryError):
        connect(state / "idx.sqlite")


def test_snapshot_tree_refuses_when_an_ancestor_of_root_is_untrusted(tmp_path: Path) -> None:
    """Integration regression for Codex#4 (round 12, 2026-09-13):
    snapshot_tree()'s O_NOFOLLOW open protects `root` itself from being a
    symlink, but every ancestor ABOVE root was still resolved the normal
    way - a world-writable grandparent (no sticky bit) let an attacker
    rename it out from under an otherwise perfectly-owned root."""
    from app.ingestion.snapshot import SnapshotError, snapshot_tree

    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o777)
    root = shared / "knowledge"
    root.mkdir()
    (root / "ku.md").write_text("content", encoding="utf-8")

    with pytest.raises(SnapshotError, match=str(shared)):
        snapshot_tree(root)
