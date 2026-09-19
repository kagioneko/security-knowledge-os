"""app/storage/db.py: connection construction, read-only enforcement.

Regression for Codex cross-review finding #5 (2026-09-11): the read-only URI
used to be a bare f"file:{db_path}?mode=ro". A '#' in the path starts the URI
*fragment*, silently dropping "?mode=ro" (read-only stops being requested at
all) and truncating the path SQLite actually opens (a different file than
intended). '?' and '%' in the path have similar misparsing risks.
"""

from __future__ import annotations

import contextlib
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


def test_connect_does_not_mutate_a_foreign_wal_database_before_rejecting_it(
    tmp_path: Path,
) -> None:
    """Regression for Codex#1 / Antigravity SKOS-ADV-26 (round 20,
    2026-09-15), reproduced exactly as reported: the round-19
    `PRAGMA journal_mode = DELETE` fix ran BEFORE the foreign-database
    (application_id) check, so opening someone else's unrelated SQLite
    database in write mode - one left in WAL mode, exactly the shape the
    round-19 fix exists to defend against - silently checkpointed it and
    deleted its `-wal`/`-shm` sidecars before `ForeignDatabaseError` was
    ever raised, the same "mutate before reject" bug the chmod fix
    (round 8, see the test above) already closed for permissions. Same
    fix shape: only touch the file once it is known to be ours."""
    import sqlite3

    db_path = tmp_path / "foreign.sqlite"
    foreign = sqlite3.connect(str(db_path))
    assert foreign.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    foreign.execute("CREATE TABLE unrelated (x INTEGER)")
    foreign.commit()

    with pytest.raises(ForeignDatabaseError):
        connect(db_path)

    # the ORIGINAL connection (still open) is the authoritative way to read
    # back journal_mode without re-triggering a mode negotiation of our own.
    assert foreign.execute("PRAGMA journal_mode").fetchone()[0] == "wal", (
        "a rejected foreign database's journal_mode must be untouched"
    )
    foreign.close()


def test_connect_rejects_a_schema_empty_database_with_a_foreign_application_id(
    tmp_path: Path,
) -> None:
    """Regression for Codex#1 / Antigravity SKOS-ADV-31 (round 21,
    2026-09-15), reproduced exactly as reported: "no tables/views" was
    treated as sufficient proof a file was safe to claim as a fresh
    index - but a file with an EMPTY schema can already carry a foreign,
    nonzero application_id (an external application that stamped its own
    ID before ever creating a table). connect() used to overwrite that ID
    and build the SKOS schema into it instead of raising
    ForeignDatabaseError, silently hijacking a database that was never
    ours to take."""
    import sqlite3

    db_path = tmp_path / "foreign.sqlite"
    foreign = sqlite3.connect(str(db_path))
    foreign.execute("PRAGMA application_id = 305419896")  # 0x12345678, some OTHER app's ID
    foreign.commit()
    foreign.close()

    with pytest.raises(ForeignDatabaseError):
        connect(db_path)

    check = sqlite3.connect(str(db_path))
    try:
        assert check.execute("PRAGMA application_id").fetchone()[0] == 305419896, (
            "a rejected foreign database's application_id must be untouched"
        )
        assert (
            check.execute(
                "SELECT 1 FROM sqlite_master WHERE type IN ('table', 'view') LIMIT 1"
            ).fetchone()
            is None
        ), "a rejected foreign database must not have the SKOS schema installed"
    finally:
        check.close()


def test_connect_closes_the_connection_on_an_unanticipated_post_connect_setup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#5 (round 21, 2026-09-15), reproduced exactly as
    reported: the round-20 fix wrapped every write-path setup step from
    the has_existing_content check ONWARD in a single try/except that
    closes `conn` on any failure - but the identity-verification
    `os.stat(opened_path)` call (and the `_has_fts5()` probe) just above
    it were still OUTSIDE that guard, each only closing `conn` on the ONE
    failure shape it anticipated by name. An unrelated, unanticipated
    OSError from `os.stat(opened_path)` itself - the file vanishing
    between `sqlite3.connect()` and this stat, say - propagated with
    `conn` never closed."""
    import sqlite3

    import app.storage.db as db_module

    db_path = tmp_path / "idx.sqlite"
    real_stat = os.stat
    real_connect = db_module.sqlite3.connect
    connections: list[sqlite3.Connection] = []

    def spy_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        conn = real_connect(*args, **kwargs)  # type: ignore[arg-type]
        connections.append(conn)
        return conn

    def faulty_stat(path: object, *a: object, **kw: object) -> os.stat_result:
        if str(path).endswith("idx.sqlite"):
            raise OSError("simulated: vanished between connect() and identity check")
        return real_stat(path, *a, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(db_module.sqlite3, "connect", spy_connect)
    monkeypatch.setattr(db_module.os, "stat", faulty_stat)

    with pytest.raises(OSError, match="simulated"):
        connect(db_path)

    assert len(connections) == 1
    with pytest.raises(sqlite3.ProgrammingError):
        connections[0].execute("SELECT 1")  # a closed connection raises on use


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


def test_untrusted_ancestor_chain_flags_group_writable_by_a_non_private_group(
    tmp_path: Path, monkeypatch
) -> None:
    """Regression for Codex#4 (round 13, 2026-09-13), reproduced exactly as
    reported: round 12's check trusted a group-writable ancestor whenever
    the group's GID merely equalled this process's own effective GID -
    that does not prove the group is actually PRIVATE. Another local
    account sharing the same group (a real, common setup - project
    groups, `docker`, `adm`, ...) could still rename the ancestor.
    _group_is_private() (not GID equality) is now the actual gate;
    monkeypatched here directly since real group membership varies by
    system and this test must be deterministic."""
    import app.storage.db as db_module

    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o775)
    state = shared / "state"
    state.mkdir()
    os.chmod(state, 0o700)

    monkeypatch.setattr(db_module, "_group_is_private", lambda gid: False)

    reason = db_module.untrusted_ancestor_chain_reason(state / "idx.sqlite")
    assert reason is not None
    assert str(shared) in reason


def test_untrusted_ancestor_chain_allows_a_verified_private_group(
    tmp_path: Path, monkeypatch
) -> None:
    """The mirror case: a group-writable ancestor whose group genuinely IS
    private (this test forces the answer since real group membership
    varies by system) must still be allowed."""
    import app.storage.db as db_module

    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o775)
    state = shared / "state"
    state.mkdir()
    os.chmod(state, 0o700)

    monkeypatch.setattr(db_module, "_group_is_private", lambda gid: True)

    assert db_module.untrusted_ancestor_chain_reason(state / "idx.sqlite") is None


def test_untrusted_ancestor_chain_flags_a_directory_owned_by_another_uid(
    tmp_path: Path, monkeypatch
) -> None:
    """Regression for Codex#1 / Antigravity SKOS-ADV-16 (round 16,
    2026-09-14), reproduced exactly as reported: the trust check only
    ever inspected CURRENT write bits (group/other), never OWNERSHIP - a
    directory owned by a different, untrusted account but currently mode
    0755 (no group/other write bit at all) passed outright, even though
    that owner can chmod it writable, or replace its contents outright,
    at any later time regardless of the bits observed a moment ago.

    This directory is actually owned by the test process's own real uid
    (there is no other way to create one in a test). Forging
    `os.geteuid()` globally (an earlier version of this test did) also
    makes every REAL ancestor of `tmp_path` (e.g. `/tmp/pytest-of-
    <user>`, itself owned by the test's real uid, not root) look
    foreign-owned to this same check, which would reject the chain THERE
    first and make the test pass for the wrong reason - confirmed while
    investigating round 17's adjacent finding: `str(other_owned) in
    reason` passed even when the actual rejection came from `tmp_path`'s
    own real ancestor, since `other_owned`'s path string is a SUBSTRING
    of the origin path mentioned in that unrelated rejection's generic
    trailing clause. Faking ONLY `other_owned`'s own `.stat()` result
    (leaving `os.geteuid()` and every other path's real stat untouched)
    isolates the check to that one directory specifically."""
    from app.storage.db import untrusted_ancestor_chain_reason

    other_owned = tmp_path / "other_owned"
    other_owned.mkdir()
    os.chmod(other_owned, 0o755)  # deliberately NOT group/other-writable
    state = other_owned / "state"
    state.mkdir()
    os.chmod(state, 0o700)

    real_stat = Path.stat

    class _FakeForeignStat:
        def __init__(self, real: os.stat_result) -> None:
            self.st_uid = real.st_uid + 12345
            self.st_mode = real.st_mode
            self.st_gid = real.st_gid

    def _fake_stat(self: Path, *args: object, **kwargs: object) -> object:
        result = real_stat(self, *args, **kwargs)
        if self == other_owned:
            return _FakeForeignStat(result)
        return result

    monkeypatch.setattr(Path, "stat", _fake_stat)

    reason = untrusted_ancestor_chain_reason(state / "idx.sqlite")
    assert reason is not None
    assert "is owned by uid" in reason
    assert str(other_owned) in reason


def test_untrusted_ancestor_chain_allows_a_directory_owned_by_root(tmp_path: Path) -> None:
    """Mirror case: a root-owned ancestor (matching ordinary, safely-
    shared system directories like `/`, `/home`) must still be allowed
    even though it is not owned by this process. Faked via a stand-in
    stat result (constructing a real root-owned directory needs root)."""
    import app.storage.db as db_module

    real_stat = Path.stat

    class _FakeStat:
        st_uid = 0
        st_mode = 0o40755  # directory, mode 0755
        st_gid = 0

    def _fake_stat(self: Path, *args: object, **kwargs: object) -> object:
        if self.name == "root_owned":
            return _FakeStat()
        return real_stat(self, *args, **kwargs)

    root_owned = tmp_path / "root_owned"
    root_owned.mkdir()
    state = root_owned / "state"
    state.mkdir()
    os.chmod(state, 0o700)

    import unittest.mock as mock

    with mock.patch.object(Path, "stat", _fake_stat):
        assert db_module.untrusted_ancestor_chain_reason(state / "idx.sqlite") is None


def test_untrusted_ancestor_chain_flags_a_symlink_owned_by_another_uid_in_a_sticky_dir(
    tmp_path: Path, monkeypatch
) -> None:
    """Regression for Codex#1 / Antigravity SKOS-ADV-16 (round 16,
    2026-09-14), reproduced exactly as reported: the sticky bit stops
    others from renaming/deleting an entry they do not own, but never
    stops them from CREATING a new one (a symlink) inside a shared
    sticky directory like /tmp, and says nothing about what a symlink
    someone else made actually points to. Checking only the CONTAINING
    directory's trust (which passes for a sticky world-writable dir)
    missed this - the symlink ENTRY itself must be checked too.

    Isolating this specific check needs care: forging os.geteuid() also
    makes every REAL ancestor of tmp_path (e.g. /tmp/pytest-of-<user>,
    itself owned by the test's real uid, not root) look foreign-owned to
    the round-16 per-directory ownership check, which would otherwise
    reject the chain there first and make this test pass for the wrong
    reason (confirmed while investigating round 17's adjacent finding:
    the original version of this test asserted only `str(link) in
    reason`, which passed even when the actual rejection came from
    tmp_path's own real ancestor - link's path string is a SUBSTRING of
    the origin path mentioned in that unrelated rejection's generic
    trailing clause). Bypassing the regular-directory check via
    monkeypatch isolates the SYMLINK-entry-specific inline check (which
    does not call it) as the only thing that can produce a rejection
    here."""
    import app.storage.db as db_module

    monkeypatch.setattr(db_module, "_untrusted_directory_stat_reason", lambda directory: None)

    sticky_shared = tmp_path / "sticky_shared"
    sticky_shared.mkdir()
    os.chmod(sticky_shared, 0o1777)  # world-writable + sticky, like /tmp

    real_target = tmp_path / "real_target"
    real_target.mkdir()
    os.chmod(real_target, 0o700)

    link = sticky_shared / "link"
    link.symlink_to(real_target, target_is_directory=True)

    root = link / "knowledge"
    root.mkdir()

    # the symlink is actually owned by this test process's own real uid;
    # forge a different one so it LOOKS attacker-owned to the check.
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 12345)

    reason = db_module.untrusted_ancestor_chain_reason(root / "idx.sqlite")
    assert reason is not None
    assert "is a symlink owned by uid" in reason
    assert str(link) in reason


def test_untrusted_ancestor_chain_allows_a_self_owned_symlink_in_a_sticky_dir(
    tmp_path: Path,
) -> None:
    """Mirror case: a symlink this process itself created and owns,
    inside a shared sticky directory, must still be allowed."""
    from app.storage.db import untrusted_ancestor_chain_reason

    sticky_shared = tmp_path / "sticky_shared"
    sticky_shared.mkdir()
    os.chmod(sticky_shared, 0o1777)

    real_target = tmp_path / "real_target"
    real_target.mkdir()
    os.chmod(real_target, 0o700)

    link = sticky_shared / "link"
    link.symlink_to(real_target, target_is_directory=True)

    root = link / "knowledge"
    root.mkdir()
    os.chmod(root, 0o700)

    assert untrusted_ancestor_chain_reason(root / "idx.sqlite") is None


def test_untrusted_ancestor_chain_flags_a_world_writable_directory_behind_a_symlink(
    tmp_path: Path,
) -> None:
    """Regression for Codex#1 (round 15, 2026-09-14), reproduced exactly as
    reported: untrusted_ancestor_chain_reason() started with
    `path.resolve(strict=False)`, which silently follows every symlink
    before any check runs - erasing the evidence that a lexical ancestor
    was a symlink at all. A world-writable `exposed/` directory containing
    `exposed/link -> nicely_owned/target` let the OLD check see only
    `nicely_owned/target`'s own (fine) ancestors, never `exposed` itself,
    even though `exposed/link` is exactly the entry an attacker holding
    `exposed` can repoint at will."""
    from app.storage.db import untrusted_ancestor_chain_reason

    exposed = tmp_path / "exposed"
    exposed.mkdir()
    os.chmod(exposed, 0o777)

    nicely_owned = tmp_path / "nicely_owned"
    target = nicely_owned / "target"
    target.mkdir(parents=True)
    os.chmod(nicely_owned, 0o700)
    os.chmod(target, 0o700)

    link = exposed / "link"
    link.symlink_to(target, target_is_directory=True)

    root = link / "knowledge"
    root.mkdir()

    reason = untrusted_ancestor_chain_reason(root / "idx.sqlite")
    assert reason is not None
    assert str(exposed) in reason


def test_untrusted_ancestor_chain_allows_a_symlink_through_trusted_directories(
    tmp_path: Path,
) -> None:
    """Mirror case: a symlink whose containing directory (and whose
    target's own ancestors) are all trusted must still be allowed - the
    fix must not flag every symlink outright, only ones reachable through
    an untrusted directory."""
    from app.storage.db import untrusted_ancestor_chain_reason

    real = tmp_path / "real"
    target = real / "target"
    target.mkdir(parents=True)
    os.chmod(real, 0o700)
    os.chmod(target, 0o700)

    link_parent = tmp_path / "link_parent"
    link_parent.mkdir()
    os.chmod(link_parent, 0o700)
    link = link_parent / "link"
    link.symlink_to(target, target_is_directory=True)

    root = link / "knowledge"
    root.mkdir()

    assert untrusted_ancestor_chain_reason(root / "idx.sqlite") is None


def test_group_is_private_for_a_real_single_member_group() -> None:
    """Sanity check against the REAL system group database (not
    monkeypatched) - this process's own primary group, in the common
    single-user-workstation "user-private group" layout, has no explicit
    secondary members and exactly one primary-group member (this
    process's own account). Skips on a system where that convention does
    not hold (a shared primary group, or a system with no traditional
    passwd/group database at all)."""
    import grp
    import pwd

    from app.storage.db import _group_is_private

    own_gid = os.getegid()
    own_group = grp.getgrgid(own_gid)
    primary_members = {entry.pw_uid for entry in pwd.getpwall() if entry.pw_gid == own_gid}
    if own_group.gr_mem or primary_members != {os.geteuid()}:
        pytest.skip("this system's own primary group is not a private user-group")
    assert _group_is_private(own_gid) is True


def test_group_is_private_is_false_for_an_unknown_gid() -> None:
    from app.storage.db import _group_is_private

    assert _group_is_private(2**31 - 1) is False


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


def test_connect_does_not_create_directories_through_an_untrusted_symlink_ancestor(
    tmp_path: Path, monkeypatch
) -> None:
    """Regression for Codex#3 / Antigravity SKOS-ADV-18 (round 17,
    2026-09-14), reproduced exactly as reported: `parent.parent.mkdir(
    parents=True, exist_ok=True)` resolves and creates through an
    EXISTING symlink exactly like a normal `mkdir -p` would - an
    attacker-owned `/tmp/skos-link -> /home/victim` with db_path
    configured as `/tmp/skos-link/new/index.sqlite` got `/home/victim/
    new` CREATED before `untrusted_state_dir_reason()` ever ran and
    refused to WRITE there. Fail-closed on the write, but not on the
    side effect of having created a directory outside the intended
    lexical path at all - this test's real assertion is that `victim/
    new` is never created, not just that connect() eventually raises.

    The symlink's containing directory (`tmp_path`) is legitimately
    owned by this test process; only the symlink's OWN `.lstat()` result
    is faked to look foreign-owned (leaving `os.geteuid()` and every
    other path's real stat untouched) - see the sibling ownership tests
    above for why a global `os.geteuid()` forge would be unsound here
    too (tmp_path's own real ancestors would look foreign as well)."""
    from app.storage.db import UntrustedStateDirectoryError, connect

    victim = tmp_path / "victim"
    victim.mkdir()
    os.chmod(victim, 0o700)

    link = tmp_path / "skos-link"
    link.symlink_to(victim, target_is_directory=True)

    real_lstat = Path.lstat

    class _FakeForeignLstat:
        def __init__(self, real: os.stat_result) -> None:
            self.st_uid = real.st_uid + 12345
            self.st_mode = real.st_mode
            self.st_gid = real.st_gid

    def _fake_lstat(self: Path, *args: object, **kwargs: object) -> object:
        result = real_lstat(self, *args, **kwargs)
        if self == link:
            return _FakeForeignLstat(result)
        return result

    monkeypatch.setattr(Path, "lstat", _fake_lstat)

    db_path = link / "new" / "index.sqlite"

    with pytest.raises(UntrustedStateDirectoryError):
        connect(db_path)

    assert not (victim / "new").exists(), (
        "connect() must not create ANY directory through an untrusted symlink ancestor, "
        "even one it ultimately refuses to write into"
    )


def test_connect_state_dir_creation_does_not_chmod_a_racily_planted_symlinks_target(
    tmp_path: Path,
) -> None:
    """Regression for Codex#2 (round 15, 2026-09-14), reproduced exactly as
    reported (this IS Codex's own repro, adapted to pytest): the old
    check-then-act sequence - `parent.exists()`, then
    `parent.mkdir(exist_ok=True)`, then `os.chmod(parent, 0o700)` - let an
    attacker who can write into `parent`'s own parent plant a symlink to
    an unrelated, differently-owned directory in the window between the
    exists() check and the mkdir() call. `Path.mkdir(exist_ok=True)`
    silently accepts a pre-existing symlink-to-a-directory (only
    `is_dir()` is checked, which follows symlinks), so the "we created it"
    branch still ran and `os.chmod()` - which follows symlinks by default
    - re-permissioned the attacker's OWN directory instead of `parent`."""
    from unittest.mock import patch

    victim = tmp_path / "victim"
    victim.mkdir()
    os.chmod(victim, 0o755)

    state_link = tmp_path / "state"
    state_link.symlink_to(victim, target_is_directory=True)

    real_exists = Path.exists
    already_raced = {"done": False}

    def raced_exists(self: Path) -> bool:
        if self == state_link and not already_raced["done"]:
            already_raced["done"] = True
            return False  # simulates: checked just before the attacker plants the symlink
        return real_exists(self)

    # either outcome is acceptable here; the mode assertion below is the point
    with patch.object(Path, "exists", raced_exists), contextlib.suppress(Exception):
        connect(state_link / "index.sqlite").close()

    assert stat.S_IMODE(victim.stat().st_mode) == 0o755, (
        "connect() must never chmod a directory it did not itself create, "
        "even when racing a symlink into its intended state-directory path"
    )


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


def test_snapshot_tree_refuses_when_root_itself_is_untrusted(tmp_path: Path) -> None:
    """Regression for Codex#4 (round 13, 2026-09-13), reproduced exactly as
    reported: snapshot_tree() checked root's ANCESTORS (round 12) but
    never root ITSELF - a root directly writable by an untrusted group/
    other (without the sticky bit) can be substituted the same way,
    without needing to touch anything above it."""
    from app.ingestion.snapshot import SnapshotError, snapshot_tree

    root = tmp_path / "knowledge"
    root.mkdir()
    os.chmod(root, 0o777)
    (root / "ku.md").write_text("content", encoding="utf-8")

    with pytest.raises(SnapshotError, match=str(root)):
        snapshot_tree(root)


def test_connect_does_not_create_directories_through_a_symlink_planted_after_the_trust_check(
    tmp_path: Path, monkeypatch
) -> None:
    """Regression for Codex#3 (round 23, 2026-09-20), reproduced exactly as
    reported: the round-17 fix validates whatever EXISTS along the ancestor
    chain and then calls `mkdir(parents=True, exist_ok=True)` - but a
    component that was still MISSING at check time can be replaced by a
    symlink in the gap (a sticky /tmp lets anyone create entries), and that
    `mkdir` then followed it and created `/target/new` outside the intended
    path. The check is wrapped so the symlink is planted at exactly that
    moment: right after the real check returned clean."""
    import app.storage.db as db_module

    outside = tmp_path / "outside"
    outside.mkdir()
    shared = tmp_path / "shared"
    shared.mkdir()
    db_path = shared / "skos-race" / "new" / "index.sqlite"

    real_check = db_module.existing_ancestors_untrusted_reason

    def check_then_plant(path: Path) -> str | None:
        result = real_check(path)
        (shared / "skos-race").symlink_to(outside, target_is_directory=True)
        return result

    monkeypatch.setattr(db_module, "existing_ancestors_untrusted_reason", check_then_plant)
    # Only the planted link is "foreign": tests run as one uid and cannot create a
    # symlink owned by someone else (see the ownership tests above for why a global
    # os.geteuid() forge is unsound here).
    monkeypatch.setattr(db_module, "_is_trusted_symlink_owner", lambda uid: False)

    with pytest.raises(db_module.UntrustedStateDirectoryError, match="symlink"):
        db_module.connect(db_path)

    assert list(outside.iterdir()) == [], "a directory was created THROUGH the planted symlink"


def test_make_dirs_no_follow_creates_a_normal_chain_with_private_mode(tmp_path: Path) -> None:
    from app.storage.db import make_dirs_no_follow

    target = tmp_path / "a" / "b" / "c"
    make_dirs_no_follow(target)
    make_dirs_no_follow(target)  # idempotent, like exist_ok=True

    assert target.is_dir()
    assert (target.stat().st_mode & 0o777) == 0o700


def test_make_dirs_no_follow_still_accepts_a_symlink_this_process_owns(tmp_path: Path) -> None:
    from app.storage.db import make_dirs_no_follow

    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real, target_is_directory=True)

    make_dirs_no_follow(tmp_path / "link" / "sub")

    assert (real / "sub").is_dir()
