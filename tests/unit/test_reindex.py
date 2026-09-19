"""M6: reindex is atomic and fail-closed; it never changes knowledge content.

``reindex_atomic`` refuses outright if the knowledge root has ANY validation
error (including a stray ``classification: secret`` file) - that is a deliberate
fail-closed choice, so these tests use clean corpora for the success path.
"""

from __future__ import annotations

import contextlib
import os
import stat
from pathlib import Path

import pytest

from app.models.policy_outcome import PolicyOutcome
from app.retrieval.index import IndexBuildError, build_index, reindex_atomic
from app.storage.db import connect
from app.storage.repository import ChunkRepository


def _revision(db: Path) -> str | None:
    conn = connect(db, read_only=True)
    try:
        return ChunkRepository(conn).knowledge_revision()
    finally:
        conn.close()


def test_reindex_from_scratch(tmp_path: Path, corpus_alt_root: Path) -> None:
    db = tmp_path / "idx.sqlite"
    report = reindex_atomic(corpus_alt_root, db)
    assert report.ok, report.decision.reasons
    assert report.old_revision is None
    assert report.new_revision is not None
    assert _revision(db) == report.new_revision
    assert list(tmp_path.glob("idx.sqlite.staging.*")) == []
    assert list(tmp_path.glob("idx.sqlite.bak.*")) == []


def test_reindex_refuses_a_world_writable_state_directory(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for Codex#3 (round 11, 2026-09-13), reproduced exactly as
    reported: the round-10 fixes (Codex#1/#2) each narrowed a symlink-
    substitution TOCTOU in reindex_atomic()'s publish path to a single
    stat-then-use gap, but a residual window is provably unavoidable
    through more syscalls alone - POSIX has no rename-from-fd or
    replace-from-fd primitive, so the code itself documented this as an
    accepted residual risk. The actual guarantee against every attack in
    this class is that an untrusted writer cannot write into db_path's
    parent directory at all; reindex_atomic() now verifies that
    precondition and refuses outright rather than publishing under a
    directory anyone else could already write into."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    os.chmod(state_dir, 0o777)
    db = state_dir / "idx.sqlite"

    report = reindex_atomic(corpus_alt_root, db)

    assert not report.ok
    assert report.decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert "writable" in " ".join(report.decision.reasons)
    assert not db.exists()


def test_reindex_refuses_a_state_directory_not_owned_by_this_process(
    tmp_path: Path, corpus_alt_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same protection as above, for the ownership half of the check -
    simulated via monkeypatching os.geteuid() since a real ownership
    mismatch needs a second local account. Forging our OWN euid also
    makes every EXISTING ancestor look foreign-owned, so round-17's
    earlier existing_ancestors_untrusted_reason() pre-check (Codex#3 /
    SKOS-ADV-18) now catches this before untrusted_state_dir_reason()'s
    own later check on state_dir itself ever runs - both are ownership
    rejections, just from different call sites, so the assertion checks
    for "owned" generically rather than either one's exact wording."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    db = state_dir / "idx.sqlite"

    real_geteuid = os.geteuid
    monkeypatch.setattr(os, "geteuid", lambda: real_geteuid() + 1)

    report = reindex_atomic(corpus_alt_root, db)

    assert not report.ok
    assert report.decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert "owned" in " ".join(report.decision.reasons)
    assert not db.exists()


def test_reindex_does_not_create_directories_through_an_untrusted_symlink_ancestor(
    tmp_path: Path, corpus_alt_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#3 / Antigravity SKOS-ADV-18 (round 17,
    2026-09-14), reproduced exactly as reported: `.parent.mkdir(parents=
    True, exist_ok=True)` resolves and creates through an EXISTING
    symlink exactly like a normal `mkdir -p` would - an attacker-owned
    symlink ancestor got a directory CREATED on the other side of it
    before the trust check ever ran and refused to WRITE there. Fail-
    closed on the write, but not on the side effect of having created a
    directory outside the intended lexical path at all - this test's
    real assertion is that `victim/new` is never created, not just that
    reindex_atomic() eventually reports POLICY_BLOCKED.

    Only the symlink's own `.lstat()` result is faked to look foreign-
    owned (leaving `os.geteuid()` and every other path's real stat
    untouched) - see the identical technique and its own rationale in
    tests/unit/test_db.py's sibling test for connect()."""
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

    db = link / "new" / "index.sqlite"
    report = reindex_atomic(corpus_alt_root, db)

    assert not report.ok
    assert report.decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert not (victim / "new").exists(), (
        "reindex_atomic() must not create ANY directory through an untrusted symlink "
        "ancestor, even one it ultimately refuses to write into"
    )


def test_reindex_replaces_and_reports_old_revision(tmp_path: Path, corpus_alt_root: Path) -> None:
    db = tmp_path / "idx.sqlite"
    first = reindex_atomic(corpus_alt_root, db)
    second = reindex_atomic(corpus_alt_root, db)
    assert second.ok
    assert second.old_revision == first.new_revision
    assert second.new_revision == first.new_revision


def test_reindex_fails_closed_and_keeps_the_old_index(
    tmp_path: Path, corpus_alt_root: Path, fixture_knowledge_root: Path
) -> None:
    db = tmp_path / "idx.sqlite"
    good = reindex_atomic(corpus_alt_root, db)
    good_revision = good.new_revision

    # the fixture knowledge root has invalid units + a secret-classified file
    bad = reindex_atomic(fixture_knowledge_root, db)
    assert not bad.ok
    assert bad.decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert _revision(db) == good_revision  # existing index untouched
    assert list(tmp_path.glob("idx.sqlite.staging.*")) == []
    assert list(tmp_path.glob("idx.sqlite.bak.*")) == []


def test_reindex_returns_policy_blocked_when_current_revision_hits_fts5_unavailable(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for Codex#3 (round 15, 2026-09-14), reproduced exactly as
    reported: FTS5Unavailable (raised by connect() when the SQLite build
    lacks the FTS5 extension) is a RuntimeError subclass, not one of the
    types the pre-swap except clause around _current_revision() caught -
    it escaped as a raw exception instead of the typed POLICY_BLOCKED
    ReindexReport every other failure path here returns. The existing
    index is never touched either way (this never gets far enough to
    write one)."""
    import app.retrieval.index as index_module
    from app.storage.db import FTS5Unavailable

    db = tmp_path / "idx.sqlite"
    good = reindex_atomic(corpus_alt_root, db)
    assert good.ok

    original_connect = index_module.connect

    def _flaky(path, *, read_only=False):  # type: ignore[no-untyped-def]
        if Path(path) == db:
            raise FTS5Unavailable("simulated: FTS5 unavailable in this build")
        return original_connect(path, read_only=read_only)

    index_module.connect = _flaky
    try:
        report = reindex_atomic(corpus_alt_root, db)
    finally:
        index_module.connect = original_connect

    assert not report.ok
    assert report.decision.outcome is PolicyOutcome.POLICY_BLOCKED


def test_reindex_returns_policy_blocked_when_staging_integrity_check_hits_fts5_unavailable(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for Codex#3 (round 15, 2026-09-14): the build-step's own
    pre-swap except clause (around building + integrity-checking the
    STAGING index, before publish) had the identical FTS5Unavailable gap
    - connect(staging, read_only=True) can raise it too, and this is also
    a pre-swap failure path where db_path must stay untouched."""
    import app.retrieval.index as index_module
    from app.storage.db import FTS5Unavailable

    db = tmp_path / "idx.sqlite"
    good = reindex_atomic(corpus_alt_root, db)
    good_revision = good.new_revision
    assert good.ok

    original_connect = index_module.connect

    def _flaky(path, *, read_only=False):  # type: ignore[no-untyped-def]
        if ".staging." in Path(path).name:
            raise FTS5Unavailable("simulated: FTS5 unavailable in this build")
        return original_connect(path, read_only=read_only)

    index_module.connect = _flaky
    try:
        report = reindex_atomic(corpus_alt_root, db)
    finally:
        index_module.connect = original_connect

    assert not report.ok
    assert report.decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert _revision(db) == good_revision  # existing index untouched (pre-swap failure)
    assert list(tmp_path.glob("idx.sqlite.staging.*")) == []
    assert list(tmp_path.glob("idx.sqlite.bak.*")) == []


def test_reindex_from_a_missing_root_fails_closed_and_keeps_the_old_index(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for Codex cross-review finding #4 (2026-09-11): a missing
    knowledge root used to validate as "clean" (rglob on it yields nothing, so
    zero issues) and reindex would happily replace a real index with an empty
    one - the empty index still passes integrity checking, since 0 chunks is
    internally consistent."""
    db = tmp_path / "idx.sqlite"
    good = reindex_atomic(corpus_alt_root, db)
    good_revision = good.new_revision

    bad = reindex_atomic(tmp_path / "no-such-knowledge-root", db)
    assert not bad.ok
    assert bad.decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert _revision(db) == good_revision  # existing index untouched, NOT emptied
    assert list(tmp_path.glob("idx.sqlite.staging.*")) == []
    assert list(tmp_path.glob("idx.sqlite.bak.*")) == []


def test_reindex_atomic_refuses_an_empty_but_existing_root(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for Codex#3 (round 6, 2026-09-12), reproduced exactly as
    reported: a knowledge root that EXISTS but contains zero files has zero
    validation errors (unlike the missing-root case above), so
    reindex_atomic() itself - not just the scripts/build_index.py CLI
    (Codex#7, round 5) - happily replaced a real, populated index with an
    empty one. The API's /v1/knowledge/reindex calls this function
    directly with no guard of its own, so this must be fixed here."""
    db = tmp_path / "idx.sqlite"
    good = reindex_atomic(corpus_alt_root, db)
    good_revision = good.new_revision
    assert good.chunks_indexed > 0

    empty_root = tmp_path / "empty-knowledge-root"
    empty_root.mkdir()

    bad = reindex_atomic(empty_root, db)
    assert not bad.ok
    assert bad.decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert _revision(db) == good_revision  # existing, populated index untouched
    assert list(tmp_path.glob("idx.sqlite.staging.*")) == []
    assert list(tmp_path.glob("idx.sqlite.bak.*")) == []


def test_reindex_refuses_to_clobber_an_unrelated_sqlite_database(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for Codex#4 (round 6, 2026-09-12), reproduced exactly as
    reported: an unrelated SQLite database's identity was checked only by
    querying meta(key,value) - CREATE TABLE IF NOT EXISTS is idempotent, so
    any file that happens to already have a compatible `meta` table
    (created by something else entirely) was silently adopted as "an
    existing SKOS index" and then atomically replaced, destroying whatever
    it actually held."""
    import sqlite3

    other = tmp_path / "other.sqlite"
    conn = sqlite3.connect(other)
    conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.execute("CREATE TABLE precious (v TEXT NOT NULL)")
    conn.execute("INSERT INTO precious(v) VALUES ('do not delete me')")
    conn.commit()
    conn.close()

    report = reindex_atomic(corpus_alt_root, other)
    assert not report.ok
    assert report.decision.outcome is PolicyOutcome.POLICY_BLOCKED

    conn = sqlite3.connect(other)
    try:
        rows = conn.execute("SELECT v FROM precious").fetchall()
    finally:
        conn.close()
    assert rows == [("do not delete me",)]  # untouched


def test_reindex_restores_previous_index_on_post_swap_failure(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for Codex cross-review finding #3 / Antigravity B6.2
    (2026-09-11): a failed post-swap integrity check used to leave the freshly
    (and now known-bad) swapped-in index live, with the previous good index
    already gone - reindex_atomic reported POLICY_BLOCKED but the system was
    left serving a broken index. The previous index must be restored.

    Uses a second corpus with genuinely different content (not just a second
    build of the same corpus) so the revision left in db afterwards can only
    match good_revision if it was actually restored, not by coincidence."""
    import shutil

    import app.retrieval.index as index_module

    db = tmp_path / "idx.sqlite"
    good = reindex_atomic(corpus_alt_root, db)
    good_revision = good.new_revision
    assert _revision(db) == good_revision

    corpus2 = tmp_path / "corpus2"
    shutil.copytree(corpus_alt_root, corpus2)
    ku = next(corpus2.glob("public/**/*.md"))
    ku.write_text(ku.read_text(encoding="utf-8").replace("0.1", "0.2"), encoding="utf-8")

    class _FakeStop:
        is_allowed = False
        reasons = ["simulated post-swap corruption"]

    original = index_module.verify_chunk_hashes
    calls = {"n": 0}

    def _flaky(conn):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if calls["n"] == 2:  # 1st call = staging check (let it pass); 2nd = post-swap
            return _FakeStop()
        return original(conn)

    index_module.verify_chunk_hashes = _flaky  # type: ignore[assignment]
    try:
        bad = reindex_atomic(corpus2, db)
    finally:
        index_module.verify_chunk_hashes = original  # type: ignore[assignment]

    assert not bad.ok
    assert bad.decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert bad.new_revision != good_revision  # the *attempted* new content really differed
    assert _revision(db) == good_revision  # but db was restored, not left on the bad content
    assert list(tmp_path.glob("idx.sqlite.staging.*")) == []
    assert list(tmp_path.glob("idx.sqlite.bak.*")) == []


def test_reindex_restores_backup_on_post_swap_exception_not_a_stop_decision(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for Codex cross-review finding #1 (round 3, 2026-09-12):
    the exception handler around the publish step used to be `except OSError`
    and unconditionally `_cleanup(staging, backup)` regardless of whether
    os.replace() had already published the new (as yet unverified) content to
    db_path - once published, `staging` no longer exists and `backup` is the
    only copy of the last known-good index, so deleting it left the
    unverified new content live with no way back. It also missed
    sqlite3.Error subclasses verify_chunk_hashes can raise that are not
    OSError."""
    import sqlite3

    import app.retrieval.index as index_module

    db = tmp_path / "idx.sqlite"
    good = reindex_atomic(corpus_alt_root, db)
    good_revision = good.new_revision
    assert _revision(db) == good_revision

    corpus2 = tmp_path / "corpus2"
    import shutil

    shutil.copytree(corpus_alt_root, corpus2)
    ku = next(corpus2.glob("public/**/*.md"))
    ku.write_text(ku.read_text(encoding="utf-8").replace("0.1", "0.2"), encoding="utf-8")

    calls = {"n": 0}
    original = index_module.verify_chunk_hashes

    def _flaky(conn):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if calls["n"] == 2:  # 1st call = staging check (let it pass); 2nd = post-swap
            raise sqlite3.OperationalError("simulated post-swap read failure")
        return original(conn)

    index_module.verify_chunk_hashes = _flaky  # type: ignore[assignment]
    try:
        bad = reindex_atomic(corpus2, db)
    finally:
        index_module.verify_chunk_hashes = original  # type: ignore[assignment]

    assert not bad.ok
    assert bad.decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert _revision(db) == good_revision  # restored, not left on the unverified swap
    assert list(tmp_path.glob("idx.sqlite.staging.*")) == []
    assert list(tmp_path.glob("idx.sqlite.bak.*")) == []


def _flaky_connect_on_second_use_of(index_module, target_db: Path, exc: BaseException):  # type: ignore[no-untyped-def]
    """Raise `exc` the SECOND time `connect()` is called with `target_db` -
    the first such call is `_current_revision(db_path)` (step 1, before the
    build even starts); the second is the post-swap integrity-check
    connect() this finding is about. Returns (patched_fn, restore_fn)."""
    calls = {"n": 0}
    original = index_module.connect

    def _flaky(path, *, read_only=False):  # type: ignore[no-untyped-def]
        if Path(path) == target_db:
            calls["n"] += 1
            if calls["n"] == 2:
                raise exc
        return original(path, read_only=read_only)

    return _flaky, original


def test_reindex_restores_backup_on_a_runtime_error_from_post_swap_connect(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for Codex#3 (round 13, 2026-09-13), reproduced exactly as
    reported: `connect(db_path, read_only=True)` right after the swap can
    itself raise `ForeignDatabaseError`/`UntrustedStateDirectoryError`/
    `FTS5Unavailable` - all `RuntimeError` subclasses, none of them
    `OSError` or `sqlite3.Error` - which escaped the except clause
    entirely: the newly-swapped, unverified index stayed live and the
    backup stayed stranded."""
    import app.retrieval.index as index_module

    db = tmp_path / "idx.sqlite"
    good = reindex_atomic(corpus_alt_root, db)
    good_revision = good.new_revision
    assert _revision(db) == good_revision

    corpus2 = tmp_path / "corpus2"
    import shutil

    shutil.copytree(corpus_alt_root, corpus2)
    ku = next(corpus2.glob("public/**/*.md"))
    ku.write_text(ku.read_text(encoding="utf-8").replace("0.1", "0.2"), encoding="utf-8")

    flaky, original = _flaky_connect_on_second_use_of(
        index_module, db, RuntimeError("simulated FTS5Unavailable-like failure")
    )
    index_module.connect = flaky
    try:
        bad = reindex_atomic(corpus2, db)
    finally:
        index_module.connect = original

    assert not bad.ok
    assert bad.decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert _revision(db) == good_revision  # restored, not left on the unverified swap
    assert list(tmp_path.glob("idx.sqlite.staging.*")) == []
    assert list(tmp_path.glob("idx.sqlite.bak.*")) == []


def test_reindex_restores_backup_then_reraises_a_genuinely_unexpected_exception(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """A post-swap exception outside every anticipated type (not OSError,
    sqlite3.Error, or RuntimeError - a real bug, not an operational
    failure) must still trigger restoration before propagating, rather
    than being silently converted into a POLICY_BLOCKED report as if it
    were an expected failure."""
    import app.retrieval.index as index_module

    db = tmp_path / "idx.sqlite"
    good = reindex_atomic(corpus_alt_root, db)
    good_revision = good.new_revision
    assert _revision(db) == good_revision

    corpus2 = tmp_path / "corpus2"
    import shutil

    shutil.copytree(corpus_alt_root, corpus2)
    ku = next(corpus2.glob("public/**/*.md"))
    ku.write_text(ku.read_text(encoding="utf-8").replace("0.1", "0.2"), encoding="utf-8")

    flaky, original = _flaky_connect_on_second_use_of(
        index_module, db, KeyError("totally unexpected bug")
    )
    index_module.connect = flaky
    try:
        with pytest.raises(KeyError):
            reindex_atomic(corpus2, db)
    finally:
        index_module.connect = original

    assert _revision(db) == good_revision  # still restored, not left on the unverified swap
    assert list(tmp_path.glob("idx.sqlite.staging.*")) == []
    assert list(tmp_path.glob("idx.sqlite.bak.*")) == []


def _wrong_revision_on_second_call(
    monkeypatch: pytest.MonkeyPatch, wrong_revision: str | None
) -> None:
    """Make `ChunkRepository.knowledge_revision()` return `wrong_revision`
    the SECOND time it is called anywhere in the process - during
    `reindex_atomic()` the first call is `_current_revision(db_path)` (step
    1, before the build even starts); the second is the post-swap
    integrity-check this finding is about (the only other production call
    site, `Bm25Retriever.retrieve()`, runs on the query path, never during
    reindex). Mirrors `_flaky_connect_on_second_use_of`'s call-counting
    technique, one level down."""
    calls = {"n": 0}
    original = ChunkRepository.knowledge_revision

    def _flaky(self):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if calls["n"] == 2:
            return wrong_revision
        return original(self)

    monkeypatch.setattr(ChunkRepository, "knowledge_revision", _flaky)


def test_reindex_fails_closed_when_the_post_swap_visible_revision_does_not_match(
    tmp_path: Path, corpus_alt_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#1 (round 19, 2026-09-14), reproduced exactly as
    reported: `reindex_atomic()` copies/replaces db_path's MAIN file only -
    a WAL sidecar left behind by a prior writer (see `connect()`'s own
    comment on why every write connection now forces `journal_mode =
    DELETE`) is a separate file the swap never touches, so a fresh
    connection could see stale-but-internally-consistent content that
    `verify_chunk_hashes()` alone can't catch: it proves the visible
    content is *a* valid, self-consistent index, not that it's the
    revision we just published. Simulated here - without depending on
    fragile real-WAL-internals trickery - by making the post-swap
    `ChunkRepository.knowledge_revision()` read report the OLD revision
    instead of the new one `build_index()` just reported; the fix must
    treat that mismatch as a publish failure and restore the backup,
    exactly like any other post-swap integrity failure."""
    db = tmp_path / "idx.sqlite"
    good = reindex_atomic(corpus_alt_root, db)
    good_revision = good.new_revision
    assert _revision(db) == good_revision

    corpus2 = tmp_path / "corpus2"
    import shutil

    shutil.copytree(corpus_alt_root, corpus2)
    ku = next(corpus2.glob("public/**/*.md"))
    ku.write_text(ku.read_text(encoding="utf-8").replace("0.1", "0.2"), encoding="utf-8")

    _wrong_revision_on_second_call(monkeypatch, good_revision)
    bad = reindex_atomic(corpus2, db)

    assert not bad.ok
    assert bad.decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert _revision(db) == good_revision  # restored, not left on the mismatched swap
    assert list(tmp_path.glob("idx.sqlite.staging.*")) == []
    assert list(tmp_path.glob("idx.sqlite.bak.*")) == []


def test_reindex_rejects_a_build_that_skipped_units(
    tmp_path: Path, fixture_knowledge_root: Path
) -> None:
    """Regression for Codex cross-review finding #4 (round 3, 2026-09-12):
    step 1 validates the tree, but build_index() -> load_corpus() re-walks
    and independently re-validates the same knowledge_root (its own
    validate_tree() call). If that second read disagrees with the first -
    simulated here by forcing step 1 to see a clean tree while the tree
    genuinely has files load_corpus skips - the resulting build silently
    dropped content (down to zero units, in the fault-injected repro) and
    reindex_atomic used to still publish it as ALLOWED."""
    import app.retrieval.index as index_module

    db = tmp_path / "idx.sqlite"
    original_validate_tree = index_module.validate_tree
    index_module.validate_tree = lambda root: []  # pretend step 1 saw a clean tree
    try:
        report = index_module.reindex_atomic(fixture_knowledge_root, db)
    finally:
        index_module.validate_tree = original_validate_tree

    assert not report.ok
    assert report.decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert "skipped" in " ".join(report.decision.reasons)
    assert not db.exists()  # nothing published - there was no previous index either
    assert list(tmp_path.glob("idx.sqlite.staging.*")) == []
    assert list(tmp_path.glob("idx.sqlite.bak.*")) == []


def test_reindex_rejects_when_the_tree_changes_between_the_two_reads(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for Codex#2 / Antigravity SKOS-ADV-11 (round 4,
    2026-09-12), reproduced exactly as reported: a file that DISAPPEARS
    between step 1's file count and build_index()'s own independent
    re-enumeration is invisible to the round-3 build.skipped check - a
    vanished file is never "skipped", it is simply never seen a second time.
    Simulated here by making step 1's own count see one MORE file than
    actually exists (the same "the two independent reads disagree"
    condition the fix detects, regardless of which direction the count
    moves)."""
    import app.retrieval.index as index_module

    db = tmp_path / "idx.sqlite"
    real_files = index_module.iter_knowledge_files(corpus_alt_root)
    assert real_files  # sanity: the fixture corpus is non-empty
    original = index_module.iter_knowledge_files
    index_module.iter_knowledge_files = lambda root: [*original(root), Path("/phantom.md")]
    try:
        report = index_module.reindex_atomic(corpus_alt_root, db)
    finally:
        index_module.iter_knowledge_files = original

    assert not report.ok
    assert report.decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert "changed during reindex" in " ".join(report.decision.reasons)
    assert not db.exists()  # nothing published - there was no previous index either


def test_reindex_never_falsely_claims_restoration_when_restore_itself_fails(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for Codex#3 / Antigravity SKOS-ADV-12 (round 4,
    2026-09-12), reproduced exactly as reported: restoring the backup after
    a failed post-swap integrity check can ITSELF fail - the previous
    version suppressed that with `contextlib.suppress(OSError)` and
    unconditionally reported "previous index restored" regardless of
    whether the replace actually succeeded. The report must never claim a
    success it cannot verify, and must fail closed (remove the
    unverified/bad content from service) rather than leave it live."""
    import shutil

    import app.retrieval.index as index_module

    db = tmp_path / "idx.sqlite"
    good = reindex_atomic(corpus_alt_root, db)
    assert good.ok

    corpus2 = tmp_path / "corpus2"
    shutil.copytree(corpus_alt_root, corpus2)
    ku = next(corpus2.glob("public/**/*.md"))
    ku.write_text(ku.read_text(encoding="utf-8").replace("0.1", "0.2"), encoding="utf-8")

    class _FakeStop:
        is_allowed = False
        reasons = ["simulated post-swap corruption"]

    original_verify = index_module.verify_chunk_hashes
    calls = {"n": 0}

    def _flaky_verify(conn):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if calls["n"] == 2:  # 1st call = staging check (let it pass); 2nd = post-swap
            return _FakeStop()
        return original_verify(conn)

    original_replace = index_module.os.replace

    def _flaky_replace(src, dst):  # type: ignore[no-untyped-def]
        if ".bak." in str(src):  # this is the RESTORE call (backup -> db_path); fail it
            raise PermissionError("simulated restore failure")
        return original_replace(src, dst)

    index_module.verify_chunk_hashes = _flaky_verify  # type: ignore[assignment]
    index_module.os.replace = _flaky_replace  # type: ignore[assignment]
    try:
        bad = reindex_atomic(corpus2, db)
    finally:
        index_module.verify_chunk_hashes = original_verify  # type: ignore[assignment]
        index_module.os.replace = original_replace  # type: ignore[assignment]

    assert not bad.ok
    assert bad.decision.outcome is PolicyOutcome.POLICY_BLOCKED
    reason = " ".join(bad.decision.reasons)
    assert "RESTORE ALSO FAILED" in reason
    assert "previous index restored" not in reason  # never a false success claim
    assert not db.exists()  # fail closed: the bad/unverified content is not left live


def test_reindex_fails_closed_when_the_existing_index_is_corrupt(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for Codex#4 sub-point 1 (round 5, 2026-09-12), reproduced
    exactly as reported: _current_revision() and the initial validation walk
    used to run outside any try/except in _reindex_atomic_locked() - a
    corrupt EXISTING index (its `meta` table dropped) made
    _current_revision() raise sqlite3.OperationalError straight out of
    reindex_atomic(), instead of the POLICY_BLOCKED ReindexReport every
    other failure path in this function returns."""
    db = tmp_path / "idx.sqlite"
    good = reindex_atomic(corpus_alt_root, db)
    assert good.ok

    conn = connect(db)
    conn.execute("DROP TABLE meta")
    conn.commit()
    conn.close()

    report = reindex_atomic(corpus_alt_root, db)  # must not raise
    assert not report.ok
    assert report.decision.outcome is PolicyOutcome.POLICY_BLOCKED


def test_reindex_fails_closed_on_a_non_text_stored_revision(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for Codex#4 / Antigravity SKOS-ADV-32 (round 21,
    2026-09-15), reproduced exactly as reported: `meta.value` is a
    TEXT-affinity column, but a BLOB literal bypasses that affinity and is
    stored (and read back) as raw `bytes`. That bytes value used to flow
    through `_current_revision()` into `old_revision` untouched and only
    surfaced much later as a raw, uncaught Pydantic `ValidationError` when
    constructing the final `ReindexReport` - potentially AFTER a
    successful publish, misrepresenting success as a crash."""
    db = tmp_path / "idx.sqlite"
    good = reindex_atomic(corpus_alt_root, db)
    assert good.ok

    conn = connect(db)
    conn.execute("UPDATE meta SET value = X'FF' WHERE key = 'knowledge_revision'")
    conn.commit()
    conn.close()

    report = reindex_atomic(corpus_alt_root, db)  # must not raise
    assert not report.ok
    assert report.decision.outcome is PolicyOutcome.POLICY_BLOCKED
    # the existing (corrupted-metadata) index was never touched - this
    # function never got far enough to build or swap anything.
    assert _revision(db) == b"\xff"


def test_reindex_converts_an_unexpected_ingestion_valueerror_to_policy_blocked(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for Codex#4 sub-point 2 (round 5, 2026-09-12): an
    unexpected ingestion-content failure from build_index()/load_corpus() -
    a pydantic ValidationError, a FrontMatterError, or any other bare
    ValueError - must become a POLICY_BLOCKED ReindexReport, not an
    exception escaping reindex_atomic(). load_corpus() itself now converts
    per-file parse/schema failures into a `skipped` entry rather than
    raising (Codex#3 above); this is the defensive backstop for anything
    that still reaches build_index() as a raised ValueError."""
    import app.retrieval.index as index_module

    db = tmp_path / "idx.sqlite"

    def _boom(knowledge_root, staging_db_path):  # type: ignore[no-untyped-def]
        raise ValueError("simulated unexpected ingestion failure")

    original_build_index = index_module.build_index
    index_module.build_index = _boom  # type: ignore[assignment]
    try:
        report = reindex_atomic(corpus_alt_root, db)  # must not raise
    finally:
        index_module.build_index = original_build_index  # type: ignore[assignment]

    assert not report.ok
    assert report.decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert not db.exists()


def test_reindex_restore_note_never_claims_removal_when_unlink_also_fails(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for Codex#4 sub-point 3 (round 5, 2026-09-12), reproduced
    exactly as reported: if BOTH the backup restore (os.replace) and the
    fallback db_path.unlink() fail, the report used to unconditionally claim
    the bad index was "removed from service" - db_path can still exist with
    unverified content in that double-failure case."""
    import shutil

    import app.retrieval.index as index_module

    db = tmp_path / "idx.sqlite"
    good = reindex_atomic(corpus_alt_root, db)
    assert good.ok

    corpus2 = tmp_path / "corpus2"
    shutil.copytree(corpus_alt_root, corpus2)
    ku = next(corpus2.glob("public/**/*.md"))
    ku.write_text(ku.read_text(encoding="utf-8").replace("0.1", "0.2"), encoding="utf-8")

    class _FakeStop:
        is_allowed = False
        reasons = ["simulated post-swap corruption"]

    original_verify = index_module.verify_chunk_hashes
    calls = {"n": 0}

    def _flaky_verify(conn):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if calls["n"] == 2:  # 1st call = staging check (let it pass); 2nd = post-swap
            return _FakeStop()
        return original_verify(conn)

    original_replace = index_module.os.replace

    def _flaky_replace(src, dst):  # type: ignore[no-untyped-def]
        if ".bak." in str(src):  # this is the RESTORE call (backup -> db_path); fail it
            raise PermissionError("simulated restore failure")
        return original_replace(src, dst)

    original_unlink = index_module.Path.unlink

    def _flaky_unlink(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        if self == db:  # the fallback removal _restore_or_remove falls back to; fail it too
            raise PermissionError("simulated unlink failure")
        return original_unlink(self, *args, **kwargs)

    index_module.verify_chunk_hashes = _flaky_verify  # type: ignore[assignment]
    index_module.os.replace = _flaky_replace  # type: ignore[assignment]
    index_module.Path.unlink = _flaky_unlink  # type: ignore[assignment]
    try:
        bad = reindex_atomic(corpus2, db)
    finally:
        index_module.verify_chunk_hashes = original_verify  # type: ignore[assignment]
        index_module.os.replace = original_replace  # type: ignore[assignment]
        index_module.Path.unlink = original_unlink  # type: ignore[assignment]

    assert not bad.ok
    reason = " ".join(bad.decision.reasons)
    assert "STILL CONTAINS" in reason
    assert "removed from service" not in reason
    assert db.exists()  # the double failure really did leave it in place


def test_reindex_publish_never_leaves_db_path_missing(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for SKOS-ADV-08 / Codex#2 (round 2, 2026-09-11): publish used
    to move the existing index OUT of the way first (os.replace(db_path,
    backup)) before moving staging in - a real window where db_path did not
    exist at all, observable by a concurrent reader. Publish must now be a
    single atomic os.replace(staging, db_path); the existing index is copied
    (not moved) to the backup path beforehand, so db_path itself is never
    touched until the one atomic swap."""
    import app.retrieval.index as index_module

    db = tmp_path / "idx.sqlite"
    reindex_atomic(corpus_alt_root, db)  # first build: nothing to observe yet
    assert db.exists()

    seen_missing = []
    original_replace = index_module.os.replace

    def _spy(src, dst):  # type: ignore[no-untyped-def]
        if str(dst) == str(db):
            seen_missing.append(not db.exists())  # was db_path missing right before?
        return original_replace(src, dst)

    index_module.os.replace = _spy  # type: ignore[assignment]
    try:
        second = reindex_atomic(corpus_alt_root, db)
    finally:
        index_module.os.replace = original_replace  # type: ignore[assignment]

    assert second.ok
    assert seen_missing == [False]  # db_path existed at the moment of the swap


def test_concurrent_reindex_calls_do_not_corrupt_or_collide(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Codex cross-review finding #3 (2026-09-11): two reindex_atomic() calls
    sharing a fixed staging path could unlink() each other's in-progress file.
    Run several concurrently against the same db_path (thread pool - flock and
    file I/O both release the GIL) and require every call to finish cleanly
    with the index left in a valid, readable state and no leftover staging/
    backup files."""
    from concurrent.futures import ThreadPoolExecutor

    db = tmp_path / "idx.sqlite"

    with ThreadPoolExecutor(max_workers=5) as pool:
        reports = list(pool.map(lambda _: reindex_atomic(corpus_alt_root, db), range(5)))

    assert all(r.ok for r in reports), [r.decision.reasons for r in reports]
    assert _revision(db) is not None
    assert list(tmp_path.glob("idx.sqlite.staging.*")) == []
    assert list(tmp_path.glob("idx.sqlite.bak.*")) == []


def test_build_index_rejects_a_file_as_root(tmp_path: Path) -> None:
    """Regression for Codex cross-review finding #5 (round 2, 2026-09-11),
    reproduced exactly as reported: build_index() given a FILE (not a
    directory) as knowledge_root used to succeed with zero units/chunks and
    no reported skips - a typo'd root would silently write an empty index."""
    a_file = tmp_path / "README.md"
    a_file.write_text("not a knowledge root", encoding="utf-8")
    with pytest.raises(IndexBuildError, match="not a directory"):
        build_index(a_file, tmp_path / "idx.sqlite")


def test_reindex_fails_closed_on_invalid_utf8_not_a_raw_unicodedecodeerror(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for Codex#5 (round 7, 2026-09-12), reproduced exactly as
    reported: invalid UTF-8 in a KU raised a raw UnicodeDecodeError out of
    reindex_atomic() instead of a typed POLICY_BLOCKED result."""
    import shutil

    corpus2 = tmp_path / "corpus2"
    shutil.copytree(corpus_alt_root, corpus2)
    ku_path = next(corpus2.glob("public/**/*.md"))
    ku_path.write_bytes(
        b"---\nid: KU-BAD\ntitle: t\ncategory: prompt-security\n"
        b"classification: public\nversion: '0.1'\nsource_ref: x\n---\n"
        b"\xff\xfe invalid utf-8 bytes"
    )

    db = tmp_path / "idx.sqlite"
    report = reindex_atomic(corpus2, db)  # must not raise
    assert not report.ok
    assert report.decision.outcome is PolicyOutcome.POLICY_BLOCKED


def test_reindex_creates_the_index_directory_and_file_non_world_readable(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for Codex#4 (round 7, 2026-09-12), reproduced exactly as
    reported: a local build produced a world-readable (0o644) db and
    (0o664) lock file inside a default-mode directory - the index can hold
    every non-secret classification, including confidential, even when
    runtime retrieval never returns confidential results. Another local
    user reading the SQLite file directly bypasses the classification
    filter entirely."""
    db = tmp_path / "sub" / "idx.sqlite"
    report = reindex_atomic(corpus_alt_root, db)
    assert report.ok

    dir_mode = stat.S_IMODE(db.parent.stat().st_mode)
    db_mode = stat.S_IMODE(db.stat().st_mode)
    lock_mode = stat.S_IMODE(db.with_suffix(db.suffix + ".lock").stat().st_mode)
    assert dir_mode == 0o700, oct(dir_mode)
    assert db_mode == 0o600, oct(db_mode)
    assert lock_mode == 0o600, oct(lock_mode)


def test_reindex_does_not_chmod_a_preexisting_index_directory(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for Codex#4 (round 8, 2026-09-12), reproduced exactly as
    reported: reindexing to a database inside an EXISTING 0o755 directory
    changed that directory to 0o700 - a relative db_path like
    "index.sqlite" makes this the current working directory itself."""
    existing = tmp_path / "existing"
    existing.mkdir(mode=0o755)
    os.chmod(existing, 0o755)  # mkdir's mode is umask-adjusted; force the exact value
    db = existing / "idx.sqlite"

    report = reindex_atomic(corpus_alt_root, db)

    assert report.ok
    assert stat.S_IMODE(existing.stat().st_mode) == 0o755


def test_reindex_state_dir_creation_does_not_chmod_a_racily_planted_symlinks_target(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for Codex#2 (round 15, 2026-09-14), reproduced exactly as
    reported: the old check-then-act sequence - `db_path.parent.exists()`,
    then `.mkdir(exist_ok=True)`, then `os.chmod(db_path.parent, 0o700)` -
    let an attacker who can write into the parent's own parent plant a
    symlink to an unrelated, differently-owned directory in the window
    between the exists() check and the mkdir() call.
    `Path.mkdir(exist_ok=True)` silently accepts a pre-existing
    symlink-to-a-directory (only `is_dir()` is checked, which follows
    symlinks), so the "not already existed" branch still ran and
    `os.chmod()` - which follows symlinks by default - re-permissioned
    the attacker's own directory instead of the intended state
    directory. Identical bug and fix to `app.storage.db.connect()`'s own
    version of this (same round, finding #2)."""
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
        reindex_atomic(corpus_alt_root, state_link / "idx.sqlite")

    assert stat.S_IMODE(victim.stat().st_mode) == 0o755, (
        "reindex_atomic() must never chmod a directory it did not itself create, "
        "even when racing a symlink into its intended state-directory path"
    )


def test_reindex_rejects_a_lock_path_symlinked_to_an_unrelated_file(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for Codex#4 (round 8, 2026-09-12), reproduced exactly as
    reported: precreating `idx.sqlite.lock` as a symlink to an unrelated
    0o644 file caused reindexing to chmod that unrelated TARGET to 0o600 -
    plain `open(lock_path, "a")` and `os.chmod(lock_path, ...)` both
    follow a symlink at that exact path."""
    db = tmp_path / "idx.sqlite"
    lock_path = db.with_suffix(db.suffix + ".lock")
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_text("not a lock file", encoding="utf-8")
    os.chmod(unrelated, 0o644)
    lock_path.symlink_to(unrelated)

    report = reindex_atomic(corpus_alt_root, db)

    assert not report.ok
    assert report.decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert stat.S_IMODE(unrelated.stat().st_mode) == 0o644, "the symlink TARGET must be untouched"


def test_reindex_rejects_a_backup_path_precreated_as_a_symlink(
    tmp_path: Path, corpus_alt_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#1 (round 10, 2026-09-13), reproduced exactly as
    reported: `shutil.copy2(db_path, backup)` opens `backup` the normal
    way - a writer able to precreate the backup path (derived from a
    `unique` suffix shared with the `staging` path, which sits on disk
    under that name for the whole build and is therefore observable) as a
    symlink caused `copy2()` to silently overwrite the symlink's TARGET
    with the live database's content. The `unique` value is deterministic
    here (a fixed uuid4 + this process's own real pid) so the exact
    backup path can be precreated before the SECOND reindex_atomic() call
    that actually writes a backup (the first call has no existing index
    to back up yet)."""
    import uuid

    db = tmp_path / "idx.sqlite"
    first = reindex_atomic(corpus_alt_root, db)
    assert first.ok

    fixed_uuid = uuid.UUID("deadbeef-0000-0000-0000-000000000000")
    monkeypatch.setattr("app.retrieval.index.uuid4", lambda: fixed_uuid)
    unique = f"{os.getpid()}-{fixed_uuid.hex[:8]}"
    backup = db.with_suffix(db.suffix + f".bak.{unique}")
    victim = tmp_path / "victim.txt"
    victim.write_text("victim content untouched", encoding="utf-8")
    backup.symlink_to(victim)

    second = reindex_atomic(corpus_alt_root, db)

    assert not second.ok
    assert victim.read_text(encoding="utf-8") == "victim content untouched"


def test_reindex_rejects_a_staging_database_substituted_before_publish(
    tmp_path: Path, corpus_alt_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#2 (round 10, 2026-09-13), reproduced exactly as
    reported: `staging` was verified by PATHNAME, its connection closed,
    and `os.replace(staging, db_path)` later re-resolved that pathname -
    a writer able to replace `staging` with a symlink to a separately-
    built, internally self-consistent "valid" database in that window
    got it published instead. `os.replace()` does not follow symlinks -
    it moves the symlink ENTRY itself into db_path's place - so db_path
    would become a symlink into the attacker's own database, which every
    later read (including the post-swap integrity check) transparently
    follows and happily verifies on its own terms.

    Monkeypatching `os.replace` to perform the substitution immediately
    before the real call simulates the attacker winning the race,
    independent of how much real wall-clock time the backup-copy step
    (the actual window in production) takes."""
    import shutil

    import app.retrieval.index as index_module
    from app.retrieval.index import build_index

    db = tmp_path / "idx.sqlite"
    first = reindex_atomic(corpus_alt_root, db)
    assert first.ok, "test assumption: an existing index to trigger the backup-copy window"

    evil_root = tmp_path / "evil_corpus"
    shutil.copytree(corpus_alt_root, evil_root)
    evil_db = tmp_path / "evil.sqlite"
    build_index(evil_root, evil_db)

    real_copy = index_module._copy_no_follow_exclusive
    swapped = {"done": False}

    def racy_copy(src: Path, dst: Path) -> None:
        # simulates the actual production window: the attacker acts during
        # the (potentially slow) backup-copy step, AFTER staging was
        # verified but BEFORE the pre-swap re-check this fix adds.
        real_copy(src, dst)
        staging = next(tmp_path.glob("idx.sqlite.staging.*"))
        staging.unlink()
        staging.symlink_to(evil_db)
        swapped["done"] = True

    monkeypatch.setattr(index_module, "_copy_no_follow_exclusive", racy_copy)

    report = reindex_atomic(corpus_alt_root, db)

    assert swapped["done"], "test assumption: the swap actually happened"
    assert not report.ok
    assert not db.is_symlink(), "db_path must never become a symlink into attacker content"


def test_reindex_snapshot_is_immune_to_source_mutation_after_it_is_taken(
    tmp_path: Path, corpus_alt_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#1 (round 7, 2026-09-12), reproduced exactly as
    reported: a file changed transiently during the build (between the
    file-count/validation walk and build_index()'s own read) and restored
    right after still passed integrity, because the published index simply
    reflects whatever was read at that moment. reindex_atomic() now takes
    one immutable snapshot of the entire tree BEFORE any validation or
    build step runs; mutating the SOURCE tree after that point must have
    zero effect on what gets published."""
    import shutil

    import app.retrieval.index as index_module

    corpus2 = tmp_path / "corpus2"
    shutil.copytree(corpus_alt_root, corpus2)
    ku_path = next(corpus2.glob("public/**/*.md"))
    original_text = ku_path.read_text(encoding="utf-8")

    original_snapshot_tree = index_module.snapshot_tree

    def _mutate_source_right_after_snapshotting(root):  # type: ignore[no-untyped-def]
        snapshot = original_snapshot_tree(root)
        # the source tree changes the instant after this process took its
        # private copy, then is restored before anything else could
        # observe the swap - exactly the window the review's repro used.
        ku_path.write_text(original_text + "\nPOISONED_CONTENT_MARKER", encoding="utf-8")
        try:
            return snapshot
        finally:
            ku_path.write_text(original_text, encoding="utf-8")

    monkeypatch.setattr(index_module, "snapshot_tree", _mutate_source_right_after_snapshotting)

    db = tmp_path / "idx.sqlite"
    report = reindex_atomic(corpus2, db)
    assert report.ok

    conn = connect(db, read_only=True)
    try:
        texts = " ".join(r["text"] for r in conn.execute("SELECT text FROM chunks"))
    finally:
        conn.close()
    assert "POISONED_CONTENT_MARKER" not in texts


def test_reindex_fails_closed_when_the_lock_setup_itself_fails(corpus_alt_root: Path) -> None:
    """Regression for Codex#9 (round 6, 2026-09-12), reproduced exactly as
    reported: parent-directory creation, lock-file opening, and the
    initial flock() ran outside any try/except in reindex_atomic() -
    reindex_atomic("knowledge", "/proc/1/skos-audit.sqlite") raised a raw
    FileNotFoundError/PermissionError instead of returning a
    POLICY_BLOCKED ReindexReport."""
    report = reindex_atomic(corpus_alt_root, Path("/proc/1/skos-audit.sqlite"))
    assert not report.ok
    assert report.decision.outcome is PolicyOutcome.POLICY_BLOCKED


def test_reindex_atomic_nonblocking_reports_busy_instead_of_waiting(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    """Regression for Codex#2 (round 13, 2026-09-13), reproduced exactly as
    reported: reindex_atomic()'s flock() used to always BLOCK - with
    `blocking=False`, a contended lock must return a POLICY_BLOCKED report
    with `decision.subject == "reindex-busy"` immediately instead.

    Runs the contended call in a worker thread with a bounded
    `future.result(timeout=...)` - never a bare, unbounded call - so that
    IF this ever regresses back to blocking, the call hangs in the
    (leaked) worker thread while this test still fails cleanly and
    promptly instead of hanging the whole suite (confirmed by hand: an
    unbounded call against the pre-fix, always-blocking code hangs
    indefinitely, since flock() locks are per OPEN FILE DESCRIPTION, not
    per process - even a second fd opened by this SAME process contends
    with the one held below exactly like a different process would)."""
    import fcntl
    from concurrent.futures import ThreadPoolExecutor
    from concurrent.futures import TimeoutError as FutureTimeoutError

    from app.retrieval.index import open_no_follow

    db = tmp_path / "idx.sqlite"
    reindex_atomic(corpus_alt_root, db)  # seed a real index first
    lock_path = db.with_suffix(db.suffix + ".lock")

    lock_fd = open_no_follow(lock_path, 0o600)
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(reindex_atomic, corpus_alt_root, db, blocking=False)
            try:
                report = future.result(timeout=5)
            except FutureTimeoutError:
                pytest.fail(
                    "reindex_atomic(blocking=False) did not return within 5s - "
                    "it is blocking on the held lock instead of reporting busy"
                )
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)

    assert not report.ok
    assert report.decision.subject == "reindex-busy"


def test_reindex_signature_takes_no_content() -> None:
    """`blocking` (round 13, Codex#2) is a pure concurrency-behaviour flag,
    not a content-bearing parameter - it does not weaken what this test
    guards against (a future `content=`/`override=`-shaped parameter that
    would let a caller smuggle knowledge content through reindex)."""
    import inspect

    from app.retrieval.index import reindex_atomic as fn

    assert set(inspect.signature(fn).parameters) == {"knowledge_root", "db_path", "blocking"}


def test_reindex_does_not_create_directories_through_a_symlink_planted_after_the_trust_check(
    tmp_path: Path, corpus_alt_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#3 (round 23, 2026-09-20): same check-to-mkdir gap
    as connect()'s (see tests/unit/test_db.py's sibling test), on the
    reindex path - the symlink is planted right after the trust check
    returns clean, and nothing may be created on the other side of it."""
    import app.retrieval.index as index_module
    import app.storage.db as db_module

    outside = tmp_path / "outside"
    outside.mkdir()
    shared = tmp_path / "shared"
    shared.mkdir()
    db_path = shared / "skos-race" / "new" / "index.sqlite"

    real_check = index_module.existing_ancestors_untrusted_reason

    def check_then_plant(path: Path) -> str | None:
        result = real_check(path)
        (shared / "skos-race").symlink_to(outside, target_is_directory=True)
        return result

    monkeypatch.setattr(index_module, "existing_ancestors_untrusted_reason", check_then_plant)
    monkeypatch.setattr(db_module, "_is_trusted_symlink_owner", lambda uid: False)

    report = reindex_atomic(corpus_alt_root, db_path)

    assert report.decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert "symlink" in " ".join(report.decision.reasons)
    assert list(outside.iterdir()) == [], "a directory was created THROUGH the planted symlink"


def test_reindex_does_not_build_inside_a_directory_raced_in_after_the_trust_check(
    tmp_path: Path, corpus_alt_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#1 (round 24, 2026-09-20): same ordinary-directory
    race as connect()'s (see tests/unit/test_db.py's sibling test), on the
    reindex path."""
    import app.retrieval.index as index_module
    import app.storage.db as db_module

    shared = tmp_path / "shared"
    shared.mkdir()
    db_path = shared / "a" / "b" / "state" / "index.sqlite"

    real_check = index_module.existing_ancestors_untrusted_reason

    def check_then_race(path: Path) -> str | None:
        result = real_check(path)
        (shared / "a").mkdir()
        return result

    real_judge = db_module._stat_result_untrusted_reason

    def judge(st: os.stat_result, label: str) -> str | None:
        if label.startswith("'a'"):
            return f"{label} is owned by uid {st.st_uid + 1} (injected foreign owner)"
        return real_judge(st, label)

    monkeypatch.setattr(index_module, "existing_ancestors_untrusted_reason", check_then_race)
    monkeypatch.setattr(db_module, "_stat_result_untrusted_reason", judge)

    report = reindex_atomic(corpus_alt_root, db_path)

    assert report.decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert "injected foreign owner" in " ".join(report.decision.reasons)
    assert list((shared / "a").iterdir()) == []
