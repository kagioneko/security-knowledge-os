"""M6: reindex is atomic and fail-closed; it never changes knowledge content.

``reindex_atomic`` refuses outright if the knowledge root has ANY validation
error (including a stray ``classification: secret`` file) - that is a deliberate
fail-closed choice, so these tests use clean corpora for the success path.
"""

from __future__ import annotations

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


def test_reindex_signature_takes_no_content() -> None:
    import inspect

    from app.retrieval.index import reindex_atomic as fn

    assert set(inspect.signature(fn).parameters) == {"knowledge_root", "db_path"}
