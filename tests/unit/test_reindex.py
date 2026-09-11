"""M6: reindex is atomic and fail-closed; it never changes knowledge content.

``reindex_atomic`` refuses outright if the knowledge root has ANY validation
error (including a stray ``classification: secret`` file) - that is a deliberate
fail-closed choice, so these tests use clean corpora for the success path.
"""

from __future__ import annotations

from pathlib import Path

from app.models.policy_outcome import PolicyOutcome
from app.retrieval.index import reindex_atomic
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


def test_reindex_signature_takes_no_content() -> None:
    import inspect

    from app.retrieval.index import reindex_atomic as fn

    assert set(inspect.signature(fn).parameters) == {"knowledge_root", "db_path"}
