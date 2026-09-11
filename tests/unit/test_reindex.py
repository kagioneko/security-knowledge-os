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
    assert not (tmp_path / "idx.sqlite.staging").exists()


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
    assert not (tmp_path / "idx.sqlite.staging").exists()


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
    assert not (tmp_path / "idx.sqlite.staging").exists()


def test_reindex_signature_takes_no_content() -> None:
    import inspect

    from app.retrieval.index import reindex_atomic as fn

    assert set(inspect.signature(fn).parameters) == {"knowledge_root", "db_path"}
