"""app/storage/repository.py::ChunkRepository.rebuild().

Regression for Codex cross-review finding #6 (2026-09-11): chunks_fts is a
*contentless* FTS5 table (content=''); a plain DELETE against it raises
"cannot DELETE from contentless fts5 table" once it holds any rows - so a
second rebuild() against an already-populated table (e.g. running
scripts/build_index.py twice against the same --db) used to crash.
"""

from __future__ import annotations

from pathlib import Path

from app.models.knowledge import Classification, KnowledgeCategory
from app.models.retrieval import Chunk
from app.retrieval.index import build_index
from app.storage.db import connect
from app.storage.repository import ChunkRepository


def _chunk(chunk_id: str, text: str) -> Chunk:
    return Chunk(
        chunk_id=chunk_id,
        knowledge_id="KU-9001",
        title="t",
        source_ref="test://",
        classification=Classification.PUBLIC,
        category=KnowledgeCategory.METHODOLOGY,
        version="0.1",
        section="Summary",
        text=text,
        hash="0" * 64,
    )


def test_rebuild_twice_on_the_same_connection_does_not_raise(tmp_path: Path) -> None:
    conn = connect(tmp_path / "idx.sqlite")
    try:
        repo = ChunkRepository(conn)
        assert repo.rebuild([_chunk("KU-9001#000", "first")], "rev-1") == 1
        assert repo.rebuild([_chunk("KU-9001#000", "second")], "rev-2") == 1
        assert repo.knowledge_revision() == "rev-2"
    finally:
        conn.close()


def test_rebuild_from_empty_then_nonempty_then_empty(tmp_path: Path) -> None:
    conn = connect(tmp_path / "idx.sqlite")
    try:
        repo = ChunkRepository(conn)
        assert repo.rebuild([], "rev-empty") == 0
        assert repo.rebuild([_chunk("KU-9001#000", "x")], "rev-full") == 1
        assert repo.rebuild([], "rev-empty-again") == 0
    finally:
        conn.close()


def test_build_index_twice_against_the_same_db_path(tmp_path: Path, corpus_alt_root: Path) -> None:
    """The exact repro Codex reported: running scripts/build_index.py twice
    against the same --db (build_index() calls connect() non-read-only, which
    reopens the existing, already-populated database)."""
    db = tmp_path / "idx.sqlite"
    first = build_index(corpus_alt_root, db)
    second = build_index(corpus_alt_root, db)
    assert first.chunks_indexed == second.chunks_indexed
    assert first.knowledge_revision == second.knowledge_revision
