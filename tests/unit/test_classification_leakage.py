"""M2 / AC-02 + initial gate: Classification Leakage = 0."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.config import Mode, Settings
from app.models.knowledge import Classification, KnowledgeCategory
from app.models.retrieval import Chunk
from app.policy.classification import PolicyBlocked
from app.retrieval.bm25 import Bm25Retriever
from app.retrieval.index import build_index
from app.storage.db import connect
from app.storage.repository import ChunkRepository


@pytest.fixture
def indexed_db(tmp_path: Path, corpus_root: Path) -> Path:
    db_path = tmp_path / "index.sqlite"
    build_index(corpus_root, db_path)
    return db_path


def _classifications(db_path: Path, settings: Settings, query: str) -> set[str]:
    conn = connect(db_path)
    try:
        response = Bm25Retriever(conn, settings).retrieve(query)
    finally:
        conn.close()
    return {item.chunk.classification.value for item in response.results}


def test_secret_never_in_index(indexed_db: Path) -> None:
    conn = connect(indexed_db)
    try:
        assert "secret" not in ChunkRepository(conn).classifications_in_index()
    finally:
        conn.close()


def test_public_mode_returns_only_public(indexed_db: Path) -> None:
    seen = _classifications(
        indexed_db,
        Settings(mode=Mode.PUBLIC, top_k=10),
        "internal heuristic confidential tool matrix persistent memory injection",
    )
    assert seen <= {"public"}


def test_private_mode_excludes_confidential_by_default(indexed_db: Path) -> None:
    seen = _classifications(
        indexed_db,
        Settings(mode=Mode.PRIVATE, allow_confidential=False, top_k=10),
        "internal heuristic confidential tool capability matrix approval gate",
    )
    assert "confidential" not in seen
    assert "internal" in seen  # internal IS allowed in private mode


def test_private_mode_includes_confidential_when_allowed(indexed_db: Path) -> None:
    seen = _classifications(
        indexed_db,
        Settings(mode=Mode.PRIVATE, allow_confidential=True, top_k=10),
        "confidential tool capability matrix approval threshold",
    )
    assert "confidential" in seen


def test_retriever_fails_closed_if_disallowed_chunk_slips_through(
    indexed_db: Path,
) -> None:
    """If a buggy SQL filter ever returned an internal chunk in PUBLIC mode, the
    defence-in-depth check must raise instead of leaking it (spec Section 33)."""
    internal_chunk = Chunk(
        chunk_id="KU-X#000",
        knowledge_id="KU-X",
        title="leak canary",
        source_ref="ref",
        classification=Classification.INTERNAL,
        category=KnowledgeCategory.METHODOLOGY,
        version="0.1",
        section="S",
        text="leak canary text",
        hash="h",
    )

    class LeakyRetriever(Bm25Retriever):
        def _search(self, match_query, allowed, categories):  # type: ignore[override]
            return [(internal_chunk, -1.0)]

    conn = connect(indexed_db)
    try:
        retriever = LeakyRetriever(conn, Settings(mode=Mode.PUBLIC, top_k=5))
        with pytest.raises(PolicyBlocked):
            retriever.retrieve("leak canary")
    finally:
        conn.close()


def test_chunk_search_text_composition() -> None:
    chunk = Chunk(
        chunk_id="KU-1#0",
        knowledge_id="KU-1",
        title="Title here",
        source_ref="ref",
        classification=Classification.PUBLIC,
        category=KnowledgeCategory.PROMPT_SECURITY,
        version="0.1",
        section="Risk",
        text="body text",
        hash="h",
    )
    assert chunk.search_text == "Title here\nRisk\nbody text"
