"""M2 / AC-03, AC-11: BM25 retrieval returns Top-K source-attributed chunks."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.config import LLMProvider, Mode, Settings
from app.retrieval.base import classify_query, to_fts_match_query
from app.retrieval.bm25 import Bm25Retriever
from app.retrieval.index import build_index
from app.storage.db import connect


@pytest.fixture
def private_settings() -> Settings:
    return Settings(
        mode=Mode.PRIVATE,
        allow_confidential=False,
        llm_provider=LLMProvider.NONE,
        top_k=5,
    )


@pytest.fixture
def indexed_db(tmp_path: Path, corpus_root: Path) -> Path:
    db_path = tmp_path / "index.sqlite"
    report = build_index(corpus_root, db_path)
    assert report.units_indexed == 5
    assert "secret" not in report.classifications
    return db_path


def _retrieve(db_path: Path, settings: Settings, query: str):
    conn = connect(db_path)
    try:
        return Bm25Retriever(conn, settings).retrieve(query)
    finally:
        conn.close()


def test_top_result_for_indirect_injection(indexed_db: Path, private_settings: Settings) -> None:
    response = _retrieve(
        indexed_db, private_settings, "indirect prompt injection via an external RAG document"
    )
    assert response.results, "expected at least one hit"
    assert response.results[0].chunk.knowledge_id == "KU-1002"


def test_results_are_source_attributed(indexed_db: Path, private_settings: Settings) -> None:
    # AC-03
    response = _retrieve(indexed_db, private_settings, "how are .env files and api keys handled")
    assert response.results
    for item in response.results:
        assert item.chunk.knowledge_id
        assert item.chunk.source_ref
        assert item.rank >= 1
    assert "KU-1003" in {item.chunk.knowledge_id for item in response.results}


def test_respects_top_k(indexed_db: Path) -> None:
    settings = Settings(mode=Mode.PRIVATE, top_k=2)
    response = _retrieve(indexed_db, settings, "prompt injection memory tool credential rag agent")
    assert len(response.results) <= 2


def test_response_carries_knowledge_revision(indexed_db: Path, private_settings: Settings) -> None:
    # AC-11 (knowledge revision half; model_info arrives in M4)
    response = _retrieve(indexed_db, private_settings, "prompt injection")
    assert len(response.knowledge_revision) == 64


def test_revision_matches_between_build_and_retrieve(
    tmp_path: Path, corpus_root: Path, private_settings: Settings
) -> None:
    db_path = tmp_path / "idx.sqlite"
    report = build_index(corpus_root, db_path)
    response = _retrieve(db_path, private_settings, "credential exposure")
    assert response.knowledge_revision == report.knowledge_revision


def test_query_classification() -> None:
    from app.models.retrieval import QueryCategory

    assert QueryCategory.RAG in classify_query("indirect injection from a retrieved document")
    assert QueryCategory.CREDENTIAL in classify_query("leaked api key in .env")
    assert classify_query("完全に無関係な japanese text") == []


def test_fts_match_query_is_safe() -> None:
    assert to_fts_match_query("") == '"__no_match__"'
    assert to_fts_match_query('drop table"; --') == '"drop" OR "table"'
