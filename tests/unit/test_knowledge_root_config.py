"""M2: the knowledge root is configurable, not hardcoded.

Today it points at ``knowledge/``; later the Pack Manager can point it at
``active/knowledge/``. Retrieval code must not need to change.
"""

from __future__ import annotations

from pathlib import Path

from app.config import Settings
from app.retrieval.bm25 import Bm25Retriever
from app.retrieval.index import build_index
from app.storage.db import connect


def test_two_roots_produce_independent_indexes(
    tmp_path: Path, corpus_root: Path, corpus_alt_root: Path
) -> None:
    main_db = tmp_path / "main.sqlite"
    alt_db = tmp_path / "alt.sqlite"

    main = build_index(corpus_root, main_db)
    alt = build_index(corpus_alt_root, alt_db)

    assert set(main.knowledge_ids) == {"KU-1001", "KU-1002", "KU-1003", "KU-1010", "KU-1020"}
    assert set(alt.knowledge_ids) == {"KU-2001"}
    assert main.knowledge_revision != alt.knowledge_revision


def test_retriever_bound_to_alt_root_only_sees_alt_units(
    tmp_path: Path, corpus_alt_root: Path
) -> None:
    alt_db = tmp_path / "alt.sqlite"
    build_index(corpus_alt_root, alt_db)

    conn = connect(alt_db)
    try:
        response = Bm25Retriever(conn, Settings(top_k=10)).retrieve(
            "alternate corpus marker methodology"
        )
    finally:
        conn.close()

    assert response.results
    assert {item.chunk.knowledge_id for item in response.results} == {"KU-2001"}


def test_settings_reads_roots_from_env(monkeypatch) -> None:
    monkeypatch.setenv("SKOS_KNOWLEDGE_ROOT", "active/knowledge")
    monkeypatch.setenv("SKOS_DB_PATH", "var/custom.sqlite")
    settings = Settings.from_env()
    assert settings.knowledge_root == "active/knowledge"
    assert settings.db_path == "var/custom.sqlite"
