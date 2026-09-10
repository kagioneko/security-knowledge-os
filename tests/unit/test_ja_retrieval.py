"""M7: Japanese retrieval (registered items JA-R01 / JA-R02).

JA-R01 - a Japanese query reaches a Japanese Knowledge Unit - is required here
because the shipped corpus contains one Japanese KU (KU-0013) and the trigram
tokenizer supports CJK substring matching.

JA-R02 - cross-language retrieval (EN<->JA) - is explicitly out of MVP scope and
is left as a future evaluation item.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.config import Mode, Settings
from app.retrieval.bm25 import Bm25Retriever
from app.retrieval.index import build_index
from app.storage.db import connect

KNOWLEDGE = Path(__file__).resolve().parents[2] / "knowledge"


@pytest.fixture
def index_conn(tmp_path: Path):
    db = tmp_path / "k.sqlite"
    build_index(KNOWLEDGE, db)
    conn = connect(db, read_only=True)
    yield conn
    conn.close()


def _hits(conn, query: str) -> list[str]:
    response = Bm25Retriever(conn, Settings(mode=Mode.PRIVATE, top_k=5)).retrieve(query)
    return [r.chunk.knowledge_id for r in response.results]


@pytest.mark.parametrize(
    "query",
    [
        "プロンプトインジェクション の対策",
        "モデルは侵害されている前提",
        "リーチャビリティ と権限を絞る",
        "認証情報 ブローカ 最小権限",
        "未信頼コンテンツを指示から分離",
    ],
)
def test_ja_r01_japanese_query_reaches_japanese_ku(index_conn, query: str) -> None:
    assert "KU-0013" in _hits(index_conn, query), query


@pytest.mark.skip(reason="JA-R02: cross-language retrieval is explicitly out of MVP scope")
def test_ja_r02_cross_language_retrieval(index_conn) -> None:  # pragma: no cover
    # EN query -> JA KU, or JA query -> EN KU. Future evaluation item.
    assert "KU-0007" in _hits(index_conn, "永続メモリの汚染")
