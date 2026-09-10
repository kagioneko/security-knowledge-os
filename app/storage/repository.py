"""Read/write access to the chunk index."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Sequence

from app.models.knowledge import Classification, KnowledgeCategory
from app.models.retrieval import Chunk

_COLUMNS = (
    "chunk_id",
    "knowledge_id",
    "title",
    "source_ref",
    "classification",
    "category",
    "version",
    "section",
    "text",
    "hash",
)


def _row_to_chunk(row: sqlite3.Row) -> Chunk:
    return Chunk(
        chunk_id=row["chunk_id"],
        knowledge_id=row["knowledge_id"],
        title=row["title"],
        source_ref=row["source_ref"],
        classification=Classification(row["classification"]),
        category=KnowledgeCategory(row["category"]),
        version=row["version"],
        section=row["section"],
        text=row["text"],
        hash=row["hash"],
    )


class ChunkRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def rebuild(self, chunks: Iterable[Chunk], knowledge_revision: str) -> int:
        cur = self.conn.cursor()
        cur.execute("DELETE FROM chunks")
        cur.execute("DELETE FROM chunks_fts")
        cur.execute("DELETE FROM meta")

        count = 0
        for rowid, chunk in enumerate(chunks, start=1):
            if chunk.classification is Classification.SECRET:
                raise ValueError("refusing to index a secret-classified chunk")
            cur.execute(
                f"INSERT INTO chunks(rowid, {', '.join(_COLUMNS)}) "
                f"VALUES (?, {', '.join('?' for _ in _COLUMNS)})",
                (
                    rowid,
                    chunk.chunk_id,
                    chunk.knowledge_id,
                    chunk.title,
                    chunk.source_ref,
                    chunk.classification.value,
                    chunk.category.value,
                    chunk.version,
                    chunk.section,
                    chunk.text,
                    chunk.hash,
                ),
            )
            cur.execute(
                "INSERT INTO chunks_fts(rowid, search_text) VALUES (?, ?)",
                (rowid, chunk.search_text),
            )
            count += 1

        cur.execute(
            "INSERT INTO meta(key, value) VALUES ('knowledge_revision', ?)",
            (knowledge_revision,),
        )
        cur.execute(
            "INSERT INTO meta(key, value) VALUES ('chunk_count', ?)", (str(count),)
        )
        self.conn.commit()
        return count

    def knowledge_revision(self) -> str | None:
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key = 'knowledge_revision'"
        ).fetchone()
        return row["value"] if row is not None else None

    def chunk_count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS n FROM chunks").fetchone()
        return int(row["n"])

    def classifications_in_index(self) -> set[str]:
        return {
            row["classification"]
            for row in self.conn.execute(
                "SELECT DISTINCT classification FROM chunks"
            )
        }

    def knowledge_ids(self) -> set[str]:
        return {
            row["knowledge_id"]
            for row in self.conn.execute("SELECT DISTINCT knowledge_id FROM chunks")
        }

    def search(
        self,
        match_query: str,
        allowed_classifications: Sequence[str],
        categories: Sequence[str] | None,
        limit: int,
    ) -> list[tuple[Chunk, float]]:
        if not allowed_classifications:
            return []

        sql = [
            "SELECT c.*, bm25(chunks_fts) AS score",
            "FROM chunks_fts JOIN chunks c ON c.rowid = chunks_fts.rowid",
            "WHERE chunks_fts MATCH ?",
        ]
        params: list[object] = [match_query]

        placeholders = ", ".join("?" for _ in allowed_classifications)
        sql.append(f"AND c.classification IN ({placeholders})")
        params.extend(allowed_classifications)

        if categories:
            placeholders = ", ".join("?" for _ in categories)
            sql.append(f"AND c.category IN ({placeholders})")
            params.extend(categories)

        sql.append("ORDER BY score LIMIT ?")
        params.append(limit)

        rows = self.conn.execute("\n".join(sql), params).fetchall()
        return [(_row_to_chunk(row), float(row["score"])) for row in rows]
