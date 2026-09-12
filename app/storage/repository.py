"""Read/write access to the chunk index."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Sequence

from app.models.knowledge import Classification, KnowledgeCategory
from app.models.retrieval import Chunk
from app.storage.integrity import compute_fts_shadow_digest

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
        # Codex cross-review finding #6 (2026-09-11): chunks_fts is a
        # *contentless* FTS5 table (content=''); a plain DELETE against it
        # raises "cannot DELETE from contentless fts5 table" once it holds any
        # rows, breaking every rebuild() after the first. 'delete-all' is
        # FTS5's dedicated special command for wiping a table of any content
        # mode, without needing the original per-row column values back.
        cur.execute("INSERT INTO chunks_fts(chunks_fts) VALUES ('delete-all')")
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

        # Codex#2 (round 6, 2026-09-12): FTS5's on-disk shadow-table layout
        # is only settled AFTER commit - computed on the SAME (uncommitted)
        # transaction, the digest observably differs from what a fresh
        # connection reads back afterward (an intermediate, not-yet-merged
        # segment structure), which would make every verify_chunk_hashes()
        # call fail on a perfectly good index. Computing it in its own
        # transaction, after the commit above, matches what every later
        # reader (including verify_chunk_hashes() itself) actually sees -
        # see compute_fts_shadow_digest() for what this catches that the
        # per-chunk MATCH probe cannot.
        cur.execute(
            "INSERT INTO meta(key, value) VALUES ('fts_shadow_digest', ?)",
            (compute_fts_shadow_digest(self.conn),),
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
