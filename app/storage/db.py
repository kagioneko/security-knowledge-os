"""SQLite connection and schema for the knowledge index.

The full-text search uses the FTS5 extension (BM25 ranking). The index is rebuilt
from scratch on every ingest, so the FTS table is contentless.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS chunks (
    rowid          INTEGER PRIMARY KEY,
    chunk_id       TEXT UNIQUE NOT NULL,
    knowledge_id   TEXT NOT NULL,
    title          TEXT NOT NULL,
    source_ref     TEXT NOT NULL,
    classification TEXT NOT NULL,
    category       TEXT NOT NULL,
    version        TEXT NOT NULL,
    section        TEXT NOT NULL,
    text           TEXT NOT NULL,
    hash           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
    search_text,
    content='',
    tokenize='unicode61'
);
"""


class FTS5Unavailable(RuntimeError):
    """The linked SQLite build has no FTS5 extension."""


def _has_fts5(conn: sqlite3.Connection) -> bool:
    try:
        conn.execute("CREATE VIRTUAL TABLE temp._skos_fts_probe USING fts5(x)")
        conn.execute("DROP TABLE temp._skos_fts_probe")
    except sqlite3.OperationalError:
        return False
    return True


def connect(db_path: str | Path, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        if not _has_fts5(conn):
            conn.close()
            raise FTS5Unavailable("SQLite FTS5 is required but not available in this Python build")
        return conn

    if str(db_path) != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    if not _has_fts5(conn):
        conn.close()
        raise FTS5Unavailable(
            "SQLite FTS5 is required but not available in this Python build"
        )
    conn.executescript(SCHEMA)
    return conn
