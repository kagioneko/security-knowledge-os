"""SQLite connection and schema for the knowledge index.

The full-text search uses the FTS5 extension (BM25 ranking). The index is rebuilt
from scratch on every ingest, so the FTS table is contentless.
"""

from __future__ import annotations

import contextlib
import os
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
    tokenize='trigram'
);
"""
# The 'trigram' tokenizer gives substring matching for both English and CJK text
# (SQLite >= 3.34). It is why a Japanese query can reach a Japanese Knowledge Unit
# (JA-R01) without a language-specific segmenter.


# Codex#4 (round 6, 2026-09-12), reproduced exactly as reported: this
# database's identity was checked only by querying meta(key,value) -
# `CREATE TABLE IF NOT EXISTS` is idempotent, so ANY unrelated SQLite file
# that happens to already have a compatible `meta` table (created by
# something else entirely) was silently adopted as "an existing SKOS
# index" and then atomically overwritten by reindex_atomic(). SQLite's
# `application_id` pragma is a 4-byte header field reserved by SQLite
# itself for exactly this "which application owns this file" purpose
# (https://www.sqlite.org/pragma.html#pragma_application_id) - set once on
# a genuinely fresh file, and checked on every later open of an existing
# one. b"SKOS" as big-endian bytes; comfortably inside the signed-32-bit
# range PRAGMA application_id accepts.
_APPLICATION_ID = int.from_bytes(b"SKOS", "big")


class ForeignDatabaseError(RuntimeError):
    """db_path already contains tables, but they are not a Security
    Knowledge OS index - refusing to write into an unrelated database."""


def verify_application_id(conn: sqlite3.Connection, db_path: str | Path) -> None:
    """Raise ForeignDatabaseError unless `conn` is either a brand new/empty
    database or already carries this app's `application_id`. Shared by
    `connect()`'s own write-path check below and by
    `app.retrieval.index._current_revision()`, which reads an EXISTING
    `db_path` read-only before `reindex_atomic()` decides whether to
    replace it - `connect()`'s write-path check alone does not cover that:
    reindex_atomic() never opens the final `db_path` for writing at all, it
    replaces it wholesale with `os.replace(staging, db_path)` (Codex#4,
    round 6, 2026-09-12)."""
    app_id = conn.execute("PRAGMA application_id").fetchone()[0]
    if app_id != _APPLICATION_ID:
        raise ForeignDatabaseError(
            f"{db_path} exists but is not a Security Knowledge OS index "
            f"(application_id={app_id}, expected {_APPLICATION_ID}); refusing to "
            "treat it as one"
        )


class FTS5Unavailable(RuntimeError):
    """The linked SQLite build has no FTS5 extension."""


def _has_fts5(conn: sqlite3.Connection) -> bool:
    try:
        conn.execute("CREATE VIRTUAL TABLE temp._skos_fts_probe USING fts5(x)")
        conn.execute("DROP TABLE temp._skos_fts_probe")
    except sqlite3.OperationalError:
        return False
    return True


def _read_only_uri(db_path: str | Path) -> str:
    # Codex cross-review finding #5 (2026-09-11): a bare f"file:{db_path}?mode=ro"
    # is not a properly constructed URI. If db_path contains '#', everything from
    # '#' onward (including '?mode=ro') is parsed as the URI *fragment* and
    # discarded - read-only silently stops being requested at all, and a '?'/'%'
    # in the path can likewise be misparsed as query syntax. Path.as_uri()
    # percent-encodes special characters correctly.
    if str(db_path) == ":memory:":
        return "file::memory:?mode=ro"
    return f"{Path(db_path).resolve().as_uri()}?mode=ro"


def connect(db_path: str | Path, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        conn = sqlite3.connect(_read_only_uri(db_path), uri=True)
        conn.row_factory = sqlite3.Row
        if not _has_fts5(conn):
            conn.close()
            raise FTS5Unavailable("SQLite FTS5 is required but not available in this Python build")
        return conn

    if str(db_path) != ":memory:":
        # Codex#4 (round 7, 2026-09-12), reproduced exactly as reported: the
        # index can hold every non-secret classification, including
        # `confidential`, even when runtime retrieval never returns
        # confidential results - a local build produced a world-readable
        # (0o644) db and directory. Another local user reading the SQLite
        # file directly bypasses the classification filter entirely.
        parent = Path(db_path).parent
        parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):  # best-effort on filesystems without POSIX perms
            os.chmod(parent, 0o700)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    if str(db_path) != ":memory:":
        with contextlib.suppress(OSError):
            os.chmod(db_path, 0o600)
    if not _has_fts5(conn):
        conn.close()
        raise FTS5Unavailable(
            "SQLite FTS5 is required but not available in this Python build"
        )

    has_existing_content = (
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type IN ('table', 'view') LIMIT 1"
        ).fetchone()
        is not None
    )
    if has_existing_content:
        try:
            verify_application_id(conn, db_path)
        except ForeignDatabaseError:
            conn.close()
            raise
    else:
        # a genuinely fresh file (or an existing empty one) - safe to claim.
        conn.execute(f"PRAGMA application_id = {_APPLICATION_ID}")

    conn.executescript(SCHEMA)
    return conn
