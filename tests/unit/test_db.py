"""app/storage/db.py: connection construction, read-only enforcement.

Regression for Codex cross-review finding #5 (2026-09-11): the read-only URI
used to be a bare f"file:{db_path}?mode=ro". A '#' in the path starts the URI
*fragment*, silently dropping "?mode=ro" (read-only stops being requested at
all) and truncating the path SQLite actually opens (a different file than
intended). '?' and '%' in the path have similar misparsing risks.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from urllib.request import url2pathname

import pytest

from app.storage.db import FTS5Unavailable, _read_only_uri, connect


@pytest.mark.parametrize(
    "name",
    [
        "plain.sqlite",
        "has#hash.sqlite",
        "has?question.sqlite",
        "has%percent.sqlite",
        "has space.sqlite",
        "has#?%mixed and space.sqlite",
    ],
)
def test_read_only_uri_round_trips_special_characters(tmp_path: Path, name: str) -> None:
    db_path = tmp_path / name
    uri = _read_only_uri(db_path)
    parts = urlsplit(uri)

    assert parts.fragment == "", "a character leaked into the URI fragment"
    assert parse_qs(parts.query) == {"mode": ["ro"]}, "mode=ro must survive as a real query param"
    assert Path(url2pathname(parts.path)).resolve() == db_path.resolve()


def test_read_only_uri_memory_special_case() -> None:
    assert _read_only_uri(":memory:") == "file::memory:?mode=ro"


def test_connect_read_only_opens_the_intended_file_despite_hash(tmp_path: Path) -> None:
    db_path = tmp_path / "idx#with a?weird%name.sqlite"
    conn = connect(db_path)  # read-write: creates the schema
    conn.execute("INSERT INTO meta (key, value) VALUES ('probe', 'yes')")
    conn.commit()
    conn.close()

    ro = connect(db_path, read_only=True)
    try:
        row = ro.execute("SELECT value FROM meta WHERE key = 'probe'").fetchone()
        assert row is not None and row[0] == "yes"
    finally:
        ro.close()


def test_missing_fts5_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import app.storage.db as db_module

    monkeypatch.setattr(db_module, "_has_fts5", lambda conn: False)
    with pytest.raises(FTS5Unavailable):
        connect(tmp_path / "no-fts5.sqlite")
