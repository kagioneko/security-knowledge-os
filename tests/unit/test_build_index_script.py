"""scripts/build_index.py: the maintenance-script CLI, not the build_index()
library function (see tests/unit/test_repository.py and friends for that).
"""

from __future__ import annotations

from pathlib import Path

import scripts.build_index as build_index_script
from app.retrieval.index import build_index
from app.storage.db import connect
from app.storage.repository import ChunkRepository

REPO = Path(__file__).resolve().parents[2]
CORPUS_ALT = REPO / "tests" / "fixtures" / "corpus_alt"


def _chunk_count(db: Path) -> int:
    conn = connect(db, read_only=True)
    try:
        return ChunkRepository(conn).chunk_count()
    finally:
        conn.close()


def test_default_run_builds_and_publishes(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    db = tmp_path / "idx.sqlite"
    exit_code = build_index_script.main([str(CORPUS_ALT), "--db", str(db)])
    assert exit_code == 0
    assert _chunk_count(db) > 0
    assert "outcome        : ALLOWED" in capsys.readouterr().out


def test_default_run_refuses_an_empty_root_and_keeps_the_existing_index(
    tmp_path: Path, capsys  # type: ignore[no-untyped-def]
) -> None:
    """Regression for Codex#7 (round 5, 2026-09-12), reproduced exactly as
    reported: `build_index.py empty-directory --db existing-index.sqlite`
    used to replace a real, populated index with a self-consistent
    zero-chunk one and exit 0. The default (safe) path must refuse this and
    leave the existing index untouched."""
    db = tmp_path / "idx.sqlite"
    build_index(CORPUS_ALT, db)  # seed a real, populated index
    before = _chunk_count(db)
    assert before > 0

    empty_root = tmp_path / "empty-knowledge-root"
    empty_root.mkdir()

    exit_code = build_index_script.main([str(empty_root), "--db", str(db)])

    assert exit_code == 2
    assert _chunk_count(db) == before  # existing index untouched
    assert "refusing to publish a zero-unit index" in capsys.readouterr().err


def test_default_run_refuses_a_root_with_validation_errors(
    tmp_path: Path, capsys  # type: ignore[no-untyped-def]
) -> None:
    db = tmp_path / "idx.sqlite"
    build_index(CORPUS_ALT, db)
    before = _chunk_count(db)

    bad_root = tmp_path / "bad-knowledge-root" / "public" / "prompt-security"
    bad_root.mkdir(parents=True)
    (bad_root / "bad.md").write_text("not a knowledge unit at all")

    exit_code = build_index_script.main(
        [str(tmp_path / "bad-knowledge-root"), "--db", str(db)]
    )

    assert exit_code == 2
    assert _chunk_count(db) == before  # existing index untouched


def test_allow_partial_opts_back_into_the_old_unsafe_behavior(
    tmp_path: Path, capsys  # type: ignore[no-untyped-def]
) -> None:
    """--allow-partial is an explicit, documented opt-in back into the old
    direct/partial build_index() behavior - the same empty-root repro that
    the default path now refuses must still succeed here."""
    db = tmp_path / "idx.sqlite"
    build_index(CORPUS_ALT, db)
    assert _chunk_count(db) > 0

    empty_root = tmp_path / "empty-knowledge-root"
    empty_root.mkdir()

    exit_code = build_index_script.main(
        [str(empty_root), "--db", str(db), "--allow-partial"]
    )

    assert exit_code == 0
    assert _chunk_count(db) == 0  # the old, unsafe in-place overwrite


def test_allow_partial_still_refuses_a_root_that_is_not_a_directory(
    tmp_path: Path, capsys  # type: ignore[no-untyped-def]
) -> None:
    not_a_dir = tmp_path / "readme.md"
    not_a_dir.write_text("x")
    exit_code = build_index_script.main(
        [str(not_a_dir), "--db", str(tmp_path / "idx.sqlite"), "--allow-partial"]
    )
    assert exit_code == 2
