"""scripts/assess.py: file-read errors and PolicyStop must not escape raw.

Regression for Codex#10 (round 12, 2026-09-13), reproduced exactly as
reported:
  - `args.input.read_text()` was outside the try block that caught
    FrontMatterError/ValidationError - a directory (IsADirectoryError, an
    OSError subclass, since `.exists()` is true for directories too) or
    invalid UTF-8 (UnicodeDecodeError) both escaped as a raw traceback.
  - the script called assess() (the bare library entry point) directly
    instead of build_report() (every other caller's choice) - a PolicyStop
    (e.g. from a tampered/corrupt index) escaped as a raw, uncaught
    exception instead of the documented exit code 3 (POLICY_BLOCKED).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from assess import main  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
_REAL_INPUT = REPO / "tests" / "fixtures" / "assessments" / "safe" / "S-001-prompt-only.yaml"


def test_a_directory_exits_cleanly_instead_of_raising(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    a_directory = tmp_path / "not-a-file"
    a_directory.mkdir()

    code = main([str(a_directory)])

    assert code == 2
    assert "could not read input file" in capsys.readouterr().err


def test_invalid_utf8_exits_cleanly_instead_of_raising(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad-encoding.yaml"
    bad.write_bytes(b"name: \xff\xfe not valid utf-8\n")

    code = main([str(bad)])

    assert code == 2
    assert "could not read input file" in capsys.readouterr().err


def test_a_tampered_index_exits_with_policy_blocked_not_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """This is the finding's own repro shape: a corrupt/tampered index
    makes assess() raise PolicyStop - the standalone script must catch
    that via build_report() the same way app/cli.py's `skos assess`
    already does, not let it escape as a raw exception."""
    from app.retrieval.index import build_index
    from app.storage.db import connect

    db = tmp_path / "idx.sqlite"
    build_index(REPO / "knowledge", db)
    conn = connect(db)
    try:
        conn.execute("UPDATE chunks SET text = 'tampered' WHERE rowid = 1")
        conn.commit()
    finally:
        conn.close()

    code = main([str(_REAL_INPUT), "--db", str(db)])

    assert code == 3
    assert '"POLICY_BLOCKED"' in capsys.readouterr().out


def test_a_clean_run_still_prints_the_result_and_exits_zero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main([str(_REAL_INPUT)])

    assert code == 0
    out = capsys.readouterr().out
    assert '"overall_status"' in out


def test_a_corrupt_index_file_exits_cleanly_without_its_content(
    tmp_path: Path, corpus_alt_root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Regression for Codex round-34 (2026-09-26): same gap as `skos
    assess` - a corrupt --db index raised sqlite3.DatabaseError out of this
    script as a raw traceback quoting content from the file."""
    from app.retrieval.index import reindex_atomic
    from tests.unit.test_reindex import _corrupt_schema

    db = tmp_path / "idx.sqlite"
    assert reindex_atomic(corpus_alt_root, db).ok
    _corrupt_schema(db, "synthetic_private_canary")

    code = main([str(_REAL_INPUT), "--db", str(db)])

    captured = capsys.readouterr()
    assert code == 3
    assert "synthetic_private_canary" not in captured.out + captured.err
