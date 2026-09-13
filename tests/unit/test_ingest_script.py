"""scripts/ingest.py: a root that cannot be safely loaded must not report success.

Regression for Codex#5 (round 13, 2026-09-13), reproduced exactly as reported:

  $ skos ingest README.md
  loadable units : 0
  revision       : e3b0c442...
  $ echo $?
  0

load_corpus() records the root-is-not-a-directory failure as an ERROR-level
`report.issues` entry, but this script only ever printed `report.skipped`
(per-file skips) and always returned 0, never looking at `report.issues` at
all.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from ingest import main  # noqa: E402

REPO = Path(__file__).resolve().parents[2]


def test_ingest_ok(capsys) -> None:
    assert main([str(REPO / "knowledge")]) == 0


def test_a_file_instead_of_a_directory_exits_nonzero(capsys) -> None:
    code = main([str(REPO / "README.md")])

    assert code == 1
    err = capsys.readouterr().err
    assert "ERROR" in err and "snapshot-failed" in err
