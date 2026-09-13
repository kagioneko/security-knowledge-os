"""scripts/evaluate.py: an invalid fixture must fail the run, not shrink it.

Regression for Codex#6 (round 12, 2026-09-13), reproduced exactly as
reported: a fixture that failed to parse/validate was printed to stderr and
SKIPPED - the evaluation continued over whatever remained and could still
report gates_pass=True, silently certifying a SMALLER sample than what was
actually on disk with no error and exit code 0.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from evaluate import main  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
_REAL_FIXTURES = REPO / "tests" / "fixtures" / "assessments"


def test_an_invalid_fixture_fails_the_run_even_when_everything_else_passes(
    tmp_path: Path, capsys
) -> None:
    """Uses a full COPY of the real (all-passing) fixture set plus one
    broken file, so the only difference from a normal, gates_pass=True run
    is the presence of that one unparseable fixture - isolating this
    specific fix from the separate, stricter gates_pass fix (an empty or
    partial-label evaluation already fails gates_pass on its own and would
    make this test pass for the wrong reason)."""
    fixtures = tmp_path / "assessments"
    shutil.copytree(_REAL_FIXTURES, fixtures)
    (fixtures / "vulnerable" / "V-999-broken.yaml").write_text(
        "name: [this is not a mapping\n", encoding="utf-8"
    )

    exit_code = main(["--fixtures", str(fixtures)])

    assert exit_code == 1
    err = capsys.readouterr().err
    assert "V-999-broken.yaml" in err


def test_a_run_with_no_invalid_fixtures_is_not_penalized_for_it(capsys) -> None:
    """The exit-1-on-skip behaviour must not fire when nothing was actually
    skipped - only an incomplete evaluation is being caught here, not every
    evaluation unconditionally. The real, unmodified fixture set both
    parses cleanly and passes every gate."""
    exit_code = main(["--fixtures", str(_REAL_FIXTURES)])

    assert exit_code == 0
    err = capsys.readouterr().err
    assert "INVALID fixture" not in err
