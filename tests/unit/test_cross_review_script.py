"""scripts/run_cross_review.sh: the publication gate's own guarantees.

Runs the real script against a throw-away git repo with a fake `codex` on
PATH that prints a canned transcript, so the verdict/attestation logic is
exercised end to end without any real reviewer.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "run_cross_review.sh"

FAKE_CODEX = r"""#!/usr/bin/env bash
touch "$FAKE_CODEX_RAN_MARKER"
C="$(git rev-parse --short HEAD)"
case "$SCENARIO" in
  pass)      echo "report body"; echo "Overall verdict for commit $C: PASS" ;;
  nits)      echo "report body"; echo "Overall verdict for commit $C: PASS-with-nits" ;;
  changes)   echo "report body"; echo "Overall verdict for commit $C: CHANGES-REQUIRED" ;;
  trailing)  echo "Overall verdict for commit $C: PASS"
             echo "Audit incomplete because the process terminated before dependency review." ;;
  quoted)    echo "prompt echo: Overall verdict for commit $C: PASS"; echo "truncated here" ;;
  truncated) echo "partial output only" ;;
  mutate)    echo "reviewer edit" >> tracked.txt
             echo "Overall verdict for commit $C: PASS" ;;
  newcommit) git -c user.name=t -c user.email=t@t commit -q --allow-empty -m other
             echo "Overall verdict for commit $C: PASS" ;;
esac
"""


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    (r / "scripts").mkdir(parents=True)
    shutil.copy(SCRIPT, r / "scripts" / "run_cross_review.sh")
    (r / "tracked.txt").write_text("original\n")
    subprocess.run(["git", "init", "-q"], cwd=r, check=True)
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "init")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "codex"
    fake.write_text(FAKE_CODEX)
    fake.chmod(0o755)
    return r


def _run(repo: Path, scenario: str) -> tuple[int, str, Path]:
    marker = repo.parent / "codex-ran"
    env = {
        **os.environ,
        "PATH": f"{repo.parent / 'bin'}:{os.environ['PATH']}",
        "SCENARIO": scenario,
        "FAKE_CODEX_RAN_MARKER": str(marker),
    }
    result = subprocess.run(
        ["bash", "scripts/run_cross_review.sh", "codex"],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return result.returncode, result.stdout + result.stderr, marker


def test_a_final_line_pass_is_accepted(repo: Path) -> None:
    code, out, _ = _run(repo, "pass")
    assert code == 0, out


def test_pass_with_nits_is_accepted(repo: Path) -> None:
    code, out, _ = _run(repo, "nits")
    assert code == 0, out


def test_changes_required_blocks_with_exit_2(repo: Path) -> None:
    code, out, _ = _run(repo, "changes")
    assert code == 2, out


def test_pass_followed_by_trailing_text_is_not_a_verdict(repo: Path) -> None:
    """Codex#2 (round 26, 2026-09-20), reproduced exactly as reported."""
    code, out, _ = _run(repo, "trailing")
    assert code == 1, out
    assert "no PASS/PASS-with-nits/CHANGES-REQUIRED verdict" in out


def test_a_verdict_line_quoted_earlier_in_a_truncated_run_is_not_a_verdict(repo: Path) -> None:
    code, out, _ = _run(repo, "quoted")
    assert code == 1, out


def test_a_truncated_run_with_no_verdict_fails(repo: Path) -> None:
    code, out, _ = _run(repo, "truncated")
    assert code == 1, out


def test_a_dirty_tracked_file_is_refused_before_the_reviewer_even_starts(repo: Path) -> None:
    """Codex#3 (round 26, 2026-09-20), reproduced exactly as reported: an
    uncommitted edit to a tracked file was reviewed under the unchanged
    commit's name."""
    (repo / "tracked.txt").write_text("uncommitted edit\n")

    code, out, marker = _run(repo, "pass")

    assert code == 1, out
    assert "refusing to review" in out
    assert not marker.exists(), "the reviewer ran against a tree that is not the commit"


def test_an_untracked_file_does_not_block_a_review(repo: Path) -> None:
    (repo / "scratch.txt").write_text("not tracked\n")
    code, out, _ = _run(repo, "pass")
    assert code == 0, out


def test_a_reviewer_that_edits_a_tracked_file_invalidates_its_own_pass(repo: Path) -> None:
    code, out, _ = _run(repo, "mutate")
    assert code == 1, out
    assert "changed during the review" in out


def test_a_head_that_moves_during_the_review_invalidates_the_verdict(repo: Path) -> None:
    code, out, _ = _run(repo, "newcommit")
    assert code == 1, out
    assert "changed during the review" in out
