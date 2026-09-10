"""M6: the skos CLI."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.cli import main

REPO = Path(__file__).resolve().parents[2]
_FX = {p.stem: p for p in (REPO / "tests" / "fixtures" / "assessments").rglob("*.yaml")}
V1 = _FX["V-001-indirect-injection-auto-email"]
S1 = _FX["S-001-prompt-only"]


def test_validate_rules_ok(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["validate-rules", str(REPO / "rules")]) == 0
    assert "7 rule(s), all valid" in capsys.readouterr().out


def test_validate_safe_tests_ok(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["validate-safe-tests", str(REPO / "safe_tests")]) == 0
    assert "4 safe-test template(s), all valid" in capsys.readouterr().out


def test_validate_knowledge_on_fixtures_reports_errors() -> None:
    root = REPO / "tests" / "fixtures" / "knowledge"
    assert main(["validate-knowledge", str(root)]) == 1  # fixtures include bad units


def test_assess_completed_exit_zero(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["assess", str(V1)])
    out = capsys.readouterr().out
    assert code == 0
    assert "status: COMPLETED" in out
    assert "overall_status: FAIL" in out


def test_assess_strict_exit_one_on_fail() -> None:
    code = main(
        ["assess", str(V1), "--strict"]
    )
    assert code == 1  # COMPLETED but overall FAIL


def test_assess_json_output(capsys: pytest.CaptureFixture[str]) -> None:
    import json

    main(["assess", str(S1), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "COMPLETED"
    assert "knowledge_revision" in payload["result"]
    assert "model_info" in payload["result"]
    assert "human_review_required" in payload["result"]


def test_assess_policy_blocked_exit_three(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from app.retrieval.index import build_index
    from app.storage.db import connect

    db = tmp_path / "idx.sqlite"
    build_index(REPO / "tests" / "fixtures" / "corpus", db)
    conn = connect(db)
    conn.execute("UPDATE chunks SET text = 'x' WHERE rowid = 1")
    conn.commit()
    conn.close()

    code = main(["assess", str(S1), "--db", str(db)])
    assert code == 3
    assert "POLICY_BLOCKED" in capsys.readouterr().out


def test_test_command_runs_all_fixtures(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["test"]) == 0
    assert "12/12 fixtures completed" in capsys.readouterr().out
