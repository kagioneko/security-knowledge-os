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


def test_validate_safe_tests_catches_a_broken_rule_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Regression for Codex#8 (round 5, 2026-09-12): a syntactically valid
    (even empty) safe-test catalogue can still be USELESS if a configured
    rule references a safe_test_template id it does not contain.
    assess.py's _safe_tests_for() does not raise on that (a rule still
    fires, it just loses its safe-test recommendation) - this command must
    catch it instead of reporting "N safe-test template(s), all valid"."""
    rules_root = tmp_path / "rules"
    rules_root.mkdir()
    (rules_root / "bad.yaml").write_text(
        "id: PI-901\ntitle: t\ncategory: prompt-security\nseverity: high\n"
        "checks: [{outbound_enabled: true}]\n"
        "safe_test_template: ST-DOES-NOT-EXIST\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SKOS_RULES_ROOT", str(rules_root))

    empty_safe_tests = tmp_path / "safe_tests"
    empty_safe_tests.mkdir()

    assert main(["validate-safe-tests", str(empty_safe_tests)]) == 1
    err = capsys.readouterr().err
    assert "PI-901 -> ST-DOES-NOT-EXIST" in err


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


def test_assess_deeply_nested_yaml_exits_cleanly_instead_of_raising(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Regression for Codex#8 (round 11, 2026-09-13), reproduced exactly as
    reported: `skos assess` parsed the input file with a bare
    `yaml.safe_load()` and caught neither yaml.YAMLError, RecursionError,
    nor pydantic ValidationError - hundreds of nested flow-style brackets
    drove PyYAML's composer past Python's recursion limit and raised an
    uncaught RecursionError straight out of the CLI instead of the normal
    exit-code-2 usage-error path."""
    nested = "name: " + "[" * 2000 + "]" * 2000
    bad = tmp_path / "bad.yaml"
    bad.write_text(nested, encoding="utf-8")

    code = main(["assess", str(bad)])

    assert code == 2
    assert "invalid assessment file" in capsys.readouterr().err


def test_assess_oversized_yaml_exits_cleanly_instead_of_raising(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Same protection as above, for the size dimension: a file well over
    AssessmentInput's own 300,000-byte post-parse total-size limit must be
    rejected before the YAML parser ever runs on it, not after."""
    huge = tmp_path / "huge.yaml"
    huge.write_text("name: " + "x" * 600_000, encoding="utf-8")

    code = main(["assess", str(huge)])

    assert code == 2
    assert "invalid assessment file" in capsys.readouterr().err


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
