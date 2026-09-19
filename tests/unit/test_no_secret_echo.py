"""Codex#1 (round 22, 2026-09-19): a credential the validators REJECT must not
be echoed back in the rejection itself - HTTP 422 bodies or CLI stderr."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.cli import main
from app.main import app
from app.models.assessment import AssessmentInput
from app.safe_errors import format_validation_error, sanitize_errors

# Built at runtime so this source file itself never contains a credential-shaped literal.
SECRET = "AKIA" + "Q" * 16


@pytest.fixture
def client() -> TestClient:
    return TestClient(app, client=("127.0.0.1", 12345))


def test_422_on_create_does_not_echo_the_rejected_credential(client: TestClient) -> None:
    response = client.post("/v1/assessments", json={"name": SECRET})

    assert response.status_code == 422
    assert SECRET not in response.text
    detail = response.json()["detail"]
    assert detail, "the caller still needs to learn WHICH field was rejected"
    assert all(set(err) <= {"type", "loc", "msg"} for err in detail)
    assert any(err["loc"][-1] == "name" for err in detail)


def test_422_on_answers_does_not_echo_the_rejected_credential(client: TestClient) -> None:
    response = client.post("/v1/assessments/nope/answers", json={"system_prompt": SECRET})

    assert response.status_code == 422
    assert SECRET not in response.text


def test_sanitize_errors_is_an_allowlist_so_unknown_keys_are_dropped() -> None:
    cleaned = sanitize_errors(
        [{"type": "t", "loc": ("a", 0), "msg": "m", "input": SECRET, "ctx": {"x": SECRET}}]
    )

    assert cleaned == [{"type": "t", "loc": ["a", 0], "msg": "m"}]


def test_format_validation_error_names_the_field_but_not_the_value() -> None:
    with pytest.raises(ValidationError) as excinfo:
        AssessmentInput.model_validate({"name": SECRET})

    assert SECRET in str(excinfo.value), "premise: pydantic's own str() DOES leak it"
    rendered = format_validation_error(excinfo.value)
    assert SECRET not in rendered
    assert "name" in rendered


def test_cli_assess_does_not_print_the_rejected_credential(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(json.dumps({"name": SECRET}), encoding="utf-8")

    assert main(["assess", str(bad)]) == 2

    captured = capsys.readouterr()
    assert SECRET not in captured.err
    assert SECRET not in captured.out
    assert "invalid assessment file" in captured.err
