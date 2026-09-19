"""Codex#1 (round 22, 2026-09-19): a credential the validators REJECT must not
be echoed back in the rejection itself - HTTP 422 bodies or CLI stderr."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.cli import main
from app.ingestion.parser import FrontMatterError, safe_load_bounded
from app.main import app
from app.models.assessment import AssessmentInput
from app.reviewer.rule_loader import RuleLoadError, parse_clause
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
        [{"type": "t", "loc": ("name", 0), "msg": "m", "input": SECRET, "ctx": {"x": SECRET}}]
    )

    assert cleaned == [{"type": "t", "loc": ["name", 0], "msg": "m"}]


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


# --- Codex#2 (round 23, 2026-09-20): secret-shaped KEYS leak through `loc` ---


def test_422_does_not_echo_a_secret_used_as_an_extra_property_name(client: TestClient) -> None:
    response = client.post("/v1/assessments", json={"name": "ok", SECRET: 1})

    assert response.status_code == 422
    assert SECRET not in response.text
    assert response.json()["detail"], "the caller must still be told something was rejected"


def test_422_does_not_echo_a_secret_used_as_a_nested_mapping_key(client: TestClient) -> None:
    response = client.post(
        "/v1/assessments", json={"name": "ok", "human_approval": {SECRET: True}}
    )

    assert response.status_code == 422
    assert SECRET not in response.text


def test_known_field_names_survive_redaction_so_messages_stay_useful() -> None:
    from app.safe_errors import safe_loc

    assert safe_loc(("body", "name", 2, SECRET)) == ["body", "name", 2, "<redacted>"]


def test_knowledge_validate_endpoint_does_not_echo_a_secret_front_matter_key(
    client: TestClient,
) -> None:
    doc = f"---\n{SECRET}: 1\ntitle: t\n---\nbody\n"
    response = client.post("/v1/knowledge/validate", json={"content": doc})

    assert SECRET not in response.text


def test_cli_does_not_print_a_secret_used_as_a_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(json.dumps({"name": "ok", SECRET: 1}), encoding="utf-8")

    assert main(["assess", str(bad)]) == 2

    captured = capsys.readouterr()
    assert SECRET not in captured.err + captured.out


# --- YAML syntax errors quoted the offending source line ---


def test_yaml_syntax_error_does_not_quote_the_offending_line() -> None:
    text = f'name: x\ndescription: "{SECRET}\ntools: [a\n'

    with pytest.raises(FrontMatterError) as excinfo:
        safe_load_bounded(text, max_bytes=10_000, what="assessment file")

    assert SECRET not in str(excinfo.value)
    assert "line 2" in str(excinfo.value), "position must remain, so the file is still debuggable"


def test_yaml_constructor_value_error_does_not_quote_the_scalar() -> None:
    with pytest.raises(FrontMatterError) as excinfo:
        safe_load_bounded(f"x: !!int {SECRET}\n", max_bytes=10_000, what="assessment file")

    assert SECRET not in str(excinfo.value)


def test_cli_yaml_syntax_error_does_not_print_the_secret(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(f'name: x\ndescription: "{SECRET}\ntools: [a\n', encoding="utf-8")

    assert main(["assess", str(bad)]) == 2

    assert SECRET not in capsys.readouterr().err


# --- Codex#5 (round 23): malformed shorthand clause must be a typed error ---


def test_malformed_shorthand_clause_is_a_typed_rule_load_error_without_the_value() -> None:
    with pytest.raises(RuleLoadError) as excinfo:
        parse_clause({"external_content_ingestion": {"nested": SECRET}})

    assert SECRET not in str(excinfo.value)


# --- Codex#4 (round 23): the CLI size limit must bound the READ, not just the parse ---


def test_read_text_bounded_never_reads_more_than_the_limit_plus_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import builtins

    import app.ingestion.parser as parser_module

    big = tmp_path / "big.yaml"
    with big.open("wb") as fh:
        fh.truncate(50_000_000)  # sparse: 50 MB logical size, ~0 on disk

    requested: list[int] = []
    real_open = builtins.open

    def spying_open(*args, **kwargs):  # type: ignore[no-untyped-def]
        fh = real_open(*args, **kwargs)
        real_read = fh.read

        def read(n: int = -1) -> bytes:
            requested.append(n)
            return real_read(n)

        return type("Spy", (), {
            "read": staticmethod(read),
            "__enter__": lambda self: self,
            "__exit__": lambda self, *a: fh.close(),
        })()

    monkeypatch.setattr(parser_module, "open", spying_open, raising=False)

    with pytest.raises(FrontMatterError, match="exceeds 1000 bytes"):
        parser_module.read_text_bounded(big, max_bytes=1000, what="assessment file")

    assert requested == [1001], f"unbounded read requested: {requested}"


def test_cli_rejects_an_oversized_assessment_file_with_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    big = tmp_path / "big.yaml"
    with big.open("wb") as fh:
        fh.truncate(2_000_000)

    assert main(["assess", str(big)]) == 2

    assert "exceeds" in capsys.readouterr().err


def test_read_text_bounded_reads_a_normal_file_unchanged(tmp_path: Path) -> None:
    from app.ingestion.parser import read_text_bounded

    f = tmp_path / "ok.yaml"
    f.write_text("name: café\n", encoding="utf-8")

    assert read_text_bounded(f, max_bytes=1000) == "name: café\n"
