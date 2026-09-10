"""M6: FastAPI app - HTTP status vs policy outcome, no knowledge-write endpoint."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from app.main import app

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures" / "assessments"


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def _input(name: str) -> dict:
    return yaml.safe_load((FIXTURES / f"{name}.yaml").read_text(encoding="utf-8"))


def test_health(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "ok"}


def test_create_assessment_completed_is_200_even_when_human_review_required(
    client: TestClient,
) -> None:
    resp = client.post("/v1/assessments", json=_input("V-001-indirect-injection-auto-email"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "COMPLETED"
    assert body["result"]["overall_status"] == "FAIL"
    assert body["result"]["human_review_required"] is True  # workflow flag, not an error
    assert body["result"]["knowledge_revision"] is None or len(body["result"]["knowledge_revision"])
    assert body["result"]["model_info"]["deterministic_only"] is True


def test_get_and_report_roundtrip(client: TestClient) -> None:
    created = client.post("/v1/assessments", json=_input("S-001-prompt-only")).json()
    aid = created["result"]["assessment_id"]

    got = client.get(f"/v1/assessments/{aid}")
    assert got.status_code == 200
    assert got.json()["status"] == "COMPLETED"

    report = client.get(f"/v1/assessments/{aid}/report")
    assert report.status_code == 200
    assert "overall_status:" in report.text


def test_unknown_assessment_is_404(client: TestClient) -> None:
    assert client.get("/v1/assessments/nope").status_code == 404


def test_answers_reassesses(client: TestClient) -> None:
    created = client.post("/v1/assessments", json=_input("U-001-tool-permissions-missing")).json()
    aid = created["result"]["assessment_id"]
    resp = client.post(
        f"/v1/assessments/{aid}/answers",
        json={"answers": {"system_prompt": "You only read files."}},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "COMPLETED"


def test_knowledge_validate_is_read_only(client: TestClient) -> None:
    good = "\n".join(
        [
            "---",
            "id: KU-9001",
            "title: t",
            "category: prompt-security",
            "source_type: manual",
            "source_ref: ref",
            "classification: public",
            "status: draft",
            "risk_ids: []",
            'version: "0.1"',
            'last_reviewed: "2026-09-10"',
            "requires_ip_review: false",
            "---",
            "## Summary",
            "x",
        ]
    )
    resp = client.post("/v1/knowledge/validate", json={"content": good})
    assert resp.status_code == 200
    assert resp.json()["valid"] is True

    bad = client.post("/v1/knowledge/validate", json={"content": "no front matter"})
    assert bad.json()["valid"] is False


def test_reindex_endpoint(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SKOS_KNOWLEDGE_ROOT", str(REPO / "tests" / "fixtures" / "corpus_alt"))
    monkeypatch.setenv("SKOS_DB_PATH", str(tmp_path / "idx.sqlite"))
    resp = client.post("/v1/knowledge/reindex")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert resp.json()["decision"]["outcome"] == "ALLOWED"


def test_reindex_fails_closed_returns_422(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        "SKOS_KNOWLEDGE_ROOT", str(REPO / "tests" / "fixtures" / "knowledge")
    )  # has invalid units
    monkeypatch.setenv("SKOS_DB_PATH", str(tmp_path / "idx.sqlite"))
    resp = client.post("/v1/knowledge/reindex")
    assert resp.status_code == 422
    assert resp.json()["detail"]["decision"]["outcome"] == "POLICY_BLOCKED"


def test_no_knowledge_write_endpoint(client: TestClient) -> None:
    paths = {route.path for route in app.routes}
    for p in paths:
        assert "knowledge" not in p or p in {"/v1/knowledge/validate", "/v1/knowledge/reindex"}
    # and the two knowledge endpoints do not accept a write/mutation verb beyond POST-as-query
    assert "/v1/knowledge/update" not in paths
    assert "/v1/knowledge/delete" not in paths
