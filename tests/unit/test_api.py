"""M6: FastAPI app - HTTP status vs policy outcome, no knowledge-write endpoint."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from app.main import app

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures" / "assessments"
_BY_NAME = {p.stem: p for p in FIXTURES.rglob("*.yaml")}


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def _input(name: str) -> dict:
    return yaml.safe_load(_BY_NAME[name].read_text(encoding="utf-8"))


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


def test_answers_reassesses_and_tracks_history(client: TestClient) -> None:
    created = client.post(
        "/v1/assessments", json=_input("U-002-memory-persistence-unspecified")
    ).json()
    aid = created["result"]["assessment_id"]
    assert created["result"]["overall_status"] == "UNKNOWN"

    resp = client.post(f"/v1/assessments/{aid}/answers", json={"memory_persistent": True})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "COMPLETED"
    assert body["result"]["overall_status"] == "CONDITIONAL"
    assert body["result"]["supersedes"] == aid
    assert body["result"]["revision"] == 2

    history = client.get(f"/v1/assessments/{body['result']['assessment_id']}/history").json()
    assert [h["revision"] for h in history] == [1, 2]


def test_answers_noop_merge_does_not_create_a_new_revision(client: TestClient) -> None:
    """Regression for Codex cross-review finding #10 (2026-09-11): patch.is_empty()
    only catches every field being None. {"human_approval": {}} sets a field to a
    non-None value that merges (.update()) to a no-op, so it used to bypass the
    empty-patch check and trigger a full free re-assessment + new stored revision
    on every repeated call - a repeatable cost/storage amplifier."""
    created = client.post(
        "/v1/assessments", json=_input("U-002-memory-persistence-unspecified")
    ).json()
    aid = created["result"]["assessment_id"]

    resp = client.post(f"/v1/assessments/{aid}/answers", json={"human_approval": {}})
    assert resp.status_code == 200
    body = resp.json()
    assert body["result"]["assessment_id"] == aid  # same assessment returned, not a new one
    assert body["result"]["revision"] == created["result"]["revision"]

    history = client.get(f"/v1/assessments/{aid}/history").json()
    assert len(history) == 1  # no new revision was appended


def test_answers_rejects_unknown_field(client: TestClient) -> None:
    created = client.post("/v1/assessments", json=_input("S-001-prompt-only")).json()
    aid = created["result"]["assessment_id"]
    resp = client.post(f"/v1/assessments/{aid}/answers", json={"bogus_field": 1})
    assert resp.status_code == 422


def test_answers_new_tool_name_is_accepted_and_reevaluated(client: TestClient) -> None:
    created = client.post("/v1/assessments", json=_input("S-001-prompt-only")).json()
    aid = created["result"]["assessment_id"]
    resp = client.post(
        f"/v1/assessments/{aid}/answers",
        json={"tool_permissions": {"db_wipe": "delete"}},
    )
    assert resp.status_code == 200
    findings = {f["risk_id"] for f in resp.json()["result"]["findings"]}
    assert "TOOL-001" in findings  # the newly-declared delete tool is now assessed


def test_answers_rejects_bad_permission_value(client: TestClient) -> None:
    created = client.post("/v1/assessments", json=_input("S-001-prompt-only")).json()
    aid = created["result"]["assessment_id"]
    resp = client.post(
        f"/v1/assessments/{aid}/answers",
        json={"tool_permissions": {"t": "root"}},
    )
    assert resp.status_code == 422


def test_knowledge_validate_rejects_unknown_fields(client: TestClient) -> None:
    """Regression for Codex cross-review finding #15 (2026-09-11): KnowledgeDoc
    silently discarded unknown fields instead of rejecting them, unlike every
    other externally-fed request model."""
    resp = client.post(
        "/v1/knowledge/validate", json={"content": "x", "unknown_field": True}
    )
    assert resp.status_code == 422


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
            "provenance:",
            '  source_title: "example"',
            '  source_license: "public"',
            "  derivation: original",
            '  last_verified: "2026-09-10"',
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


def test_reindex_rejects_a_foreign_host_header(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex cross-review finding #11 (2026-09-11): the endpoint
    accepted a request regardless of Host/Origin - a form-encoded POST from any
    page could trigger it. It is documented as loopback-only; that must be an
    enforced check."""
    monkeypatch.setenv("SKOS_KNOWLEDGE_ROOT", str(REPO / "tests" / "fixtures" / "corpus_alt"))
    monkeypatch.setenv("SKOS_DB_PATH", str(tmp_path / "idx.sqlite"))
    resp = client.post("/v1/knowledge/reindex", headers={"Host": "attacker.example.com"})
    assert resp.status_code == 403


def test_reindex_rejects_cross_origin_csrf_with_a_legitimate_host(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for SKOS-ADV-09 / Codex#3 (round 2, 2026-09-11): the Host
    header names the DESTINATION the client is connecting to, which is always
    correct/local for a request that actually reaches this loopback service -
    it does not identify who INITIATED the request. A cross-origin POST from
    an attacker's page (Origin: https://attacker.example) still carries a
    perfectly legitimate Host header; only Origin (or Referer) reveals it."""
    monkeypatch.setenv("SKOS_KNOWLEDGE_ROOT", str(REPO / "tests" / "fixtures" / "corpus_alt"))
    monkeypatch.setenv("SKOS_DB_PATH", str(tmp_path / "idx.sqlite"))
    resp = client.post(
        "/v1/knowledge/reindex",
        headers={"Origin": "https://attacker.example"},  # Host stays "testserver"
    )
    assert resp.status_code == 403


def test_reindex_allows_a_legitimate_same_origin_request(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SKOS_KNOWLEDGE_ROOT", str(REPO / "tests" / "fixtures" / "corpus_alt"))
    monkeypatch.setenv("SKOS_DB_PATH", str(tmp_path / "idx.sqlite"))
    resp = client.post(
        "/v1/knowledge/reindex", headers={"Origin": "http://testserver"}
    )
    assert resp.status_code == 200


def test_store_is_bounded_and_evicts_oldest() -> None:
    """Regression for Codex cross-review finding #10 (2026-09-11): _STORE had
    no size bound at all."""
    import app.main as main_module

    original = dict(main_module._STORE)
    original_max = main_module._MAX_STORE_ENTRIES
    main_module._STORE.clear()
    main_module._MAX_STORE_ENTRIES = 3
    try:
        for i in range(5):
            main_module._store_put(f"id-{i}", (object(), object()))  # type: ignore[arg-type]
        assert len(main_module._STORE) == 3
        assert set(main_module._STORE) == {"id-2", "id-3", "id-4"}  # oldest 2 evicted
    finally:
        main_module._MAX_STORE_ENTRIES = original_max
        main_module._STORE.clear()
        main_module._STORE.update(original)


def test_no_knowledge_write_endpoint(client: TestClient) -> None:
    paths = {route.path for route in app.routes}
    for p in paths:
        assert "knowledge" not in p or p in {"/v1/knowledge/validate", "/v1/knowledge/reindex"}
    # and the two knowledge endpoints do not accept a write/mutation verb beyond POST-as-query
    assert "/v1/knowledge/update" not in paths
    assert "/v1/knowledge/delete" not in paths
