"""M6: FastAPI app - HTTP status vs policy outcome, no knowledge-write endpoint."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from app.main import app
from app.storage.db import connect
from app.storage.repository import ChunkRepository

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures" / "assessments"
_BY_NAME = {p.stem: p for p in FIXTURES.rglob("*.yaml")}


@pytest.fixture
def client() -> TestClient:
    # Codex#1 (round 5, 2026-09-12): TestClient's default ASGI peer is
    # ("testclient", 50000) - not a real IP, so `_peer_is_loopback` would
    # reject every request. A real deployment's loopback peer is 127.0.0.1;
    # set that explicitly so these tests exercise the actual gate rather than
    # bypassing it via an ASGI-transport quirk.
    return TestClient(app, client=("127.0.0.1", 12345))


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


def test_concurrent_identical_answers_do_not_duplicate_the_assessment(
    client: TestClient,
) -> None:
    """Regression for Codex cross-review finding #6 (round 4, 2026-09-12),
    reproduced exactly as reported: two threads submitting the SAME patch
    against the SAME parent, synchronized so both would miss the
    sequential-repeat cache (above) before either could populate it, used to
    each run a full re-assessment and create two distinct child assessments.
    A lock per cache key now serializes the check-cache/run/store section -
    `_run` is slowed down (not raced with a rendezvous barrier, which would
    deadlock against the fix's own serialization) to widen the window a real
    assessment might not reliably hit."""
    import threading
    import time

    import app.main as main_module

    created = client.post(
        "/v1/assessments", json=_input("U-002-memory-persistence-unspecified")
    ).json()
    aid = created["result"]["assessment_id"]

    original_run = main_module._run
    call_count = {"n": 0}

    def _slow_run(inp, settings):  # type: ignore[no-untyped-def]
        call_count["n"] += 1
        time.sleep(0.1)
        return original_run(inp, settings)

    main_module._run = _slow_run  # type: ignore[assignment]
    try:
        start = threading.Event()
        results: list[str] = []

        def _submit() -> None:
            start.wait()
            resp = client.post(
                f"/v1/assessments/{aid}/answers", json={"memory_persistent": True}
            )
            results.append(resp.json()["result"]["assessment_id"])

        threads = [threading.Thread(target=_submit) for _ in range(4)]
        for t in threads:
            t.start()
        start.set()
        for t in threads:
            t.join()
    finally:
        main_module._run = original_run

    assert call_count["n"] == 1  # the lock collapsed every concurrent call to one _run()
    assert len(set(results)) == 1  # and every thread got that same assessment_id


def test_answers_repeated_identical_patch_against_same_parent_is_idempotent(
    client: TestClient,
) -> None:
    """Regression for Codex cross-review finding #6, part 2 (round 2,
    2026-09-11), reproduced as reported: repeating the SAME (non-no-op)
    patch against the SAME parent three times used to produce three separate
    assessments/store entries with byte-for-byte identical content - e.g. a
    client retrying after a dropped response paid for (and stored) full
    duplicate re-assessments."""
    created = client.post(
        "/v1/assessments", json=_input("U-002-memory-persistence-unspecified")
    ).json()
    aid = created["result"]["assessment_id"]

    ids = set()
    for _ in range(3):
        resp = client.post(f"/v1/assessments/{aid}/answers", json={"memory_persistent": True})
        assert resp.status_code == 200
        ids.add(resp.json()["result"]["assessment_id"])

    assert len(ids) == 1  # all three calls returned the SAME assessment
    history = client.get(f"/v1/assessments/{next(iter(ids))}/history").json()
    assert [h["revision"] for h in history] == [1, 2]  # only one new revision, not three


def test_assessment_input_rejects_an_oversized_prompt(client: TestClient) -> None:
    """Regression for Codex cross-review finding #6 (round 2, 2026-09-11),
    reproduced close to the reviewer's own repro: an assessment containing a
    huge user_prompts string used to be accepted (200) and retained in full
    in the in-memory store. AssessmentInput now bounds field sizes.

    Sized to exceed AssessmentInput's own 50,000-character field bound while
    staying under _MAX_BODY_SIZE's wire-level cap (round 4), so this
    specifically exercises pydantic's field validation (422), not the
    earlier ASGI-level body-size gate (413, covered separately below)."""
    resp = client.post(
        "/v1/assessments",
        json={"name": "t", "user_prompts": ["x" * 60_000]},
    )
    assert resp.status_code == 422


def test_oversized_request_body_is_rejected_before_json_parsing(client: TestClient) -> None:
    """Regression for Codex cross-review finding #4 (round 4, 2026-09-12),
    reproduced exactly as reported: padding a request with megabytes of
    whitespace around a tiny valid AssessmentInput returned 200 - pydantic's
    canonical serialization drops the padding, so the total-size guard on
    the PARSED model never saw the actual wire size. The ASGI-level body-size
    middleware counts raw bytes as they stream in, independent of what they
    deserialize to."""
    padding = " " * 2_000_000
    resp = client.post(
        "/v1/assessments",
        content=f'{padding}{{"name": "padding-repro"}}'.encode(),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413


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


def test_knowledge_validate_handles_an_invalid_date_cleanly(client: TestClient) -> None:
    """Regression for Codex cross-review finding #8 (round 2, 2026-09-11),
    reproduced exactly as reported: a syntactically YAML-timestamp-shaped but
    semantically invalid date (month=99) made PyYAML's constructor raise a
    bare ValueError, not caught by the existing yaml.YAMLError handler -
    POST /v1/knowledge/validate returned a 500 instead of a clean
    {valid: false} response."""
    resp = client.post(
        "/v1/knowledge/validate",
        json={"content": "---\nlast_reviewed: 2026-99-99\n---\nbody"},
    )
    assert resp.status_code == 200
    assert resp.json()["valid"] is False


def test_knowledge_validate_rejects_deeply_nested_flow_collections(client: TestClient) -> None:
    """Regression for Codex cross-review finding #2, part 2 (round 3,
    2026-09-12), reproduced exactly as reported: hundreds of nested
    flow-style brackets (``[[[...]]]``) drove PyYAML's composer past
    Python's recursion limit - RecursionError is not a yaml.YAMLError
    subclass, so this returned an HTTP 500 instead of a clean
    {valid: false} response."""
    nested = "x: " + "[" * 700 + "]" * 700
    resp = client.post("/v1/knowledge/validate", json={"content": f"---\n{nested}\n---\nbody"})
    assert resp.status_code == 200
    assert resp.json()["valid"] is False


def test_knowledge_validate_rejects_oversized_content(client: TestClient) -> None:
    """Codex cross-review finding #2, part 3 (round 3, 2026-09-12): the whole
    request body is now bounded independently of the YAML-specific guards
    above (which cap the front-matter block, not the full document)."""
    resp = client.post("/v1/knowledge/validate", json={"content": "x" * 200_001})
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


def test_chunked_oversized_body_to_a_bodyless_route_is_rejected() -> None:
    """Regression for Codex#10 (round 9, 2026-09-12), reproduced exactly as
    reported: the Content-Length precheck (round 8, Codex#13) fixed the
    ordinary oversized-request case, but a CHUNKED request (which omits
    Content-Length entirely) to a bodyless endpoint was never counted by
    anything, since nothing downstream ever called receive() to trigger
    the old per-chunk counter. Tested directly at the ASGI protocol level
    (no Content-Length header, multiple http.request frames with
    more_body=True) since it is the transport-level omission of
    Content-Length that matters here, not any particular HTTP client's
    ability to produce one."""
    import asyncio

    import app.main as main_module

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/knowledge/reindex",
        "headers": [],  # no content-length - as under chunked transfer-encoding
    }
    chunk = b"x" * 100_000
    chunks_needed = main_module._MAX_BODY_BYTES // len(chunk) + 2
    remaining = chunks_needed

    async def fake_receive() -> dict[str, object]:
        nonlocal remaining
        remaining -= 1
        return {"type": "http.request", "body": chunk, "more_body": remaining > 0}

    async def downstream_app(scope: object, receive: object, send: object) -> None:
        # a bodyless handler: never calls receive() itself, same as
        # reindex()'s real handler.
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    sent: list[dict[str, object]] = []

    async def fake_send(message: dict[str, object]) -> None:
        sent.append(message)

    middleware = main_module._MaxBodySizeMiddleware(downstream_app)
    asyncio.run(middleware(scope, fake_receive, fake_send))

    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 413


def test_reindex_rejects_an_oversized_body_despite_taking_no_body_param(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#13 (round 8, 2026-09-12), reproduced exactly as
    reported: `_MaxBodySizeMiddleware` only counts bytes if the DOWNSTREAM
    handler calls `receive()` - the reindex() handler takes no
    Request/body parameter and never reads the body, so a POST with a
    body far over `_MAX_BODY_BYTES` returned 200 instead of 413."""
    import app.main as main_module

    monkeypatch.setenv("SKOS_KNOWLEDGE_ROOT", str(REPO / "tests" / "fixtures" / "corpus_alt"))
    monkeypatch.setenv("SKOS_DB_PATH", str(tmp_path / "idx.sqlite"))
    oversized = b"x" * (main_module._MAX_BODY_BYTES + 1)
    resp = client.post(
        "/v1/knowledge/reindex",
        content=oversized,
        headers={"Content-Type": "application/octet-stream"},
    )
    assert resp.status_code == 413


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


def test_reindex_422_does_not_disclose_configured_filesystem_paths(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#11 (round 9, 2026-09-12), reproduced exactly as
    reported: a nonexistent SKOS_KNOWLEDGE_ROOT's absolute path and raw OS
    diagnostic were embedded in decision.reasons and returned verbatim in
    the public 422 response - disclosing server configuration to any
    local caller reaching this unauthenticated endpoint."""
    missing_root = tmp_path / "definitely-does-not-exist"
    monkeypatch.setenv("SKOS_KNOWLEDGE_ROOT", str(missing_root))
    monkeypatch.setenv("SKOS_DB_PATH", str(tmp_path / "idx.sqlite"))

    resp = client.post("/v1/knowledge/reindex")

    assert resp.status_code == 422
    body_text = resp.text
    assert str(missing_root) not in body_text
    assert str(tmp_path) not in body_text
    detail = resp.json()["detail"]
    assert detail["decision"]["outcome"] == "POLICY_BLOCKED"
    assert detail["decision"]["reasons"] == ["reindex failed; see server logs for details"]


def test_reindex_endpoint_refuses_an_empty_knowledge_root(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#3 (round 6, 2026-09-12): /v1/knowledge/reindex
    calls reindex_atomic() directly with no guard of its own - an empty
    (but existing) SKOS_KNOWLEDGE_ROOT used to replace a real index with an
    empty one through the API, not just via the CLI script."""
    db = tmp_path / "idx.sqlite"
    monkeypatch.setenv("SKOS_KNOWLEDGE_ROOT", str(REPO / "tests" / "fixtures" / "corpus_alt"))
    monkeypatch.setenv("SKOS_DB_PATH", str(db))
    good = client.post("/v1/knowledge/reindex")
    assert good.status_code == 200
    assert good.json()["ok"] is True

    empty_root = tmp_path / "empty-knowledge-root"
    empty_root.mkdir()
    monkeypatch.setenv("SKOS_KNOWLEDGE_ROOT", str(empty_root))
    bad = client.post("/v1/knowledge/reindex")
    assert bad.status_code == 422
    assert bad.json()["detail"]["decision"]["outcome"] == "POLICY_BLOCKED"

    conn = connect(db, read_only=True)
    try:
        assert ChunkRepository(conn).chunk_count() > 0  # untouched
    finally:
        conn.close()


def test_assessment_endpoint_rejects_a_foreign_origin(client: TestClient) -> None:
    """Regression for Codex#5 / Antigravity SKOS-ADV-13 (round 4,
    2026-09-12), reproduced exactly as reported: only
    /v1/knowledge/reindex enforced the local-origin check (see
    `test_reindex_rejects_cross_origin_csrf_with_a_legitimate_host` below) -
    the assessment endpoints, which can trigger LLM-provider spend and
    return excerpts of internal/confidential Knowledge Units, had none. A
    DNS-rebinding attacker (a domain that rebinds to 127.0.0.1) or a
    same-machine malicious page could reach them directly. The
    `_local_origin_gate` middleware now covers every route."""
    resp = client.post(
        "/v1/assessments",
        json={"name": "t"},
        headers={"Origin": "https://attacker.example"},
    )
    assert resp.status_code == 403


def test_health_endpoint_is_exempt_from_the_origin_gate(client: TestClient) -> None:
    """/health returns no sensitive data and triggers no provider spend, so
    it is deliberately excluded from `_local_origin_gate` - useful for a
    liveness probe that may not send Origin/Host exactly as expected."""
    resp = client.get("/health", headers={"Origin": "https://attacker.example"})
    assert resp.status_code == 200


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


def test_reindex_rejects_a_cross_port_localhost_origin(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#3 (round 8, 2026-09-12), reproduced exactly as
    reported: `_is_local_origin` compared only the HOSTNAME
    (`_hostname_only` strips the port), so `Origin: http://testserver:9999`
    passed against this service actually serving on the default port -
    both reduce to the hostname "testserver". A hostile page on any OTHER
    localhost port could trigger this endpoint; a browser's own
    same-origin policy already treats a different port as a different
    origin, and this check must match that."""
    monkeypatch.setenv("SKOS_KNOWLEDGE_ROOT", str(REPO / "tests" / "fixtures" / "corpus_alt"))
    monkeypatch.setenv("SKOS_DB_PATH", str(tmp_path / "idx.sqlite"))
    resp = client.post(
        "/v1/knowledge/reindex", headers={"Origin": "http://testserver:9999"}
    )
    assert resp.status_code == 403


def test_reindex_rejects_a_forged_localhost_host_from_a_remote_peer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#1 (round 5, 2026-09-12), reproduced exactly as
    reported: `_is_local_origin` trusted the client-supplied Host/Origin/
    Referer headers alone. If Uvicorn were ever bound to a non-loopback
    address, a remote client that sends `Host: localhost` (no Origin/Referer)
    passed that check outright - the transport peer address was never
    consulted. A client whose ASGI peer is a real, non-loopback IP must be
    rejected even when every header claims to be local."""
    monkeypatch.setenv("SKOS_KNOWLEDGE_ROOT", str(REPO / "tests" / "fixtures" / "corpus_alt"))
    monkeypatch.setenv("SKOS_DB_PATH", str(tmp_path / "idx.sqlite"))
    remote_client = TestClient(app, client=("203.0.113.7", 54321))
    resp = remote_client.post(
        "/v1/knowledge/reindex", headers={"Host": "localhost"}
    )
    assert resp.status_code == 403


class _FakeModel:
    """A cheap stand-in for (AssessmentInput, AssessmentReport) that only
    needs to support _entry_size()'s model_dump_json() call - these
    eviction-mechanics tests care about the FIFO/threading behaviour of
    _store_put(), not real assessment content."""

    def model_dump_json(self) -> str:
        return "{}"


def test_store_is_bounded_and_evicts_oldest() -> None:
    """Regression for Codex cross-review finding #10 (2026-09-11): _STORE had
    no size bound at all."""
    import app.main as main_module

    original = dict(main_module._STORE)
    original_bytes = dict(main_module._STORE_ENTRY_BYTES)
    original_total = main_module._STORE_TOTAL_BYTES
    original_max = main_module._MAX_STORE_ENTRIES
    main_module._STORE.clear()
    main_module._STORE_ENTRY_BYTES.clear()
    main_module._STORE_TOTAL_BYTES = 0
    main_module._MAX_STORE_ENTRIES = 3
    try:
        for i in range(5):
            main_module._store_put(f"id-{i}", (_FakeModel(), _FakeModel()))  # type: ignore[arg-type]
        assert len(main_module._STORE) == 3
        assert set(main_module._STORE) == {"id-2", "id-3", "id-4"}  # oldest 2 evicted
    finally:
        main_module._MAX_STORE_ENTRIES = original_max
        main_module._STORE.clear()
        main_module._STORE.update(original)
        main_module._STORE_ENTRY_BYTES.clear()
        main_module._STORE_ENTRY_BYTES.update(original_bytes)
        main_module._STORE_TOTAL_BYTES = original_total


def test_store_evicts_on_total_byte_budget_not_just_entry_count() -> None:
    """Regression for Codex#8 (round 8, 2026-09-12), reproduced exactly as
    reported: an entry-COUNT cap alone bounds nothing about actual memory -
    5,000 entries near AssessmentInput's own 300,000-byte total-size cap
    retain ~1.5 GB from the inputs alone. A byte-weighted budget must evict
    well before the entry-count cap when entries are large, even though
    the count cap alone would have allowed many more of them."""
    import app.main as main_module

    class _BigModel:
        def model_dump_json(self) -> str:
            return "x" * 1_000_000  # 1 MB per (half-)entry

    original = dict(main_module._STORE)
    original_bytes = dict(main_module._STORE_ENTRY_BYTES)
    original_total = main_module._STORE_TOTAL_BYTES
    original_max = main_module._MAX_STORE_ENTRIES
    original_max_bytes = main_module._MAX_STORE_BYTES
    main_module._STORE.clear()
    main_module._STORE_ENTRY_BYTES.clear()
    main_module._STORE_TOTAL_BYTES = 0
    main_module._MAX_STORE_ENTRIES = 5000  # count cap alone would allow all of these
    main_module._MAX_STORE_BYTES = 5_000_000  # ~5 MB - only ~2 of these 2 MB entries fit
    try:
        for i in range(5):
            main_module._store_put(f"id-{i}", (_BigModel(), _BigModel()))  # type: ignore[arg-type]
        assert len(main_module._STORE) < 5, "byte budget must evict before the count cap does"
        assert main_module._STORE_TOTAL_BYTES <= main_module._MAX_STORE_BYTES
    finally:
        main_module._MAX_STORE_ENTRIES = original_max
        main_module._MAX_STORE_BYTES = original_max_bytes
        main_module._STORE.clear()
        main_module._STORE.update(original)
        main_module._STORE_ENTRY_BYTES.clear()
        main_module._STORE_ENTRY_BYTES.update(original_bytes)
        main_module._STORE_TOTAL_BYTES = original_total


def test_store_put_is_thread_safe_under_concurrent_eviction() -> None:
    """Regression for Codex#5 (round 5, 2026-09-12): with `_MAX_STORE_ENTRIES
    = 1`, concurrent `_store_put` calls raced the unguarded
    assign/len-check/evict sequence, raising `RuntimeError("dictionary
    changed size during iteration")` and `KeyError`. Plain concurrent threads
    do not reliably land inside that window (the sequence is a handful of
    fast C calls), so `.pop()` is slowed on this dict instance only, to
    deterministically widen the gap between the `len()` check and the actual
    eviction - `_STORE_GUARD` must still serialize the whole sequence despite
    that, and no thread should observe an exception either way."""
    import threading
    import time

    import app.main as main_module

    class _SlowPopDict(dict):  # type: ignore[type-arg]
        def pop(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            time.sleep(0.01)
            return super().pop(*args, **kwargs)

    original = main_module._STORE
    original_bytes = dict(main_module._STORE_ENTRY_BYTES)
    original_total = main_module._STORE_TOTAL_BYTES
    original_max = main_module._MAX_STORE_ENTRIES
    main_module._STORE = _SlowPopDict()  # type: ignore[assignment]
    main_module._STORE_ENTRY_BYTES.clear()
    main_module._STORE_TOTAL_BYTES = 0
    main_module._MAX_STORE_ENTRIES = 1
    errors: list[BaseException] = []

    def _worker(i: int) -> None:
        try:
            main_module._store_put(f"id-{i}", (_FakeModel(), _FakeModel()))  # type: ignore[arg-type]
        except BaseException as exc:  # noqa: BLE001 - capturing for the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(32)]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        assert len(main_module._STORE) <= main_module._MAX_STORE_ENTRIES
    finally:
        main_module._MAX_STORE_ENTRIES = original_max
        main_module._STORE = original
        main_module._STORE_ENTRY_BYTES.clear()
        main_module._STORE_ENTRY_BYTES.update(original_bytes)
        main_module._STORE_TOTAL_BYTES = original_total


def test_answer_lock_eviction_does_not_break_the_singleflight_guarantee() -> None:
    """Regression for Codex#12 (round 8, 2026-09-12), reproduced exactly as
    reported: with `_MAX_ANSWER_LOCKS = 1`, obtaining lock A, then
    requesting a different key B (evicting A's dict entry under plain FIFO
    eviction - not the lock object itself, which the first caller still
    holds), then requesting "A" again used to return a DIFFERENT, freshly
    created Lock object - uncontended, even while the original is still
    held. Two concurrent callers for the SAME key could then both enter
    the critical section this is meant to serialize."""
    import threading

    import app.main as main_module

    original = dict(main_module._ANSWER_LOCKS)
    original_max = main_module._MAX_ANSWER_LOCKS
    main_module._ANSWER_LOCKS.clear()
    main_module._MAX_ANSWER_LOCKS = 1
    key_a = ("parent-a", "hash-a")
    key_b = ("parent-b", "hash-b")
    entered_critical_section = threading.Event()
    second_caller_got_in = threading.Event()
    release_first_caller = threading.Event()

    def _hold_a() -> None:
        with main_module._answer_lock_for(key_a):
            entered_critical_section.set()
            release_first_caller.wait(timeout=5)

    def _request_b_then_a_again() -> None:
        # requesting a different key while capacity is 1 must not evict A's
        # entry while it is still held.
        with main_module._answer_lock_for(key_b):
            pass
        with main_module._answer_lock_for(key_a):
            second_caller_got_in.set()

    try:
        t1 = threading.Thread(target=_hold_a)
        t1.start()
        assert entered_critical_section.wait(timeout=5), "first caller never entered"

        t2 = threading.Thread(target=_request_b_then_a_again)
        t2.start()
        # the second caller must be BLOCKED on the same lock object, not
        # sail through on a fresh one - give it a moment, then confirm.
        assert not second_caller_got_in.wait(timeout=0.2), (
            "second caller for the SAME key entered while the first still held it"
        )

        release_first_caller.set()
        t1.join(timeout=5)
        t2.join(timeout=5)
        assert second_caller_got_in.is_set(), "second caller never got in after release"
    finally:
        main_module._MAX_ANSWER_LOCKS = original_max
        main_module._ANSWER_LOCKS.clear()
        main_module._ANSWER_LOCKS.update(original)


def test_answer_cache_put_is_thread_safe_under_concurrent_eviction() -> None:
    """Same race as `test_store_put_is_thread_safe_under_concurrent_eviction`,
    for `_ANSWER_CACHE` / `_ANSWER_CACHE_GUARD` (Codex#5, round 5,
    2026-09-12): the review's suggested fix called for a concurrency test on
    both caches, not just `_STORE`."""
    import threading
    import time

    import app.main as main_module

    class _SlowPopDict(dict):  # type: ignore[type-arg]
        def pop(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            time.sleep(0.01)
            return super().pop(*args, **kwargs)

    original = main_module._ANSWER_CACHE
    original_max = main_module._MAX_ANSWER_CACHE_ENTRIES
    main_module._ANSWER_CACHE = _SlowPopDict()  # type: ignore[assignment]
    main_module._MAX_ANSWER_CACHE_ENTRIES = 1
    errors: list[BaseException] = []

    def _worker(i: int) -> None:
        try:
            main_module._answer_cache_put((f"parent-{i}", f"hash-{i}"), f"id-{i}")
        except BaseException as exc:  # noqa: BLE001 - capturing for the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(32)]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        assert len(main_module._ANSWER_CACHE) <= main_module._MAX_ANSWER_CACHE_ENTRIES
    finally:
        main_module._MAX_ANSWER_CACHE_ENTRIES = original_max
        main_module._ANSWER_CACHE = original


def test_no_knowledge_write_endpoint(client: TestClient) -> None:
    paths = {route.path for route in app.routes}
    for p in paths:
        assert "knowledge" not in p or p in {"/v1/knowledge/validate", "/v1/knowledge/reindex"}
    # and the two knowledge endpoints do not accept a write/mutation verb beyond POST-as-query
    assert "/v1/knowledge/update" not in paths
    assert "/v1/knowledge/delete" not in paths
