"""M6: FastAPI app - HTTP status vs policy outcome, no knowledge-write endpoint."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi import HTTPException
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


def test_answers_rejects_past_the_max_chain_depth(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#5 (round 12, 2026-09-13), reproduced exactly as
    reported: the answer-cache dedup only catches a repeat of the SAME
    patch against the SAME parent - always patching the newest CHILD with
    a different value each time bypasses it indefinitely, since the cache
    key changes on every call. Nothing bounded the chain's LENGTH the way
    _MAX_CONCURRENT_ASSESSMENTS bounds its concurrent WIDTH. Every
    assessment already carries its own chain depth for free (`revision`,
    incremented once per successful `/answers` call); capping it closes
    the unbounded-length case with no new state."""
    import app.main as main_module

    monkeypatch.setattr(main_module, "_MAX_ANSWER_CHAIN_DEPTH", 2)

    created = client.post(
        "/v1/assessments", json=_input("U-002-memory-persistence-unspecified")
    ).json()
    aid = created["result"]["assessment_id"]

    first = client.post(f"/v1/assessments/{aid}/answers", json={"memory_persistent": True})
    assert first.status_code == 200
    assert first.json()["result"]["revision"] == 2
    child_id = first.json()["result"]["assessment_id"]

    resp = client.post(f"/v1/assessments/{child_id}/answers", json={"memory_persistent": False})
    assert resp.status_code == 422
    assert "chain depth" in resp.json()["detail"]


def test_a_fresh_assessment_is_unaffected_by_another_lineage_at_the_chain_cap(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The chain-depth cap is per-lineage, not global - a caller that hits
    it on one assessment can always start a brand-new one (itself still
    bounded by the concurrency/store caps), it just cannot keep extending
    the SAME chain indefinitely."""
    import app.main as main_module

    monkeypatch.setattr(main_module, "_MAX_ANSWER_CHAIN_DEPTH", 1)

    created = client.post(
        "/v1/assessments", json=_input("U-002-memory-persistence-unspecified")
    ).json()
    aid = created["result"]["assessment_id"]
    blocked = client.post(f"/v1/assessments/{aid}/answers", json={"memory_persistent": True})
    assert blocked.status_code == 422

    fresh = client.post("/v1/assessments", json=_input("U-002-memory-persistence-unspecified"))
    assert fresh.status_code == 200


def test_concurrent_identical_answers_do_not_duplicate_the_assessment(
    client: TestClient,
) -> None:
    """Regression for Codex cross-review finding #6 (round 4, 2026-09-12),
    reproduced exactly as reported: two threads submitting the SAME patch
    against the SAME parent, synchronized so both would miss the
    sequential-repeat cache (above) before either could populate it, used to
    each run a full re-assessment and create two distinct child assessments.
    A lock per cache key now serializes the check-cache/run/store section -
    `_build_report` (the actual per-request evaluation call since round 10's
    _load_resources()/_evaluate() split, Codex#5, and round 11's removal of
    the now-redundant _evaluate() wrapper, Codex#5) is slowed down (not
    raced with a rendezvous barrier, which would deadlock against the
    fix's own serialization) to widen the window a real assessment might
    not reliably hit."""
    import threading
    import time

    import app.main as main_module

    created = client.post(
        "/v1/assessments", json=_input("U-002-memory-persistence-unspecified")
    ).json()
    aid = created["result"]["assessment_id"]

    original_build_report = main_module._build_report
    call_count = {"n": 0}

    def _slow_build_report(inp, settings, resources):  # type: ignore[no-untyped-def]
        call_count["n"] += 1
        time.sleep(0.1)
        return original_build_report(inp, settings, resources)

    main_module._build_report = _slow_build_report  # type: ignore[assignment]
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
        main_module._build_report = original_build_report

    assert call_count["n"] == 1  # the lock collapsed every concurrent call to one _build_report()
    assert len(set(results)) == 1  # and every thread got that same assessment_id


def test_a_duplicate_answer_waiting_on_the_lock_does_not_hold_a_semaphore_slot(
    client: TestClient,
) -> None:
    """Regression for Codex#5 (round 14, 2026-09-13), reproduced exactly as
    reported: submit_answers() used to acquire _ASSESSMENT_SEMAPHORE (via
    _admitted_resources()) BEFORE _answer_lock_for(cache_key) - a
    duplicate request for the SAME (assessment_id, patch) that lost the
    race for that lock then BLOCKED on it while STILL HOLDING its own
    semaphore permit. With capacity 2, one request doing real work plus
    one duplicate merely WAITING already occupied every slot, so a third,
    completely unrelated assessment got 429 even though only one
    computation was actually running. The fix serializes duplicates on a
    cheaper (assessment_id, input-hash) lock BEFORE admission, so a
    waiter holds no semaphore permit while blocked."""
    import threading
    import time

    import app.main as main_module

    original_max = main_module._MAX_CONCURRENT_ASSESSMENTS
    original_semaphore = main_module._ASSESSMENT_SEMAPHORE
    main_module._MAX_CONCURRENT_ASSESSMENTS = 2
    main_module._ASSESSMENT_SEMAPHORE = main_module.threading.Semaphore(2)

    created = client.post(
        "/v1/assessments", json=_input("U-002-memory-persistence-unspecified")
    ).json()
    aid = created["result"]["assessment_id"]

    original_build_report = main_module._build_report

    def _slow_build_report(inp, settings, resources):  # type: ignore[no-untyped-def]
        time.sleep(0.3)
        return original_build_report(inp, settings, resources)

    main_module._build_report = _slow_build_report  # type: ignore[assignment]
    try:
        start = threading.Event()

        def _submit_duplicate() -> None:
            start.wait()
            client.post(f"/v1/assessments/{aid}/answers", json={"memory_persistent": True})

        threads = [threading.Thread(target=_submit_duplicate) for _ in range(2)]
        for t in threads:
            t.start()
        start.set()
        time.sleep(0.1)  # let both duplicates enter admission/locking

        unrelated = client.post("/v1/assessments", json=_input("S-001-prompt-only"))

        for t in threads:
            t.join()
    finally:
        main_module._build_report = original_build_report
        main_module._MAX_CONCURRENT_ASSESSMENTS = original_max
        main_module._ASSESSMENT_SEMAPHORE = original_semaphore

    assert unrelated.status_code == 200


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


def test_concurrent_assessment_admission_is_bounded() -> None:
    """Regression for Codex#6 (round 9, 2026-09-12), reproduced exactly as
    reported: the loopback checks stop remote/CSRF callers, but nothing
    bounded how many assessments (each a real rule-load, and a real
    provider call when an LLM is configured) could run concurrently -
    a burst of local requests could occupy the whole worker pool or drive
    unbounded concurrent provider spend."""
    import app.main as main_module

    original_max = main_module._MAX_CONCURRENT_ASSESSMENTS
    main_module._MAX_CONCURRENT_ASSESSMENTS = 1
    main_module._ASSESSMENT_SEMAPHORE = main_module.threading.Semaphore(1)
    try:
        acquired_first = main_module._ASSESSMENT_SEMAPHORE.acquire(blocking=False)
        assert acquired_first
        try:
            with pytest.raises(HTTPException) as excinfo:
                main_module._run(
                    main_module.AssessmentInput(name="t"), main_module._settings()
                )
            assert excinfo.value.status_code == 429
        finally:
            main_module._ASSESSMENT_SEMAPHORE.release()
    finally:
        main_module._MAX_CONCURRENT_ASSESSMENTS = original_max
        main_module._ASSESSMENT_SEMAPHORE = main_module.threading.Semaphore(original_max)


def test_run_rejects_before_loading_resources_when_the_semaphore_is_full(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Self-review regression (round 10, 2026-09-13): the round-10 Codex#5
    fix (_load_resources()/_evaluate() split, so the /answers cache
    fingerprint reflects the exact resources evaluated) initially made
    _run() call _load_resources() - a real rule-load, safe-test-load, and
    sqlite connect() - BEFORE ever checking _ASSESSMENT_SEMAPHORE, since
    the semaphore check had moved inside _evaluate(). That undid part of
    the round-9 fix's own stated intent (its comment on
    _ASSESSMENT_SEMAPHORE names "a real rule-load" as one of the two costs
    being bounded, not just the provider call): a burst of requests beyond
    the concurrency cap would each still pay the rule-load cost before
    being told 429. _run() now acquires the semaphore itself BEFORE calling
    _load_resources(), same as before the round-10 refactor."""
    import app.main as main_module

    original_max = main_module._MAX_CONCURRENT_ASSESSMENTS
    main_module._MAX_CONCURRENT_ASSESSMENTS = 1
    main_module._ASSESSMENT_SEMAPHORE = main_module.threading.Semaphore(1)
    called = {"n": 0}
    original_load_resources = main_module._load_resources

    def _tracking_load_resources(settings):  # type: ignore[no-untyped-def]
        called["n"] += 1
        return original_load_resources(settings)

    monkeypatch.setattr(main_module, "_load_resources", _tracking_load_resources)
    try:
        acquired_first = main_module._ASSESSMENT_SEMAPHORE.acquire(blocking=False)
        assert acquired_first
        try:
            with pytest.raises(HTTPException) as excinfo:
                main_module._run(
                    main_module.AssessmentInput(name="t"), main_module._settings()
                )
            assert excinfo.value.status_code == 429
        finally:
            main_module._ASSESSMENT_SEMAPHORE.release()
    finally:
        main_module._MAX_CONCURRENT_ASSESSMENTS = original_max
        main_module._ASSESSMENT_SEMAPHORE = main_module.threading.Semaphore(original_max)

    assert called["n"] == 0, "_load_resources() must not run when the semaphore is full"


def test_answers_rejects_before_loading_resources_when_the_semaphore_is_full(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#5 (round 11, 2026-09-13), reproduced exactly as
    reported: submit_answers() called _load_resources() - a real rule-
    load, safe-test-load, and sqlite connect() - BEFORE ever checking
    _ASSESSMENT_SEMAPHORE, unlike _run() (already fixed in round 10's own
    self-review). A burst of /answers requests beyond the concurrency cap
    would each still pay the full resource-loading cost - even a request
    that will turn out to be a cache HIT - before being told 429.
    _admitted_resources() now gates the load itself for both call paths."""
    import app.main as main_module

    created = client.post(
        "/v1/assessments", json=_input("U-002-memory-persistence-unspecified")
    ).json()
    aid = created["result"]["assessment_id"]

    original_max = main_module._MAX_CONCURRENT_ASSESSMENTS
    main_module._MAX_CONCURRENT_ASSESSMENTS = 1
    main_module._ASSESSMENT_SEMAPHORE = main_module.threading.Semaphore(1)
    called = {"n": 0}
    original_load_resources = main_module._load_resources

    def _tracking_load_resources(settings):  # type: ignore[no-untyped-def]
        called["n"] += 1
        return original_load_resources(settings)

    monkeypatch.setattr(main_module, "_load_resources", _tracking_load_resources)
    try:
        acquired_first = main_module._ASSESSMENT_SEMAPHORE.acquire(blocking=False)
        assert acquired_first
        try:
            resp = client.post(
                f"/v1/assessments/{aid}/answers", json={"memory_persistent": True}
            )
            assert resp.status_code == 429
        finally:
            main_module._ASSESSMENT_SEMAPHORE.release()
    finally:
        main_module._MAX_CONCURRENT_ASSESSMENTS = original_max
        main_module._ASSESSMENT_SEMAPHORE = main_module.threading.Semaphore(original_max)

    assert called["n"] == 0, "_load_resources() must not run when the semaphore is full"


def test_answers_cache_invalidated_when_rules_change(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#5 (round 9, 2026-09-12), reproduced exactly as
    reported: the /answers cache key was only (parent assessment ID,
    merged input hash) - it omitted rule/safe-test content, the knowledge
    index revision, mode, and provider/model settings. After legitimate
    rule maintenance (edit a rule file), resubmitting the SAME patch
    against the SAME parent returned the OLD cached assessment instead of
    running the full reassessment the API advertises.

    Codex#4 (round 11, 2026-09-13): the fingerprint is now a digest of the
    exact PARSED rule/safe-test objects `_load_resources()` loaded, not a
    raw byte hash of the live YAML files (see
    `_rules_and_safe_tests_fingerprint()`'s own comment) - so the edit here
    must be a semantic one (a real field changes), not a comment-only
    edit, which would no longer be detected (correctly: a comment-only
    edit does not change what gets evaluated, so reusing the cached result
    for it is not a bug)."""
    import shutil

    rules_copy = tmp_path / "rules"
    shutil.copytree(REPO / "rules", rules_copy)
    monkeypatch.setenv("SKOS_RULES_ROOT", str(rules_copy))
    monkeypatch.setenv("SKOS_KNOWLEDGE_ROOT", str(REPO / "tests" / "fixtures" / "corpus_alt"))
    monkeypatch.setenv("SKOS_DB_PATH", str(tmp_path / "idx.sqlite"))
    assert client.post("/v1/knowledge/reindex").status_code == 200

    created = client.post(
        "/v1/assessments", json=_input("U-002-memory-persistence-unspecified")
    ).json()
    aid = created["result"]["assessment_id"]

    first = client.post(f"/v1/assessments/{aid}/answers", json={"memory_persistent": True})
    assert first.status_code == 200
    first_id = first.json()["result"]["assessment_id"]

    # simulate a rule-catalogue maintenance edit between the two calls
    mem_rule = rules_copy / "memory" / "MEM-001.yaml"
    assert "severity: high" in mem_rule.read_text(encoding="utf-8")
    mem_rule.write_text(
        mem_rule.read_text(encoding="utf-8").replace("severity: high", "severity: medium"),
        encoding="utf-8",
    )

    second = client.post(f"/v1/assessments/{aid}/answers", json={"memory_persistent": True})
    assert second.status_code == 200
    second_id = second.json()["result"]["assessment_id"]

    assert second_id != first_id, (
        "a rule-catalogue change must invalidate the answer cache, not reuse a stale hit"
    )


def test_answers_evaluates_against_the_rules_state_the_fingerprint_describes(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#5 (round 10, 2026-09-13), reproduced exactly as
    reported via fault injection: the /answers cache key used to be
    computed from a SEPARATE, fresh read of the rules directory
    (_rules_and_safe_tests_fingerprint(), called from the old
    _evaluation_fingerprint()) taken BEFORE _run() loaded its OWN, also
    fresh, copy of the same rules to actually evaluate against. A rules
    edit landing in the window between those two independent reads meant
    the assessment ran against the EDITED rules while the recorded cache
    key still described the PRE-edit content - exactly reproduced here by
    editing MEM-001.yaml's severity as a side effect of computing the
    fingerprint, immediately before the (old) separate load_rules() call
    that actually evaluates the request would see it."""
    import shutil

    import app.main as main_module

    rules_copy = tmp_path / "rules"
    shutil.copytree(REPO / "rules", rules_copy)
    monkeypatch.setenv("SKOS_RULES_ROOT", str(rules_copy))
    monkeypatch.setenv("SKOS_KNOWLEDGE_ROOT", str(REPO / "tests" / "fixtures" / "corpus_alt"))
    monkeypatch.setenv("SKOS_DB_PATH", str(tmp_path / "idx.sqlite"))
    assert client.post("/v1/knowledge/reindex").status_code == 200

    mem_rule = rules_copy / "memory" / "MEM-001.yaml"
    assert "severity: high" in mem_rule.read_text(encoding="utf-8")

    created = client.post(
        "/v1/assessments", json=_input("U-002-memory-persistence-unspecified")
    ).json()
    aid = created["result"]["assessment_id"]

    original_fingerprint = main_module._rules_and_safe_tests_fingerprint
    fired = {"done": False}

    def _racing_fingerprint(settings):  # type: ignore[no-untyped-def]
        result = original_fingerprint(settings)
        if not fired["done"]:
            fired["done"] = True
            mem_rule.write_text(
                mem_rule.read_text(encoding="utf-8").replace(
                    "severity: high", "severity: low"
                ),
                encoding="utf-8",
            )
        return result

    monkeypatch.setattr(main_module, "_rules_and_safe_tests_fingerprint", _racing_fingerprint)

    answered = client.post(f"/v1/assessments/{aid}/answers", json={"memory_persistent": True})
    assert answered.status_code == 200
    assert fired["done"], "test assumption: the rules edit actually happened mid-call"

    finding = next(f for f in answered.json()["result"]["findings"] if f["risk_id"] == "MEM-001")
    assert finding["severity"] == "high", (
        "the assessment must reflect the rules state as of the recorded cache "
        "fingerprint (severity: high, read before the edit), not a rules edit "
        "that landed after fingerprinting but before the actual evaluation "
        "read the rules"
    )


def test_rules_fingerprint_is_immune_to_a_live_file_edit_after_loading(
    tmp_path: Path,
) -> None:
    """Regression for Codex#4 (round 11, 2026-09-13), reproduced exactly as
    reported: even the round-10 fix's "immediately adjacent" read of the
    live rules directory inside _rules_and_safe_tests_fingerprint() was
    still a SEPARATE, non-atomic re-read of settings.rules_root/
    safe_tests_root - a rules edit landing between _load_resources()'s
    parse and that re-read meant the assessment evaluated parsed state A
    while the cache recorded fingerprint B (or vice versa). Hashing the
    canonical model_dump_json() of the already-loaded `resources` (not a
    second read of anything) means a live file edit AFTER loading cannot
    change the fingerprint at all - there is no read left to race
    against."""
    import shutil

    import app.main as main_module

    rules_copy = tmp_path / "rules"
    shutil.copytree(REPO / "rules", rules_copy)
    settings = main_module.Settings(
        rules_root=str(rules_copy),
        safe_tests_root=str(REPO / "safe_tests"),
        db_path=str(tmp_path / "idx.sqlite"),  # does not exist - resources.conn stays None
    )

    resources = main_module._load_resources(settings)
    before = main_module._rules_and_safe_tests_fingerprint(resources)

    mem_rule = rules_copy / "memory" / "MEM-001.yaml"
    assert "severity: high" in mem_rule.read_text(encoding="utf-8")
    mem_rule.write_text(
        mem_rule.read_text(encoding="utf-8").replace("severity: high", "severity: low"),
        encoding="utf-8",
    )

    after = main_module._rules_and_safe_tests_fingerprint(resources)
    assert after == before, "the fingerprint must depend only on `resources`, not live disk state"


def test_answers_does_not_500_on_a_foreign_sqlite_database(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#8 (round 10, 2026-09-13), reproduced exactly as
    reported: pointing SKOS_DB_PATH at a valid SQLite file that just
    contains an unrelated table (no Security Knowledge OS `meta` table)
    made the /answers cache-fingerprint's ChunkRepository.knowledge_revision()
    call raise a bare `sqlite3.OperationalError: no such table: meta`
    straight out of the endpoint - an untyped 500 - before the normal
    fail-closed assessment path (verify_chunk_hashes(), which already
    handles a missing/malformed meta/chunks table as a POLICY_BLOCKED
    decision, not an exception) ever got a chance to run."""
    import sqlite3

    # Created BEFORE the foreign db is in place - build_report()'s own
    # fail-closed path (verify_chunk_hashes()) would otherwise correctly
    # POLICY_BLOCK creation itself, and this test needs an existing parent
    # assessment to submit an answer patch against.
    created = client.post(
        "/v1/assessments", json=_input("U-002-memory-persistence-unspecified")
    ).json()
    aid = created["result"]["assessment_id"]

    foreign_db = tmp_path / "foreign.sqlite"
    conn = sqlite3.connect(foreign_db)
    try:
        conn.execute("CREATE TABLE unrelated_app_table (x INTEGER)")
        conn.commit()
    finally:
        conn.close()

    monkeypatch.setenv("SKOS_DB_PATH", str(foreign_db))

    resp = client.post(f"/v1/assessments/{aid}/answers", json={"memory_persistent": True})
    assert resp.status_code != 500


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


def test_a_flood_of_tiny_frames_within_the_byte_cap_is_still_rejected() -> None:
    """Regression for Codex#1 (round 17, 2026-09-14), reproduced exactly
    as reported: `_MaxBodySizeMiddleware` retained every individual
    `receive()` message dict in a list - a body of at most
    `_MAX_BODY_BYTES` split into a huge number of tiny frames stayed
    within the byte cap while that list grew unboundedly (hundreds of MB
    for a "1 MB" request). `_MAX_BODY_FRAMES` bounds the number of frames
    the middleware will ever process, independent of the byte count -
    this test sends one more frame than that cap allows, each carrying 0
    bytes, so the byte-count check alone would never catch it."""
    import asyncio

    import app.main as main_module

    scope = {"type": "http", "method": "POST", "path": "/v1/knowledge/reindex", "headers": []}
    frames_to_send = main_module._MAX_BODY_FRAMES + 1
    remaining = frames_to_send

    async def fake_receive() -> dict[str, object]:
        nonlocal remaining
        remaining -= 1
        return {"type": "http.request", "body": b"", "more_body": remaining > 0}

    downstream_called = False

    async def downstream_app(scope: object, receive: object, send: object) -> None:
        nonlocal downstream_called
        downstream_called = True

    sent: list[dict[str, object]] = []

    async def fake_send(message: dict[str, object]) -> None:
        sent.append(message)

    middleware = main_module._MaxBodySizeMiddleware(downstream_app)
    asyncio.run(middleware(scope, fake_receive, fake_send))

    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 413
    assert not downstream_called


def test_many_small_frames_within_the_cap_are_correctly_reassembled() -> None:
    """Mirror case: a LEGITIMATE multi-frame body (well under both the
    byte cap and the new frame-count cap) must still be correctly
    reassembled and delivered to the downstream handler as a single
    consolidated body - the fix must not just reject floods, it must
    still work for real chunked uploads."""
    import asyncio

    import app.main as main_module

    scope = {"type": "http", "method": "POST", "path": "/v1/assessments", "headers": []}
    parts = [b"chunk-%d;" % i for i in range(50)]
    expected_body = b"".join(parts)
    remaining = list(parts)

    async def fake_receive() -> dict[str, object]:
        chunk = remaining.pop(0)
        return {"type": "http.request", "body": chunk, "more_body": bool(remaining)}

    received_body = b""

    async def downstream_app(scope: object, receive: object, send: object) -> None:
        nonlocal received_body
        message = await receive()  # type: ignore[misc]
        received_body = message["body"]
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    sent: list[dict[str, object]] = []

    async def fake_send(message: dict[str, object]) -> None:
        sent.append(message)

    middleware = main_module._MaxBodySizeMiddleware(downstream_app)
    asyncio.run(middleware(scope, fake_receive, fake_send))

    assert received_body == expected_body
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 200


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


def test_concurrent_reindex_admission_is_bounded(client: TestClient) -> None:
    """Regression for Codex#6 (round 10, 2026-09-13), reproduced exactly as
    reported: /v1/knowledge/reindex is unauthenticated by design (spec §18
    localhost scope) and enters reindex_atomic()'s own BLOCKING flock() -
    a concurrent request while a rebuild is already running used to occupy
    an AnyIO worker thread waiting on that lock instead of getting an
    immediate answer, exactly the class of gap _ASSESSMENT_SEMAPHORE
    already closes for /v1/assessments (round 9, Codex#6). A nonblocking
    admission gate at the endpoint now rejects with 429 immediately
    instead."""
    import app.main as main_module

    acquired_first = main_module._REINDEX_LOCK.acquire(blocking=False)
    assert acquired_first
    try:
        resp = client.post("/v1/knowledge/reindex")
        assert resp.status_code == 429
    finally:
        main_module._REINDEX_LOCK.release()


def test_reindex_maps_a_busy_lock_report_to_429(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#2 (round 13, 2026-09-13), reproduced exactly as
    reported: `_REINDEX_LOCK` (a `threading.Lock`) only serializes callers
    within THIS process - a concurrent request reaching a DIFFERENT
    Uvicorn worker process passes `_REINDEX_LOCK` too, and
    reindex_atomic()'s own flock() used to always BLOCK that worker's
    thread instead of returning 429. reindex_atomic(blocking=False)
    reports lock contention as decision.subject == "reindex-busy" (see
    its own docstring); this checks the ENDPOINT correctly maps that to
    429, exactly as if a different process held the lock. The actual
    non-blocking flock/errno behaviour itself is exercised directly,
    under a bounded thread-pool timeout (never risking a hung test suite
    the way holding a real contested flock from inside this same process
    would - confirmed by hand: it deadlocks the pre-fix, always-blocking
    code indefinitely), by
    test_reindex_atomic_nonblocking_reports_busy_instead_of_waiting in
    test_reindex.py."""
    import app.main as main_module
    from app.models.policy_outcome import PolicyOutcome, stop
    from app.retrieval.index import ReindexReport

    def _busy(*args, **kwargs):  # type: ignore[no-untyped-def]
        return ReindexReport(
            decision=stop(
                PolicyOutcome.POLICY_BLOCKED,
                "reindex-busy",
                "a reindex is already running; retry shortly",
            )
        )

    monkeypatch.setattr(main_module, "reindex_atomic", _busy)

    resp = client.post("/v1/knowledge/reindex")
    assert resp.status_code == 429


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


def test_reindex_rejects_a_malformed_origin_with_403_not_500(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for Codex#9 (round 12, 2026-09-13), reproduced exactly as
    reported: `urlsplit(origin).hostname`/`.port` raise a raw ValueError
    for a malformed authority (a non-numeric port, or an invalid IPv6
    literal) - `_is_local_origin` propagated that straight out as a
    generic 500 instead of the 403 every other untrusted-origin shape
    already gets. A header this malformed is exactly as untrusted as one
    naming a different host outright."""
    monkeypatch.setenv("SKOS_KNOWLEDGE_ROOT", str(REPO / "tests" / "fixtures" / "corpus_alt"))
    monkeypatch.setenv("SKOS_DB_PATH", str(tmp_path / "idx.sqlite"))
    for origin in ("http://localhost:bad", "http://localhost:99999", "http://[:::]:80"):
        resp = client.post("/v1/knowledge/reindex", headers={"Origin": origin})
        assert resp.status_code == 403, origin


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


def test_answer_lock_gives_up_instead_of_blocking_forever_when_contended() -> None:
    """Regression for Codex#6 (round 15, 2026-09-14), reproduced exactly as
    reported: `_answer_lock_for()` used to call `entry.lock.acquire()`
    with no timeout - enough identical duplicate requests for the same
    (assessment_id, patch) could each occupy one of FastAPI/Starlette's
    fixed-size sync-route worker threads waiting on this same lock
    indefinitely, exhausting the pool shared with every other synchronous
    endpoint. A bounded acquire turns the worst case (a stuck holder) into
    a typed `_AnswerLockBusy` instead of an indefinite thread hold.

    This test itself follows the bounded-blocking-test rule learned the
    hard way in round 13 (a real hang from an unbounded call to
    pre-fix blocking code) - `_answer_lock_for`'s own `timeout=` argument
    is what makes the call below bounded; it is never called without one
    here."""
    import threading

    import app.main as main_module

    key = ("bounded-answer-lock", "hash")
    entered_critical_section = threading.Event()
    release_holder = threading.Event()

    def _hold() -> None:
        with main_module._answer_lock_for(key):
            entered_critical_section.set()
            release_holder.wait(timeout=5)

    holder = threading.Thread(target=_hold)
    try:
        holder.start()
        assert entered_critical_section.wait(timeout=5), "holder never entered"

        with pytest.raises(main_module._AnswerLockBusy), main_module._answer_lock_for(
            key, timeout=0.2
        ):
            pass  # must never be reached - the lock is still held
    finally:
        release_holder.set()
        holder.join(timeout=5)


def test_answer_lock_rejects_a_caller_beyond_the_waiter_cap_immediately() -> None:
    """Regression for Codex#3 (round 16, 2026-09-14), reproduced exactly
    as reported: the round-15 timeout above bounds each INDIVIDUAL wait,
    but not how MANY duplicate requests can be waiting on one key at
    once - a slow first assessment plus roughly one worker-pool's worth
    of duplicate requests for its assessment ID could still occupy every
    synchronous worker thread for repeated 30-second intervals, stalling
    unrelated endpoints (including /health) the whole time. A caller
    beyond the cap (1 holder + `_MAX_ANSWER_LOCK_WAITERS_PER_KEY - 1`
    already-queued waiters) must now be rejected IMMEDIATELY - no worker
    thread ever blocks waiting for it. The production cap (10) is
    monkeypatched down to 2 here so the test needs only two threads and
    runs fast/deterministically, the same pattern already used for
    `_MAX_ANSWER_LOCKS` above."""
    import threading
    import time

    import app.main as main_module

    original_cap = main_module._MAX_ANSWER_LOCK_WAITERS_PER_KEY
    main_module._MAX_ANSWER_LOCK_WAITERS_PER_KEY = 2  # 1 holder + 1 queued waiter
    key = ("waiter-cap-test", "hash")
    holder_in = threading.Event()
    release_holder = threading.Event()
    waiter_started = threading.Event()
    release_waiter = threading.Event()

    def _hold() -> None:
        with main_module._answer_lock_for(key):
            holder_in.set()
            release_holder.wait(timeout=5)

    def _wait_as_second_caller() -> None:
        waiter_started.set()
        with main_module._answer_lock_for(key, timeout=5):
            release_waiter.wait(timeout=5)

    holder = threading.Thread(target=_hold)
    second_caller = threading.Thread(target=_wait_as_second_caller)
    try:
        holder.start()
        assert holder_in.wait(timeout=5), "holder never entered"

        second_caller.start()
        assert waiter_started.wait(timeout=5), "second caller never started"
        # No explicit signal exists for "the second caller has registered
        # itself as a waiter" (only for "about to attempt to"); this short,
        # bounded sleep narrows that race in the common case. The
        # assertion below still checks the real outcome regardless.
        time.sleep(0.1)

        # Deliberately shorter than the holder's own 5s hold above but
        # long enough to clearly distinguish "rejected immediately" (this
        # test's claim) from "waited out its own timeout" (what pre-fix
        # code does instead) - if the holder ever released early enough
        # to let this call legitimately acquire the lock instead, that
        # would only make this assertion harder to fail, never easier.
        start = time.monotonic()
        with pytest.raises(main_module._AnswerLockBusy), main_module._answer_lock_for(
            key, timeout=2
        ):
            pass  # must never be reached - rejected before ever waiting
        elapsed = time.monotonic() - start
        assert elapsed < 1.0, (
            f"third caller waited {elapsed:.2f}s instead of being rejected immediately"
        )
    finally:
        main_module._MAX_ANSWER_LOCK_WAITERS_PER_KEY = original_cap
        release_holder.set()
        release_waiter.set()
        holder.join(timeout=5)
        second_caller.join(timeout=5)


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
