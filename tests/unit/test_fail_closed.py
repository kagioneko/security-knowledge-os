"""M5 / AC-20: classification / integrity / human-gate failures fail closed."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.config import Mode, Settings
from app.models.assessment import SafeTest, SafeTestEnvironment
from app.models.knowledge import Classification
from app.models.policy_outcome import PolicyOutcome, PolicyStop
from app.policy.classification import PolicyBlocked, assert_indexable
from app.policy.human_gate import evaluate_action
from app.policy.safe_test import validate_safe_test
from app.retrieval.index import build_index
from app.reviewer.assess import assess
from app.reviewer.rule_loader import RuleCatalogue
from app.storage.db import connect
from app.storage.integrity import verify_chunk_hashes


def test_classification_gate_fails_closed_on_secret() -> None:
    with pytest.raises(PolicyBlocked):
        assert_indexable(Classification.SECRET)


def test_human_gate_fails_closed_on_unknown_action() -> None:
    assert evaluate_action("unrecognised").outcome is PolicyOutcome.HUMAN_APPROVAL_REQUIRED


def test_malformed_safe_test_fails_closed() -> None:
    bad = SafeTest.model_validate(
        {
            "id": "ST-BAD",
            "title": "t",
            "risk_id": "PI-003",
            "environment": [SafeTestEnvironment.SANDBOX],
            "scope": "x",
            "uses_canary_values": True,
            "steps": ["rm -rf /var on the production host"],
            "expected_secure_behavior": "nothing bad",
            "failure_condition": "something bad",
            "cleanup": ["restore"],
        }
    )
    assert validate_safe_test(bad).outcome is PolicyOutcome.POLICY_BLOCKED


def test_tampered_index_fails_closed(
    tmp_path: Path, corpus_root: Path, catalogue: RuleCatalogue, load_assessment
) -> None:
    db = tmp_path / "idx.sqlite"
    build_index(corpus_root, db)

    conn = connect(db)
    try:
        conn.execute("UPDATE chunks SET text = 'tampered' WHERE rowid = 1")
        conn.commit()
        assert verify_chunk_hashes(conn).outcome is PolicyOutcome.POLICY_BLOCKED
        with pytest.raises(PolicyStop):
            assess(
                load_assessment("S-001-prompt-only"),
                catalogue,
                settings=Settings(mode=Mode.PRIVATE),
                index_conn=conn,
            )
    finally:
        conn.close()


def test_missing_revision_meta_fails_closed(tmp_path: Path, corpus_root: Path) -> None:
    db = tmp_path / "idx.sqlite"
    build_index(corpus_root, db)
    conn = connect(db)
    try:
        conn.execute("DELETE FROM meta WHERE key = 'knowledge_revision'")
        conn.commit()
        assert verify_chunk_hashes(conn).outcome is PolicyOutcome.POLICY_BLOCKED
    finally:
        conn.close()


def test_truncated_index_with_stale_chunk_count_fails_closed(
    tmp_path: Path, corpus_root: Path
) -> None:
    """Regression for Codex cross-review finding #7 (2026-09-11): an index
    whose chunks table was emptied (or never fully written) but whose
    recorded meta.chunk_count still claims the old, larger count used to pass
    - the hash loop has nothing to check when chunks is empty, and nothing
    compared the actual row count against what the index claims to contain."""
    db = tmp_path / "idx.sqlite"
    build_index(corpus_root, db)
    conn = connect(db)
    try:
        real_count = conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
        assert real_count > 0
        conn.execute("DELETE FROM chunks")
        # chunks_fts is contentless - 'delete-all' is the correct wipe here too
        conn.execute("INSERT INTO chunks_fts(chunks_fts) VALUES ('delete-all')")
        conn.commit()
        # meta.chunk_count still says real_count (untouched) - the lie this test targets
        decision = verify_chunk_hashes(conn)
        assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
        assert "chunk_count" in " ".join(decision.reasons)
    finally:
        conn.close()


def test_missing_meta_table_fails_closed_not_a_raw_exception(
    tmp_path: Path, corpus_root: Path
) -> None:
    """Regression for Codex cross-review finding #7 (2026-09-11): a corrupted
    or partially-written index (a required table missing entirely) used to
    raise a bare sqlite3.OperationalError instead of a policy decision,
    breaking the fail-closed contract every caller relies on."""
    db = tmp_path / "idx.sqlite"
    build_index(corpus_root, db)
    conn = connect(db)
    try:
        conn.execute("DROP TABLE meta")
        conn.commit()
        decision = verify_chunk_hashes(conn)  # must not raise
        assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
    finally:
        conn.close()
