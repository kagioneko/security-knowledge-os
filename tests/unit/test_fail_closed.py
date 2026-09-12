"""M5 / AC-20: classification / integrity / human-gate failures fail closed."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from app.config import Mode, Settings
from app.models.assessment import AssessmentInput, SafeTest, SafeTestEnvironment
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


def test_empty_catalogue_fails_closed_not_false_pass(
    load_assessment: Callable[[str], AssessmentInput],
) -> None:
    """Regression for SKOS-ADV-06 / Codex#1 (round 2, 2026-09-11): load_rules()
    rejects an empty/missing rules root, but assess() itself did not - a
    caller using the library API directly with RuleCatalogue() (a wiring
    mistake, zero rules loaded) got a silent PASS, human_review_required=False,
    instead of a refusal."""
    empty_catalogue = RuleCatalogue()
    assert empty_catalogue.rules == []
    with pytest.raises(PolicyStop) as exc:
        assess(
            load_assessment("S-001-prompt-only"),
            empty_catalogue,
            settings=Settings(mode=Mode.PRIVATE),
        )
    assert exc.value.decision.outcome is PolicyOutcome.POLICY_BLOCKED


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


def test_fts_wipe_fails_closed_even_though_chunks_and_meta_agree(
    tmp_path: Path, corpus_root: Path
) -> None:
    """Regression for Codex cross-review finding #5 (round 3, 2026-09-12),
    reproduced exactly as reported: wiping only the `chunks_fts` virtual
    table (`INSERT INTO chunks_fts(chunks_fts) VALUES ('delete-all')`) while
    leaving `chunks`/`meta` untouched used to pass every existing check -
    they only ever read `chunks` directly - so an index that would silently
    return zero search results was reported ALLOWED."""
    db = tmp_path / "idx.sqlite"
    build_index(corpus_root, db)
    conn = connect(db)
    try:
        real_count = conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
        assert real_count > 0
        conn.execute("INSERT INTO chunks_fts(chunks_fts) VALUES ('delete-all')")
        conn.commit()
        # chunks and meta.chunk_count both still agree on real_count - only
        # the FTS shadow table was emptied.
        decision = verify_chunk_hashes(conn)
        assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
        assert "chunks_fts" in " ".join(decision.reasons)
    finally:
        conn.close()


def test_fts_content_replacement_fails_closed_even_with_matching_counts(
    tmp_path: Path, corpus_root: Path
) -> None:
    """Regression for Codex cross-review finding #2 (round 5, 2026-09-12),
    reproduced exactly as reported: `chunks_fts` is contentless, so its
    indexed text cannot be read back and verify_chunk_hashes only ever
    compared row *counts* between `chunks` and `chunks_fts`. Wiping and
    re-inserting the SAME rowid with DIFFERENT search text (`chunks`/`meta`
    untouched, counts unchanged) used to pass every check - search() would
    silently return results for content that no longer matches the chunk it
    claims to index."""
    db = tmp_path / "idx.sqlite"
    build_index(corpus_root, db)
    conn = connect(db)
    try:
        rows = conn.execute(
            "SELECT rowid, title, section, text FROM chunks ORDER BY rowid"
        ).fetchall()
        assert len(rows) > 1
        tampered_rowid = rows[0]["rowid"]

        conn.execute("INSERT INTO chunks_fts(chunks_fts) VALUES ('delete-all')")
        for row in rows:
            if row["rowid"] == tampered_rowid:
                search_text = "omega marker completely different from the real chunk"
            else:
                search_text = "\n".join(
                    part for part in (row["title"], row["section"], row["text"]) if part
                ).strip()
            conn.execute(
                "INSERT INTO chunks_fts(rowid, search_text) VALUES (?, ?)",
                (row["rowid"], search_text),
            )
        conn.commit()

        # chunks/meta and the fts row COUNT all still agree (every rowid was
        # reinserted) - only rowid `tampered_rowid`'s indexed content
        # diverged from what `chunks` says it should be.
        decision = verify_chunk_hashes(conn)
        assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
        assert "chunks_fts content mismatch" in " ".join(decision.reasons)
    finally:
        conn.close()


def test_blob_row_type_fails_closed_not_a_raw_attributeerror(
    tmp_path: Path, corpus_root: Path
) -> None:
    """Regression for Codex cross-review finding #7, part 2 (round 2,
    2026-09-11): SQLite's default (non-STRICT) tables do not enforce column
    types. Inserting a BLOB into `chunks.text` made `.encode()` raise a bare
    AttributeError instead of the POLICY_BLOCKED this function exists to
    return - the assessment aborted rather than falsely passing, but via an
    unhandled exception, not the fail-closed contract callers rely on."""
    db = tmp_path / "idx.sqlite"
    build_index(corpus_root, db)
    conn = connect(db)
    try:
        conn.execute("UPDATE chunks SET text = ? WHERE rowid = 1", (b"\x00\x01binary",))
        conn.commit()
        decision = verify_chunk_hashes(conn)  # must not raise
        assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
    finally:
        conn.close()


def test_bogus_category_fails_closed_instead_of_crashing_retrieval(
    tmp_path: Path, corpus_root: Path
) -> None:
    """Regression for Codex cross-review finding #7 (round 4, 2026-09-12),
    reproduced exactly as reported: `chunks.classification`/`category` are
    plain TEXT - SQLite's default (non-STRICT) tables do not enforce enums.
    `UPDATE chunks SET category = 'bogus'` used to pass verify_chunk_hashes()
    as ALLOWED and only crash later, with a bare ValueError (not the
    POLICY_BLOCKED this function exists to return), when
    repository.py's `_row_to_chunk()` tried to construct
    `KnowledgeCategory('bogus')` during retrieval."""
    db = tmp_path / "idx.sqlite"
    build_index(corpus_root, db)
    conn = connect(db)
    try:
        conn.execute("UPDATE chunks SET category = 'bogus' WHERE rowid = 1")
        conn.commit()
        decision = verify_chunk_hashes(conn)  # must not raise
        assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
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
