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


def test_directly_constructed_catalogue_with_an_unknown_fact_fails_closed(
    load_assessment: Callable[[str], AssessmentInput],
) -> None:
    """Regression for Codex#2 (round 11, 2026-09-13), reproduced exactly as
    reported: load_rules() enforces the fact whitelist (via
    clause_eval.validate_clause) for every YAML-sourced rule, but assess()
    itself did not - a RuleCatalogue built directly in Python with a clause
    referencing a nonexistent fact loaded fine (an unknown fact makes
    `is_unknown` always evaluate true) and produced a deterministic, silent
    PASS instead of a refusal."""
    from app.models.risk import RiskRule
    from app.models.rule_clause import Clause, Operator

    bad_rule = RiskRule(
        id="BAD-001",
        title="invalid rule",
        category="agent-security",
        severity="high",
        checks=[Clause(field="not_a_fact", op=Operator.IS_UNKNOWN)],
    )
    with pytest.raises(PolicyStop) as exc:
        assess(
            load_assessment("S-001-prompt-only"),
            RuleCatalogue(rules=[bad_rule]),
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


def test_classification_flip_fails_closed(
    tmp_path: Path, corpus_root: Path, catalogue: RuleCatalogue, load_assessment
) -> None:
    """Regression for Codex#1 (round 6, 2026-09-12), reproduced exactly as
    reported: verify_chunk_hashes() hashed only `text` - `UPDATE chunks SET
    classification='public' WHERE ...` (flipping a confidential chunk to
    public) left the stored hash matching and used to return ALLOWED, so a
    PUBLIC-mode retrieval could return confidential content. The hash must
    now cover classification (and every other security-relevant field) too."""
    db = tmp_path / "idx.sqlite"
    build_index(corpus_root, db)

    conn = connect(db)
    try:
        before = conn.execute(
            "SELECT classification FROM chunks WHERE rowid = 1"
        ).fetchone()["classification"]
        assert before != "public"
        conn.execute("UPDATE chunks SET classification = 'public' WHERE rowid = 1")
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


def test_chunk_hash_delimiter_collision_no_longer_bypasses_classification(
    tmp_path: Path, corpus_root: Path
) -> None:
    """Regression for Codex#3 / Antigravity SKOS-ADV-29 (round 21,
    2026-09-15), reproduced exactly as reported: chunk_content_hash() used
    to NUL-separate its fields (`value.encode() + b"\\x00"` per field),
    which is not injective - a NUL byte embedded inside one field's own
    content (YAML permits it in a quoted scalar) is indistinguishable,
    once hashed, from the separator NUL between two DIFFERENT fields.
    Rewriting a confidential chunk's source_ref/classification/category/
    version so the excess bytes shift into the next field reproduces the
    EXACT SAME digest under the old scheme, while genuinely rebinding the
    row from confidential to public - verify_chunk_hashes() used to
    report this as ALLOWED, a complete silent bypass of the classification
    gate this hash is the sole integrity guard for."""
    from app.models.retrieval import chunk_content_hash

    db = tmp_path / "idx.sqlite"
    build_index(corpus_root, db)

    conn = connect(db)
    try:
        row = conn.execute(
            "SELECT chunk_id, knowledge_id, title, section, text FROM chunks WHERE rowid = 1"
        ).fetchone()
        # A hash-function-level proof the collision is closed: these two
        # field tuples used to hash to the IDENTICAL digest.
        before_hash = chunk_content_hash(
            chunk_id=row["chunk_id"],
            knowledge_id=row["knowledge_id"],
            title=row["title"],
            source_ref="x\x00public\x00rag-security",
            classification="confidential",
            category="agent-security",
            version="1",
            section=row["section"],
            text=row["text"],
        )
        after_hash = chunk_content_hash(
            chunk_id=row["chunk_id"],
            knowledge_id=row["knowledge_id"],
            title=row["title"],
            source_ref="x",
            classification="public",
            category="rag-security",
            version="\x00".join(["confidential", "agent-security", "1"]),
            section=row["section"],
            text=row["text"],
        )
        assert before_hash != after_hash

        # Legitimately store the "before" shape (a real confidential chunk
        # with an embedded-NUL source_ref), then apply the attack: rebind
        # classification to public, shifting the excess NUL-separated
        # bytes into `version`, WITHOUT touching the stored hash - exactly
        # what an attacker exploiting the old collision would do.
        conn.execute(
            "UPDATE chunks SET source_ref = ?, classification = ?, category = ?, "
            "version = ?, hash = ? WHERE rowid = 1",
            ("x\x00public\x00rag-security", "confidential", "agent-security", "1", before_hash),
        )
        conn.commit()
        conn.execute(
            "UPDATE chunks SET source_ref = ?, classification = ?, category = ?, "
            "version = ? WHERE rowid = 1",
            ("x", "public", "rag-security", "\x00".join(["confidential", "agent-security", "1"])),
        )
        conn.commit()

        assert verify_chunk_hashes(conn).outcome is PolicyOutcome.POLICY_BLOCKED
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


def test_forged_revision_fails_closed(tmp_path: Path, corpus_root: Path) -> None:
    """Regression for Codex#6 (round 8, 2026-09-12), reproduced exactly as
    reported: `verify_chunk_hashes()` only checked knowledge_revision for
    presence/truthiness, not shape - a hand-forged, non-hex-digest value
    passed cleanly and was reported back as the index's revision."""
    db = tmp_path / "idx.sqlite"
    build_index(corpus_root, db)
    conn = connect(db)
    try:
        conn.execute(
            "UPDATE meta SET value = 'FORGED-REVISION' WHERE key = 'knowledge_revision'"
        )
        conn.commit()
        decision = verify_chunk_hashes(conn)
        assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
        assert "knowledge_revision" in " ".join(decision.reasons)
    finally:
        conn.close()


def test_non_string_revision_fails_closed_not_a_raw_error(
    tmp_path: Path, corpus_root: Path
) -> None:
    """Regression for Codex#6 (round 8, 2026-09-12), reproduced exactly as
    reported: SQLite's non-STRICT tables never enforced `meta.value` as
    TEXT - a BLOB value for `knowledge_revision` passed the
    presence/truthiness check and could later raise a raw pydantic
    ValidationError downstream instead of failing closed here."""
    db = tmp_path / "idx.sqlite"
    build_index(corpus_root, db)
    conn = connect(db)
    try:
        conn.execute(
            "UPDATE meta SET value = ? WHERE key = 'knowledge_revision'", (b"\xff\xfe",)
        )
        conn.commit()
        decision = verify_chunk_hashes(conn)
        assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
        assert "knowledge_revision" in " ".join(decision.reasons)
    finally:
        conn.close()


def test_missing_fts_shadow_table_fails_closed_not_a_raw_indexerror(
    tmp_path: Path, corpus_root: Path
) -> None:
    """Regression for Codex#6 (round 8, 2026-09-12), reproduced exactly as
    reported: `PRAGMA table_info(<missing table>)` returns zero rows
    rather than raising - for an index missing an expected chunks_fts
    shadow table, `compute_fts_shadow_digest()`'s `columns[0]` raised a
    raw IndexError. Dropping any one of the four shadow tables also
    breaks FTS5's own vtable connection for every later query against
    `chunks_fts` (verified directly: `SELECT count(*) FROM chunks_fts`
    itself then raises "vtable constructor failed"), so `verify_chunk_
    hashes()`'s own earlier `fts_count` check already fails closed via
    the generic sqlite3.DatabaseError handler before ever reaching
    `compute_fts_shadow_digest()` in that full-integration path - this
    tests the helper directly, at the same unit granularity the raw
    IndexError was reported at."""
    from app.storage.integrity import compute_fts_shadow_digest

    db = tmp_path / "idx.sqlite"
    build_index(corpus_root, db)
    conn = connect(db)
    try:
        conn.execute("DROP TABLE chunks_fts_config")
        conn.commit()
        with pytest.raises(RuntimeError, match="chunks_fts_config"):
            compute_fts_shadow_digest(conn)
        # the full integration path still fails closed too, just via the
        # earlier fts_count check's generic sqlite3.DatabaseError handler.
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


def test_fts_appended_token_fails_closed(tmp_path: Path, corpus_root: Path) -> None:
    """Regression for Codex#2 (round 6, 2026-09-12), reproduced exactly as
    reported: the exact-phrase MATCH probe (round 5) only proves the
    canonical text is PRESENT as a contiguous phrase - it cannot prove
    nothing else was ALSO indexed. Rebuilding chunks_fts with the canonical
    search_text plus an extra appended token, on the same rowid/count,
    still passed that probe while MATCH 'injected' returned real results.
    The fts_shadow_digest recorded at build time must catch this too."""
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
            search_text = "\n".join(
                part for part in (row["title"], row["section"], row["text"]) if part
            ).strip()
            if row["rowid"] == tampered_rowid:
                search_text += " zzzinjectedtoken"
            conn.execute(
                "INSERT INTO chunks_fts(rowid, search_text) VALUES (?, ?)",
                (row["rowid"], search_text),
            )
        conn.commit()

        # the exact-phrase probe still passes: the canonical text is a
        # genuine, unbroken prefix of what got indexed.
        match = conn.execute(
            "SELECT rowid FROM chunks_fts WHERE chunks_fts MATCH 'zzzinjectedtoken'"
        ).fetchall()
        assert [r["rowid"] for r in match] == [tampered_rowid]

        decision = verify_chunk_hashes(conn)
        assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
        assert "shadow-table digest mismatch" in " ".join(decision.reasons)
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


def test_shadow_table_column_names_are_never_executed_as_sql(
    tmp_path: Path, corpus_root: Path
) -> None:
    """Regression for Codex#2 (round 22, 2026-09-19), reproduced exactly as
    reported: `compute_fts_shadow_digest()` read column names from `PRAGMA
    table_info()` and interpolated them unquoted into a SELECT, so a
    crafted column named `1, <expression>` was evaluated during the
    integrity check itself (the report used `randomblob(500000000)` for
    memory exhaustion). A registered SQL function that records its own
    invocation makes "was it executed?" directly observable."""
    from app.storage.integrity import compute_fts_shadow_digest

    db = tmp_path / "idx.sqlite"
    build_index(corpus_root, db)
    conn = connect(db)
    calls: list[int] = []
    conn.create_function("boom", 0, lambda: calls.append(1) or 1)
    try:
        for table in (
            "chunks_fts_data",
            "chunks_fts_idx",
            "chunks_fts_docsize",
            "chunks_fts_config",
        ):
            conn.execute(f"DROP TABLE {table}")
            conn.execute(f'CREATE TABLE {table}("1, boom()")')
            conn.execute(f"INSERT INTO {table} VALUES (1)")
        conn.commit()
        with pytest.raises(RuntimeError, match="columns FTS5 creates"):
            compute_fts_shadow_digest(conn)
        assert calls == [], "a schema-derived identifier was executed as SQL"
        assert verify_chunk_hashes(conn).outcome is PolicyOutcome.POLICY_BLOCKED
        assert calls == []
    finally:
        conn.close()


def test_ordinary_tables_masquerading_as_fts5_fail_closed(
    tmp_path: Path, corpus_root: Path
) -> None:
    """Regression for Codex#2 (round 22, 2026-09-19): the row-count and
    digest checks never established that `chunks_fts` is an FTS5 table at
    all - with zero chunks, ordinary tables of the right names passed as
    ALLOWED and retrieval then died later with an untyped SQLite error."""
    db = tmp_path / "idx.sqlite"
    build_index(corpus_root, db)
    conn = connect(db)
    try:
        conn.execute("DROP TABLE chunks_fts")  # drops the virtual table AND its shadows
        conn.execute("CREATE TABLE chunks_fts(search_text)")
        conn.execute("CREATE TABLE chunks_fts_data(id INTEGER PRIMARY KEY, block BLOB)")
        conn.execute("CREATE TABLE chunks_fts_idx(segid, term, pgno)")
        conn.execute("CREATE TABLE chunks_fts_docsize(id INTEGER PRIMARY KEY, sz BLOB)")
        conn.execute("CREATE TABLE chunks_fts_config(k, v)")
        conn.execute("DELETE FROM chunks")
        conn.execute("UPDATE meta SET value = '0' WHERE key = 'chunk_count'")
        conn.commit()

        decision = verify_chunk_hashes(conn)

        assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
        assert "not an FTS5 virtual table" in " ".join(decision.reasons)
    finally:
        conn.close()


@pytest.mark.parametrize("bad_sql", [b"AB", None], ids=["blob", "null"])
def test_a_non_text_chunks_fts_schema_fails_closed_not_a_raw_typeerror(
    tmp_path: Path, corpus_root: Path, bad_sql: bytes | None
) -> None:
    """Regression for Codex#4 (round 26, 2026-09-20), reproduced exactly as
    reported: a corrupted database can store a BLOB (or NULL) in
    `sqlite_master.sql`; the string regex raised a raw TypeError out of
    `verify_chunk_hashes()` instead of returning POLICY_BLOCKED."""
    db = tmp_path / "idx.sqlite"
    build_index(corpus_root, db)
    conn = connect(db)
    try:
        conn.execute("PRAGMA writable_schema=ON")
        conn.execute("UPDATE sqlite_master SET sql = ? WHERE name = 'chunks_fts'", (bad_sql,))
        conn.commit()

        decision = verify_chunk_hashes(conn)

        assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
    finally:
        conn.close()


# --- Codex round 28 (2026-09-20): integrity diagnostics + FTS definition + digest encoding ---

_CRED = "AKIA" + "Q" * 16  # built at runtime: no credential-shaped literal in this source file


def _built(tmp_path: Path, corpus_root: Path):
    db = tmp_path / "idx.sqlite"
    build_index(corpus_root, db)
    return connect(db)


def test_integrity_reasons_never_contain_database_cell_values(
    tmp_path: Path, corpus_root: Path
) -> None:
    """Codex#1 (round 28), reproduced exactly as reported: `UPDATE chunks SET
    chunk_id = '<credential-shaped>'` made the 422 body of a local `POST
    /v1/assessments` read `chunk hash mismatch for ['AKIA...']` - every
    database cell is untrusted input, so a reason may name a row ORDINAL, a
    count or a type, never a value."""
    conn = _built(tmp_path, corpus_root)
    try:
        conn.execute(
            "UPDATE chunks SET chunk_id = ? WHERE rowid = (SELECT MIN(rowid) FROM chunks)",
            (_CRED,),
        )
        conn.commit()

        decision = verify_chunk_hashes(conn)

        assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
        assert _CRED not in " ".join(decision.reasons)
        assert "row ordinal" in " ".join(decision.reasons)
    finally:
        conn.close()


@pytest.mark.parametrize(
    ("key", "expected_fragment"),
    [
        ("knowledge_revision", "knowledge_revision is not a valid sha256"),
        ("fts_shadow_digest", "fts_shadow_digest is not a valid sha256"),
    ],
)
def test_forged_meta_values_are_not_echoed_in_the_reason(
    tmp_path: Path, corpus_root: Path, key: str, expected_fragment: str
) -> None:
    conn = _built(tmp_path, corpus_root)
    try:
        conn.execute("UPDATE meta SET value = ? WHERE key = ?", (_CRED, key))
        conn.commit()

        decision = verify_chunk_hashes(conn)

        assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
        joined = " ".join(decision.reasons)
        assert expected_fragment in joined
        assert _CRED not in joined
    finally:
        conn.close()


def test_forged_chunk_count_is_not_echoed_in_the_reason(
    tmp_path: Path, corpus_root: Path
) -> None:
    conn = _built(tmp_path, corpus_root)
    try:
        conn.execute("UPDATE meta SET value = ? WHERE key = 'chunk_count'", (_CRED,))
        conn.commit()

        decision = verify_chunk_hashes(conn)

        assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
        assert _CRED not in " ".join(decision.reasons)
    finally:
        conn.close()


def test_non_finite_chunk_count_fails_closed_instead_of_raising_overflowerror(
    tmp_path: Path, corpus_root: Path
) -> None:
    """Regression for Codex round-31 (2026-09-25), reproduced exactly as
    reported: the chunk_count integer conversion caught TypeError and
    ValueError but not OverflowError - `meta.value` has REAL affinity, so a
    non-finite float (e.g. `float("inf")`, corruption or a forged value)
    made `int(...)` raise OverflowError, which escaped verify_chunk_hashes()
    (and build_report()) instead of producing the documented POLICY_BLOCKED
    decision."""
    conn = _built(tmp_path, corpus_root)
    try:
        conn.execute(
            "UPDATE meta SET value = ? WHERE key = 'chunk_count'", (float("inf"),)
        )
        conn.commit()

        decision = verify_chunk_hashes(conn)  # must not raise OverflowError

        assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
    finally:
        conn.close()


def test_a_non_canonical_fts_definition_is_rejected_even_with_a_recomputed_digest(
    tmp_path: Path, corpus_root: Path
) -> None:
    """Codex#2 (round 28), reproduced exactly as reported: replace `chunks_fts`
    with `fts5(search_text)` (default tokenizer, real content table), re-insert
    the text and recompute the stored digest -> ALLOWED, with substring
    behaviour silently changed."""
    from app.storage.integrity import compute_fts_shadow_digest

    conn = _built(tmp_path, corpus_root)
    try:
        rows = conn.execute(
            "SELECT rowid, title, section, text FROM chunks ORDER BY rowid"
        ).fetchall()
        conn.execute("DROP TABLE chunks_fts")
        conn.execute("CREATE VIRTUAL TABLE chunks_fts USING fts5(search_text)")
        for row in rows:
            search_text = "\n".join(p for p in (row["title"], row["section"], row["text"]) if p)
            conn.execute(
                "INSERT INTO chunks_fts(rowid, search_text) VALUES (?, ?)",
                (row["rowid"], search_text.strip()),
            )
        conn.commit()
        # the attacker's best case: the stored digest is recomputed to match
        conn.execute("UPDATE meta SET value = ? WHERE key = 'fts_shadow_digest'", ("0" * 64,))
        conn.commit()
        try:
            digest = compute_fts_shadow_digest(conn)
        except RuntimeError:
            digest = None  # the digest itself already refuses a non-canonical table
        if digest is not None:
            conn.execute("UPDATE meta SET value = ? WHERE key = 'fts_shadow_digest'", (digest,))
            conn.commit()

        decision = verify_chunk_hashes(conn)

        assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
        assert "not defined as the application defines it" in " ".join(decision.reasons) or (
            "unexpected chunks_fts_*" in " ".join(decision.reasons)
        )
    finally:
        conn.close()


def test_an_unexpected_fts_content_table_is_rejected(tmp_path: Path, corpus_root: Path) -> None:
    conn = _built(tmp_path, corpus_root)
    try:
        conn.execute("CREATE TABLE chunks_fts_content(id INTEGER PRIMARY KEY, c0)")
        conn.commit()

        decision = verify_chunk_hashes(conn)

        assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
        assert "unexpected chunks_fts_*" in " ".join(decision.reasons)
    finally:
        conn.close()


def test_digest_distinguishes_an_integer_from_the_same_digits_as_text(
    tmp_path: Path, corpus_root: Path
) -> None:
    """Codex#3 (round 28): INTEGER 4 and TEXT '4' used to hash identically."""
    from app.storage.integrity import compute_fts_shadow_digest

    conn = _built(tmp_path, corpus_root)
    try:
        before = compute_fts_shadow_digest(conn)
        assert conn.execute(
            "SELECT typeof(v) FROM chunks_fts_config WHERE k = 'version'"
        ).fetchone()[0] == "integer"
        conn.execute("UPDATE chunks_fts_config SET v = CAST(v AS TEXT) WHERE k = 'version'")
        conn.commit()

        assert compute_fts_shadow_digest(conn) != before
        assert verify_chunk_hashes(conn).outcome is PolicyOutcome.POLICY_BLOCKED
    finally:
        conn.close()


def test_digest_distinguishes_a_shifted_field_boundary(tmp_path: Path, corpus_root: Path) -> None:
    """Codex#3 (round 28): ("audit", "left\\x1fright") and ("audit\\x1fleft",
    "right") used to produce the same digest input."""
    from app.storage.integrity import compute_fts_shadow_digest

    conn = _built(tmp_path, corpus_root)
    try:
        conn.execute(
            "INSERT INTO chunks_fts_config(k, v) VALUES ('audit', ?)", ("left\x1fright",)
        )
        first = compute_fts_shadow_digest(conn)
        conn.execute("DELETE FROM chunks_fts_config WHERE k = 'audit'")
        conn.execute(
            "INSERT INTO chunks_fts_config(k, v) VALUES (?, ?)", ("audit\x1fleft", "right")
        )
        second = compute_fts_shadow_digest(conn)

        assert first != second
    finally:
        conn.close()


def test_a_text_rowid_column_cannot_smuggle_a_cell_into_the_diagnostics() -> None:
    """Codex#2 (re-review of round 29), reproduced exactly as reported: a corrupt
    database declaring its own TEXT column named `rowid` in `chunks` shadowed
    SQLite's real rowid, so the "row ordinal" in a diagnostic printed an
    arbitrary cell (and the API returns the decision in its 422 body)."""
    import sqlite3

    canary = "LEAK_ME_FROM_CORRUPT_CELL"
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript(
        """
        CREATE TABLE chunks(rowid TEXT, chunk_id TEXT, knowledge_id TEXT, title TEXT,
          source_ref TEXT, classification TEXT, category TEXT, version TEXT,
          section TEXT, text TEXT, hash TEXT);
        CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE VIRTUAL TABLE chunks_fts USING fts5(search_text,content='',tokenize='trigram');
        """
    )
    c.execute(
        "INSERT INTO chunks VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (canary, "KU-0001#000", "KU-0001", "t", "s", "public", "methodology", "1", "",
         sqlite3.Binary(b"bad"), "x"),
    )

    decision = verify_chunk_hashes(c)

    assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
    assert canary not in " ".join(decision.reasons)


def test_the_stored_chunk_count_is_not_echoed_even_when_it_is_a_valid_int(
    tmp_path: Path, corpus_root: Path
) -> None:
    conn = _built(tmp_path, corpus_root)
    try:
        conn.execute("UPDATE meta SET value = '424242424242' WHERE key = 'chunk_count'")
        conn.commit()

        decision = verify_chunk_hashes(conn)

        assert decision.outcome is PolicyOutcome.POLICY_BLOCKED
        assert "424242424242" not in " ".join(decision.reasons)
        assert "chunk_count" in " ".join(decision.reasons)
    finally:
        conn.close()


def test_row_ordinals_are_a_plain_running_count(tmp_path: Path, corpus_root: Path) -> None:
    conn = _built(tmp_path, corpus_root)
    try:
        conn.execute(
            "UPDATE chunks SET hash = 'tampered' WHERE rowid = (SELECT MIN(rowid) FROM chunks)"
        )
        conn.commit()

        decision = verify_chunk_hashes(conn)

        assert "row ordinal(s) [1]" in " ".join(decision.reasons)
    finally:
        conn.close()
