"""Index integrity check (spec Section 10 step 8, AC-20 fail-closed)."""

from __future__ import annotations

import hashlib
import sqlite3

from app.models.knowledge import Classification, KnowledgeCategory
from app.models.policy_outcome import PolicyDecision, PolicyOutcome, allow, stop

_VALID_CLASSIFICATIONS = {c.value for c in Classification}
_VALID_CATEGORIES = {c.value for c in KnowledgeCategory}


def verify_chunk_hashes(conn: sqlite3.Connection) -> PolicyDecision:
    """Codex cross-review finding #7 (2026-09-11): the two gaps fixed here are
    both "an index can look fine while lying about its own contents":
      - an empty (or truncated) ``chunks`` table with a stale, nonempty
        ``meta.chunk_count`` used to return ALLOWED - the per-chunk hash loop
        simply had nothing to check, and nothing compared the actual row count
        against what the index claims it should be.
      - a missing/malformed table (``meta`` or ``chunks`` absent - a
        corrupted or partially-written index file) raised a bare
        ``sqlite3.OperationalError`` instead of a policy decision, breaking
        the fail-closed contract every caller of this function relies on.
    """
    try:
        mismatches: list[str] = []
        malformed: list[str] = []
        actual_count = 0
        for row in conn.execute(
            "SELECT chunk_id, text, hash, classification, category FROM chunks"
        ):
            actual_count += 1
            # Codex cross-review finding #7, part 2 (round 2, 2026-09-11):
            # SQLite's default (non-STRICT) tables do not enforce column
            # types - a BLOB (or any non-TEXT value) in `text`/`hash` made
            # `.encode()` raise AttributeError, an unhandled exception that
            # skipped the caller's fail-closed handling instead of producing
            # the POLICY_BLOCKED this function exists to return.
            if not isinstance(row["text"], str) or not isinstance(row["hash"], str):
                malformed.append(row["chunk_id"])
                continue
            # Codex cross-review finding #7 (round 4, 2026-09-12): the same
            # non-STRICT-table gap applies to `classification`/`category` -
            # they are stored as free TEXT, not a SQLite-enforced enum.
            # `UPDATE chunks SET category = 'bogus'` passed every check above
            # (text/hash still matched) and this function returned ALLOWED,
            # but repository.py's `_row_to_chunk()` calls
            # `KnowledgeCategory(row["category"])` during retrieval and
            # raises a bare ValueError instead of the POLICY_BLOCKED this
            # function exists to return before that point is ever reached.
            if (
                row["classification"] not in _VALID_CLASSIFICATIONS
                or row["category"] not in _VALID_CATEGORIES
            ):
                malformed.append(row["chunk_id"])
                continue
            expected = hashlib.sha256(row["text"].encode("utf-8")).hexdigest()
            if expected != row["hash"]:
                mismatches.append(row["chunk_id"])
        if malformed:
            return stop(
                PolicyOutcome.POLICY_BLOCKED,
                "knowledge-index",
                f"malformed row (bad text/hash type or unrecognised classification/category) "
                f"for {malformed[:5]}"
                + ("" if len(malformed) <= 5 else f" (+{len(malformed) - 5} more)"),
            )
        if mismatches:
            return stop(
                PolicyOutcome.POLICY_BLOCKED,
                "knowledge-index",
                f"chunk hash mismatch for {mismatches[:5]}"
                + ("" if len(mismatches) <= 5 else f" (+{len(mismatches) - 5} more)"),
            )

        revision_row = conn.execute(
            "SELECT value FROM meta WHERE key = 'knowledge_revision'"
        ).fetchone()
        if revision_row is None or not revision_row["value"]:
            return stop(
                PolicyOutcome.POLICY_BLOCKED, "knowledge-index", "no knowledge_revision recorded"
            )

        count_row = conn.execute(
            "SELECT value FROM meta WHERE key = 'chunk_count'"
        ).fetchone()
        if count_row is None:
            return stop(
                PolicyOutcome.POLICY_BLOCKED, "knowledge-index", "no chunk_count recorded"
            )
        try:
            recorded_count = int(count_row["value"])
        except (TypeError, ValueError):
            return stop(
                PolicyOutcome.POLICY_BLOCKED,
                "knowledge-index",
                f"chunk_count is not an integer: {count_row['value']!r}",
            )
        if recorded_count != actual_count:
            return stop(
                PolicyOutcome.POLICY_BLOCKED,
                "knowledge-index",
                f"chunk_count mismatch: recorded {recorded_count}, actual {actual_count}",
            )

        # Codex cross-review finding #5 (round 3, 2026-09-12): every check
        # above reads the `chunks` table directly - none of them touch the
        # `chunks_fts` virtual table that search() actually queries. A
        # directly-emptied or partially-written FTS index (e.g. `INSERT INTO
        # chunks_fts(chunks_fts) VALUES ('delete-all')` run against the file
        # outside this app) left `chunks`/`meta` untouched and still passed
        # every check above, so an index that would silently return zero
        # search results was reported ALLOWED.
        #
        # FTS5's own 'integrity-check' special command would be the most
        # thorough test, but it is implemented as an INSERT against the
        # table's config interface, which SQLite's read-only-connection
        # enforcement rejects with "attempt to write a readonly database"
        # before FTS5 ever runs it - and every caller of this function passes
        # a read-only connection. `SELECT count(*)` on a contentless FTS5
        # table only touches its rowid index, which read-only connections can
        # query, so a plain row-count comparison against `chunks` is the
        # read-only-safe substitute: it directly detects the 'delete-all'
        # wipe (and any partial write that drops rows) without requiring
        # write access.
        fts_count = conn.execute("SELECT count(*) AS n FROM chunks_fts").fetchone()["n"]
        if fts_count != actual_count:
            return stop(
                PolicyOutcome.POLICY_BLOCKED,
                "knowledge-index",
                f"chunks_fts row count mismatch: fts has {fts_count}, chunks has {actual_count}",
            )
    except sqlite3.DatabaseError as exc:
        # a missing/malformed table (meta or chunks) means the index file is
        # corrupt or partially written - that is exactly what this function
        # exists to catch, so it must be a policy decision, not a raised
        # exception that skips the caller's fail-closed handling.
        return stop(PolicyOutcome.POLICY_BLOCKED, "knowledge-index", f"index schema error: {exc}")

    return allow("knowledge-index")
