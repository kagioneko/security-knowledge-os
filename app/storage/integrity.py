"""Index integrity check (spec Section 10 step 8, AC-20 fail-closed)."""

from __future__ import annotations

import hashlib
import sqlite3

from app.models.policy_outcome import PolicyDecision, PolicyOutcome, allow, stop


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
        for row in conn.execute("SELECT chunk_id, text, hash FROM chunks"):
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
            expected = hashlib.sha256(row["text"].encode("utf-8")).hexdigest()
            if expected != row["hash"]:
                mismatches.append(row["chunk_id"])
        if malformed:
            return stop(
                PolicyOutcome.POLICY_BLOCKED,
                "knowledge-index",
                f"malformed row type (text/hash not TEXT) for {malformed[:5]}"
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
    except sqlite3.DatabaseError as exc:
        # a missing/malformed table (meta or chunks) means the index file is
        # corrupt or partially written - that is exactly what this function
        # exists to catch, so it must be a policy decision, not a raised
        # exception that skips the caller's fail-closed handling.
        return stop(PolicyOutcome.POLICY_BLOCKED, "knowledge-index", f"index schema error: {exc}")

    return allow("knowledge-index")
