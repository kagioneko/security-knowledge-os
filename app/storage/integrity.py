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
        actual_count = 0
        for row in conn.execute("SELECT chunk_id, text, hash FROM chunks"):
            actual_count += 1
            expected = hashlib.sha256(row["text"].encode("utf-8")).hexdigest()
            if expected != row["hash"]:
                mismatches.append(row["chunk_id"])
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
