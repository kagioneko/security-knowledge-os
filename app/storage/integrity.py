"""Index integrity check (spec Section 10 step 8, AC-20 fail-closed)."""

from __future__ import annotations

import hashlib
import sqlite3

from app.models.policy_outcome import PolicyDecision, PolicyOutcome, allow, stop


def verify_chunk_hashes(conn: sqlite3.Connection) -> PolicyDecision:
    mismatches: list[str] = []
    for row in conn.execute("SELECT chunk_id, text, hash FROM chunks"):
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

    meta = conn.execute(
        "SELECT value FROM meta WHERE key = 'knowledge_revision'"
    ).fetchone()
    if meta is None or not meta["value"]:
        return stop(
            PolicyOutcome.POLICY_BLOCKED, "knowledge-index", "no knowledge_revision recorded"
        )
    return allow("knowledge-index")
