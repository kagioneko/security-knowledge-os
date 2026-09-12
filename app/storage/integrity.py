"""Index integrity check (spec Section 10 step 8, AC-20 fail-closed)."""

from __future__ import annotations

import hashlib
import re
import sqlite3

from app.models.knowledge import Classification, KnowledgeCategory
from app.models.policy_outcome import PolicyDecision, PolicyOutcome, allow, stop
from app.models.retrieval import chunk_content_hash

_VALID_CLASSIFICATIONS = {c.value for c in Classification}
_VALID_CATEGORIES = {c.value for c in KnowledgeCategory}

# Codex#6 (round 8, 2026-09-12): both `knowledge_revision` and
# `fts_shadow_digest` are always `hashlib.sha256(...).hexdigest()` output
# (see app.ingestion.loader.compute_knowledge_revision and
# compute_fts_shadow_digest above) - a lowercase 64-character hex string.
# Requiring that exact shape catches a forged/hand-edited value
# (`UPDATE meta SET value = 'FORGED-REVISION' ...`) or a non-string value
# (a BLOB, which SQLite's non-STRICT tables never prevented) at this
# fail-closed boundary, instead of letting it read back "successfully" and
# fail later - e.g. as an unhandled pydantic ValidationError somewhere
# downstream that expects a proper hex digest string.
_HEX_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class _FtsShadowTableMissing(RuntimeError):
    """A `chunks_fts` shadow table `compute_fts_shadow_digest` expects to
    read does not exist - the index is corrupt/partially written."""

# Codex#2 (round 6, 2026-09-12): the tables FTS5 actually stores a
# contentless table's postings in. Table names, not user input - safe to
# interpolate into PRAGMA/SELECT statements (sqlite3 cannot parameterise
# identifiers anyway).
_FTS_SHADOW_TABLES = (
    "chunks_fts_data",
    "chunks_fts_idx",
    "chunks_fts_docsize",
    "chunks_fts_config",
)


def _fts_phrase(text: str) -> str:
    """Quote `text` as a single FTS5 phrase literal. Doubling an embedded
    `"` is FTS5's own escaping rule for a quoted string; every other
    character (including query-syntax metacharacters like `*`/`^`/`NEAR`) is
    literal inside a quoted phrase, so this is safe for arbitrary chunk
    text, not just pre-sanitised user search terms."""
    return '"' + text.replace('"', '""') + '"'


def compute_fts_shadow_digest(conn: sqlite3.Connection) -> str:
    """A digest over FTS5's own on-disk representation of `chunks_fts`
    (its four shadow tables), not just what a MATCH query can observe
    through it.

    Codex#2 (round 6, 2026-09-12), reproduced exactly as reported: the
    exact-phrase MATCH probe in `verify_chunk_hashes()` (Codex#2, round 5)
    only proves the canonical text is PRESENT as a contiguous phrase - it
    cannot prove nothing else was ALSO indexed. Rebuilding `chunks_fts` with
    the canonical `search_text` plus an extra appended token, on the same
    rowid/count, still passed that probe while `MATCH 'appended token'`
    returned real results. `ChunkRepository.rebuild()` computes and stores
    this digest right after it finishes writing `chunks_fts` (called only
    from the build/reindex path, on a writable connection dedicated to that
    one rebuild - nothing else ever writes to these tables again);
    `verify_chunk_hashes()` recomputes it from the same tables and compares.
    Any change to what is actually indexed - replaced, appended, or
    otherwise - changes this digest, regardless of whether it also happens
    to still contain the canonical phrase.
    """
    digest = hashlib.sha256()
    for table in _FTS_SHADOW_TABLES:
        digest.update(table.encode("utf-8"))
        digest.update(b"\x00")
        columns = [row[1] for row in conn.execute(f"PRAGMA table_info({table})")]
        # Codex#6 (round 8, 2026-09-12), reproduced exactly as reported:
        # `PRAGMA table_info` on a MISSING table returns zero rows rather
        # than raising - for an empty/corrupt index missing an expected
        # chunks_fts shadow table, `columns` was `[]` and `columns[0]`
        # below raised a raw IndexError instead of the fail-closed
        # POLICY_BLOCKED this whole check exists to produce.
        if not columns:
            raise _FtsShadowTableMissing(table)
        select = f"SELECT {', '.join(columns)} FROM {table} ORDER BY {columns[0]}"  # noqa: S608
        for row in conn.execute(select):
            for value in row:
                if isinstance(value, bytes):
                    digest.update(value)
                elif value is None:
                    digest.update(b"\x00NULL\x00")
                else:
                    digest.update(str(value).encode("utf-8"))
                digest.update(b"\x1f")
            digest.update(b"\x1e")
    return digest.hexdigest()


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
        fts_content_mismatches: list[str] = []
        actual_count = 0
        for row in conn.execute(
            "SELECT rowid, chunk_id, knowledge_id, title, source_ref, version, section, "
            "text, hash, classification, category FROM chunks"
        ):
            actual_count += 1
            # Codex cross-review finding #7, part 2 (round 2, 2026-09-11):
            # SQLite's default (non-STRICT) tables do not enforce column
            # types - a BLOB (or any non-TEXT value) in `text`/`hash` made
            # `.encode()` raise AttributeError, an unhandled exception that
            # skipped the caller's fail-closed handling instead of producing
            # the POLICY_BLOCKED this function exists to return.
            if (
                not isinstance(row["chunk_id"], str)
                or not isinstance(row["knowledge_id"], str)
                or not isinstance(row["text"], str)
                or not isinstance(row["hash"], str)
                or not isinstance(row["title"], str)
                or not isinstance(row["source_ref"], str)
                or not isinstance(row["version"], str)
                or not isinstance(row["section"], str)
            ):
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
            # Codex#1 (round 6, 2026-09-12), reproduced exactly as reported:
            # the hash used to cover ONLY `text` - `UPDATE chunks SET
            # classification='public' WHERE knowledge_id='KU-1020'` (a
            # confidential unit) passed as ALLOWED, and a PUBLIC-mode
            # retrieval then returned the confidential content, because
            # nothing bound `classification` (or `source_ref`/
            # `knowledge_id`/`title`/`section`/`version`) to the hash at
            # all. chunk_content_hash() covers every field a Chunk carries
            # except the hash itself - the exact same function
            # app/retrieval/index.py used to compute it when writing.
            expected = chunk_content_hash(
                chunk_id=row["chunk_id"],
                knowledge_id=row["knowledge_id"],
                title=row["title"],
                source_ref=row["source_ref"],
                classification=row["classification"],
                category=row["category"],
                version=row["version"],
                section=row["section"],
                text=row["text"],
            )
            if expected != row["hash"]:
                mismatches.append(row["chunk_id"])
                continue
            # Codex cross-review finding #2 (round 5, 2026-09-12): every check
            # above reads `chunks` - none of them prove `chunks_fts` (a
            # separate, contentless FTS5 table with no stored copy of its own
            # indexed text) actually indexes that same text. Replacing a
            # row's FTS postings in place (same rowid, same total row count -
            # `INSERT INTO chunks_fts(chunks_fts) VALUES ('delete-all')`
            # followed by re-inserting different `search_text` for the same
            # rowids) left every check above ALLOWED while search() silently
            # returned results for different content. `chunks_fts` cannot be
            # read back directly (contentless), so this probes it the only
            # way a read-only connection can: an exact-phrase MATCH for the
            # canonical `search_text`, restricted to that row's rowid.
            # Residual gap (accepted): if tampering *appends* extra tokens
            # after an otherwise-intact canonical phrase, this exact-phrase
            # probe still matches (the canonical text is a genuine contiguous
            # prefix of the tampered one) - it is not a full content-equality
            # proof, only a lower-bound integrity signal, but it directly
            # detects the replace-in-place tamper reported above.
            search_text = "\n".join(
                part for part in (row["title"], row["section"], row["text"]) if part
            ).strip()
            if search_text:
                probe = conn.execute(
                    "SELECT 1 FROM chunks_fts WHERE rowid = ? AND chunks_fts MATCH ?",
                    (row["rowid"], _fts_phrase(search_text)),
                ).fetchone()
                if probe is None:
                    fts_content_mismatches.append(row["chunk_id"])
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
        if fts_content_mismatches:
            return stop(
                PolicyOutcome.POLICY_BLOCKED,
                "knowledge-index",
                f"chunks_fts content mismatch (indexed text does not match the "
                f"chunk it claims to index) for {fts_content_mismatches[:5]}"
                + (
                    ""
                    if len(fts_content_mismatches) <= 5
                    else f" (+{len(fts_content_mismatches) - 5} more)"
                ),
            )

        revision_row = conn.execute(
            "SELECT value FROM meta WHERE key = 'knowledge_revision'"
        ).fetchone()
        if revision_row is None or not revision_row["value"]:
            return stop(
                PolicyOutcome.POLICY_BLOCKED, "knowledge-index", "no knowledge_revision recorded"
            )
        # Codex#6 (round 8, 2026-09-12), reproduced exactly as reported:
        # this only checked for presence/truthiness, not shape - a
        # hand-forged `UPDATE meta SET value = 'FORGED-REVISION' ...` (or
        # any non-hex-digest string) passed cleanly and was reported back
        # as the index's revision. `knowledge_revision` is always a
        # `hashlib.sha256(...).hexdigest()`; reject anything else.
        if not isinstance(revision_row["value"], str) or not _HEX_DIGEST_RE.match(
            revision_row["value"]
        ):
            return stop(
                PolicyOutcome.POLICY_BLOCKED,
                "knowledge-index",
                f"knowledge_revision is not a valid sha256 hex digest: "
                f"{revision_row['value']!r}",
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

        # Codex#2 (round 6, 2026-09-12): the exact-phrase MATCH probe above
        # (per-chunk loop) proves the canonical text is present; it cannot
        # prove nothing EXTRA was also indexed (an appended token on an
        # otherwise-intact phrase still matches). This digest over FTS5's
        # own shadow-table storage (`compute_fts_shadow_digest`) catches
        # that: any change to what is actually indexed changes it.
        digest_row = conn.execute(
            "SELECT value FROM meta WHERE key = 'fts_shadow_digest'"
        ).fetchone()
        if digest_row is None or not digest_row["value"]:
            return stop(
                PolicyOutcome.POLICY_BLOCKED, "knowledge-index", "no fts_shadow_digest recorded"
            )
        # Codex#6 (round 8, 2026-09-12): same forged/non-string-value gap as
        # knowledge_revision above, for the other sha256 hexdigest this
        # function trusts from `meta`.
        if not isinstance(digest_row["value"], str) or not _HEX_DIGEST_RE.match(
            digest_row["value"]
        ):
            return stop(
                PolicyOutcome.POLICY_BLOCKED,
                "knowledge-index",
                f"fts_shadow_digest is not a valid sha256 hex digest: {digest_row['value']!r}",
            )
        actual_digest = compute_fts_shadow_digest(conn)
        if actual_digest != digest_row["value"]:
            return stop(
                PolicyOutcome.POLICY_BLOCKED,
                "knowledge-index",
                "chunks_fts shadow-table digest mismatch (indexed content changed after build)",
            )
    except sqlite3.DatabaseError as exc:
        # a missing/malformed table (meta or chunks) means the index file is
        # corrupt or partially written - that is exactly what this function
        # exists to catch, so it must be a policy decision, not a raised
        # exception that skips the caller's fail-closed handling.
        return stop(PolicyOutcome.POLICY_BLOCKED, "knowledge-index", f"index schema error: {exc}")
    except _FtsShadowTableMissing as exc:
        return stop(
            PolicyOutcome.POLICY_BLOCKED,
            "knowledge-index",
            f"chunks_fts shadow table missing: {exc}",
        )

    return allow("knowledge-index")
