"""Build the knowledge index from a configurable knowledge root (spec Section 10).

The knowledge root is a parameter, not a constant: today it points at ``knowledge/``,
later it can point at ``active/knowledge/`` populated by the Pack Manager.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import os
import shutil
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, computed_field

from app.ingestion.loader import LoadedUnit, compute_knowledge_revision, load_corpus
from app.ingestion.validator import Level, validate_tree
from app.models.policy_outcome import PolicyDecision, PolicyOutcome, allow, stop
from app.models.retrieval import Chunk
from app.storage.db import connect
from app.storage.integrity import verify_chunk_hashes
from app.storage.repository import ChunkRepository


@dataclass
class IndexBuildReport:
    knowledge_root: str
    db_path: str
    units_indexed: int = 0
    chunks_indexed: int = 0
    knowledge_revision: str = ""
    classifications: list[str] = field(default_factory=list)
    knowledge_ids: list[str] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    warnings: int = 0


def _chunk_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def chunks_for_unit(unit: LoadedUnit) -> list[Chunk]:
    fm = unit.front_matter
    sections = unit.sections or []
    chunks: list[Chunk] = []
    for ordinal, section in enumerate(sections):
        chunks.append(
            Chunk(
                chunk_id=f"{fm.id}#{ordinal:03d}",
                knowledge_id=fm.id,
                title=fm.title,
                source_ref=fm.source_ref,
                classification=fm.classification,
                category=fm.category,
                version=fm.version,
                section=section.heading,
                text=section.text,
                hash=_chunk_hash(section.text),
            )
        )
    if not chunks:
        chunks.append(
            Chunk(
                chunk_id=f"{fm.id}#000",
                knowledge_id=fm.id,
                title=fm.title,
                source_ref=fm.source_ref,
                classification=fm.classification,
                category=fm.category,
                version=fm.version,
                section="",
                text=fm.title,
                hash=_chunk_hash(fm.title),
            )
        )
    return chunks


class IndexBuildError(Exception):
    """The knowledge root failed validation; refusing to build/write an index."""


def build_index(knowledge_root: Path | str, db_path: Path | str) -> IndexBuildReport:
    knowledge_root = Path(knowledge_root)
    # Codex cross-review finding #5 (round 2, 2026-09-11): reindex_atomic()
    # checks validate_tree() for a missing root before ever calling
    # build_index() - but build_index() itself never checked, so any DIRECT
    # caller (scripts/build_index.py, a library user) bypassed the gate
    # entirely. build_index("README.md", db) - a file, not a directory -
    # used to succeed with zero units/chunks and no reported skips, silently
    # overwriting db_path with an empty index.
    #
    # This checks ONLY "is knowledge_root a directory", not "zero ERROR-level
    # issues anywhere in the tree": load_corpus() is deliberately
    # skip-and-continue for per-file problems (a secret-classified file, one
    # invalid unit) so the REST of a real corpus still indexes - that broader,
    # stricter "must be provably clean" bar belongs to reindex_atomic(), which
    # already enforces it before it ever calls this function.
    if not knowledge_root.is_dir():
        raise IndexBuildError(
            f"knowledge root does not exist or is not a directory: {knowledge_root}"
        )
    load = load_corpus(knowledge_root)
    revision = compute_knowledge_revision(load.units)

    chunks: list[Chunk] = []
    for unit in load.units:
        chunks.extend(chunks_for_unit(unit))

    conn = connect(db_path)
    try:
        repo = ChunkRepository(conn)
        chunk_count = repo.rebuild(chunks, revision)
        classifications = sorted(repo.classifications_in_index())
        knowledge_ids = sorted(repo.knowledge_ids())
    finally:
        conn.close()

    if "secret" in classifications:  # pragma: no cover - guarded upstream
        raise AssertionError("secret classification reached the index")

    return IndexBuildReport(
        knowledge_root=str(knowledge_root),
        db_path=str(db_path),
        units_indexed=len(load.units),
        chunks_indexed=chunk_count,
        knowledge_revision=revision,
        classifications=classifications,
        knowledge_ids=knowledge_ids,
        skipped=load.skipped,
        warnings=load.warning_count,
    )


class ReindexReport(BaseModel):
    decision: PolicyDecision
    old_revision: str | None = None
    new_revision: str | None = None
    chunks_indexed: int = 0
    units_indexed: int = 0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ok(self) -> bool:
        return self.decision.is_allowed


def _current_revision(db_path: Path) -> str | None:
    if not db_path.exists():
        return None
    conn = connect(db_path, read_only=True)
    try:
        return ChunkRepository(conn).knowledge_revision()
    finally:
        conn.close()


def reindex_atomic(knowledge_root: Path | str, db_path: Path | str) -> ReindexReport:
    """Rebuild the index from an already-verified, read-only knowledge root.

    This never changes knowledge *content* - it only re-derives the FTS index.
    classification + integrity are verified before the swap; on any failure the
    existing index is left untouched (no partial update). Serialized across
    concurrent callers (same or different process) via an flock on a sibling
    ``.lock`` file, and the previous index is restored if the post-swap
    integrity check fails (Codex cross-review finding #3 / Antigravity B6.2,
    2026-09-11).
    """
    knowledge_root = Path(knowledge_root)
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = db_path.with_suffix(db_path.suffix + ".lock")

    with open(lock_path, "a", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            return _reindex_atomic_locked(knowledge_root, db_path)
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def _cleanup(*paths: Path) -> None:
    for p in paths:
        with contextlib.suppress(OSError):  # best-effort - never let cleanup itself raise
            p.unlink(missing_ok=True)


def _restore_or_remove(db_path: Path, backup: Path, had_existing: bool) -> None:
    """Never leave an unverified/failed publish live at ``db_path``."""
    if had_existing:
        with contextlib.suppress(OSError):
            os.replace(backup, db_path)  # restore the last known-good index
    else:
        _cleanup(db_path)  # there was nothing before this reindex; go back to that


def _reindex_atomic_locked(knowledge_root: Path, db_path: Path) -> ReindexReport:
    old_revision = _current_revision(db_path)

    # 1. knowledge must validate clean (no ERROR-level issues)
    issues = validate_tree(knowledge_root)
    errors = [i for i in issues if i.level is Level.ERROR]
    if errors:
        return ReindexReport(
            decision=stop(
                PolicyOutcome.POLICY_BLOCKED,
                "reindex",
                f"{len(errors)} knowledge validation error(s); index unchanged",
            ),
            old_revision=old_revision,
        )

    # 2. build into a per-call, uniquely-named staging database. A unique name
    # (not the old fixed "<db>.staging") means no exists()-then-unlink() race
    # with another caller and no risk of deleting an unrelated file at a
    # predictable path; the flock above still serializes callers, but this
    # holds even without it.
    unique = f"{os.getpid()}-{uuid4().hex[:8]}"
    staging = db_path.with_suffix(db_path.suffix + f".staging.{unique}")
    backup = db_path.with_suffix(db_path.suffix + f".bak.{unique}")

    try:
        build = build_index(knowledge_root, staging)

        # Codex cross-review finding #4 (round 3, 2026-09-12): step 1 above
        # validates the tree, but build_index() -> load_corpus() re-walks and
        # re-validates the same knowledge_root independently (its own
        # validate_tree() call). If a unit is changed/removed between those
        # two reads (TOCTOU) or otherwise fails to load, load_corpus() skips
        # it and carries on - correct for load_corpus() itself, which must
        # tolerate per-file problems - but reindex_atomic() used to ignore
        # build.skipped entirely and still publish. A build that silently
        # dropped content (down to zero units, in the fault-injected repro)
        # was indistinguishable from a clean one and passed as ALLOWED.
        # Reindex is stricter than a routine load: refuse to publish an index
        # built from a corpus read that did not match step 1's validation.
        if build.skipped:
            raise _ReindexAbort(
                f"{len(build.skipped)} knowledge unit(s) skipped while building the "
                "staging index (validated tree changed since step 1); refusing to publish"
            )

        # 3. classification + integrity verification on the staging index
        if "secret" in build.classifications:
            raise _ReindexAbort("secret classification reached the staging index")
        conn = connect(staging, read_only=True)
        try:
            integrity = verify_chunk_hashes(conn)
        finally:
            conn.close()
        if not integrity.is_allowed:
            raise _ReindexAbort(f"staging integrity check failed: {integrity.reasons}")
    except (_ReindexAbort, IndexBuildError, OSError, sqlite3.Error) as abort:
        # any failure before the swap - including an unexpected OSError while
        # building, not just our own _ReindexAbort - leaves db_path untouched.
        _cleanup(staging)
        return ReindexReport(
            decision=stop(PolicyOutcome.POLICY_BLOCKED, "reindex", str(abort)),
            old_revision=old_revision,
        )

    # 4. publish. ADV-08 / Codex#2 (round 2, 2026-09-11): the previous version
    # moved db_path OUT of the way first (os.replace(db_path, backup)), then
    # moved staging in - a real window where db_path does not exist at all, so
    # a concurrent reader (assess() calls take no lock; only reindex_atomic
    # callers serialize against each other) could see a missing index and
    # silently skip retrieval. It also was not exception-safe: an OSError
    # between those two calls, or on the swap itself, could leave db_path
    # permanently missing with the old content stranded in `backup`.
    #
    # Fixed: COPY (not move) the existing index to `backup` - db_path is never
    # touched until the swap - then publish with a single os.replace(), which
    # is atomic and always leaves *something* valid at db_path. The whole
    # publish step is wrapped so any failure restores/cleans up rather than
    # leaving a stranded backup or a missing index.
    had_existing = db_path.exists()
    published = False
    try:
        if had_existing:
            shutil.copy2(db_path, backup)
        os.replace(staging, db_path)  # atomic; db_path is never absent
        published = True

        conn = connect(db_path, read_only=True)
        try:
            post = verify_chunk_hashes(conn)
        finally:
            conn.close()
    except (OSError, sqlite3.Error) as exc:
        # Codex cross-review finding #1 (round 3, 2026-09-12): this used to be
        # `except OSError` and unconditionally `_cleanup(staging, backup)`
        # regardless of whether os.replace() had already published the new
        # index. Once `published` is True, `staging` no longer exists (it was
        # moved to db_path) and db_path itself now holds the UNVERIFIED new
        # content - deleting `backup` here threw away the only copy of the
        # last known-good index while leaving the unverified one live. It also
        # only caught OSError: verify_chunk_hashes() can raise sqlite3.Error
        # subclasses that are not OSError (e.g. a locked/corrupt file opening
        # cleanly but failing on the first query), which escaped uncaught and
        # skipped this restore path entirely.
        if published:
            _restore_or_remove(db_path, backup, had_existing)
            _cleanup(staging)
        else:
            _cleanup(staging, backup)
        return ReindexReport(
            decision=stop(
                PolicyOutcome.POLICY_BLOCKED, "reindex", f"publication failed: {exc}"
            ),
            old_revision=old_revision,
            new_revision=build.knowledge_revision,
        )

    if not post.is_allowed:
        _restore_or_remove(db_path, backup, had_existing)
        return ReindexReport(
            decision=stop(
                PolicyOutcome.POLICY_BLOCKED,
                "reindex",
                f"post-swap integrity check failed: {post.reasons}; previous index restored",
            ),
            old_revision=old_revision,
            new_revision=build.knowledge_revision,
        )

    _cleanup(backup)
    return ReindexReport(
        decision=allow("reindex"),
        old_revision=old_revision,
        new_revision=build.knowledge_revision,
        chunks_indexed=build.chunks_indexed,
        units_indexed=build.units_indexed,
    )


class _ReindexAbort(Exception):
    pass
