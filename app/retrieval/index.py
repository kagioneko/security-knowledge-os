"""Build the knowledge index from a configurable knowledge root (spec Section 10).

The knowledge root is a parameter, not a constant: today it points at ``knowledge/``,
later it can point at ``active/knowledge/`` populated by the Pack Manager.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import shutil
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, computed_field

from app.ingestion.loader import LoadedUnit, compute_knowledge_revision, load_corpus
from app.ingestion.snapshot import snapshot_tree
from app.ingestion.validator import Level, iter_knowledge_files, validate_tree
from app.models.knowledge import KnowledgeUnitFrontMatter
from app.models.policy_outcome import PolicyDecision, PolicyOutcome, allow, stop
from app.models.retrieval import Chunk, chunk_content_hash
from app.storage.db import ForeignDatabaseError, connect, open_no_follow, verify_application_id
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


def _chunk(
    *,
    chunk_id: str,
    fm: KnowledgeUnitFrontMatter,
    section: str,
    text: str,
) -> Chunk:
    return Chunk(
        chunk_id=chunk_id,
        knowledge_id=fm.id,
        title=fm.title,
        source_ref=fm.source_ref,
        classification=fm.classification,
        category=fm.category,
        version=fm.version,
        section=section,
        text=text,
        hash=chunk_content_hash(
            chunk_id=chunk_id,
            knowledge_id=fm.id,
            title=fm.title,
            source_ref=fm.source_ref,
            classification=fm.classification.value,
            category=fm.category.value,
            version=fm.version,
            section=section,
            text=text,
        ),
    )


def chunks_for_unit(unit: LoadedUnit) -> list[Chunk]:
    fm = unit.front_matter
    sections = unit.sections or []
    chunks: list[Chunk] = [
        _chunk(chunk_id=f"{fm.id}#{ordinal:03d}", fm=fm, section=section.heading, text=section.text)
        for ordinal, section in enumerate(sections)
    ]
    if not chunks:
        chunks.append(_chunk(chunk_id=f"{fm.id}#000", fm=fm, section="", text=fm.title))
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
        # Codex#4 (round 6, 2026-09-12), reproduced exactly as reported: an
        # unrelated SQLite file that merely happens to have a
        # compatible-looking meta(key,value) table (created by something
        # else entirely) has no 'knowledge_revision' row, so this used to
        # return None - "no existing index" - and reindex_atomic() would go
        # on to atomically replace that unrelated file's content entirely.
        # verify_application_id() catches this before that decision is made.
        verify_application_id(conn, db_path)
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
    lock_path = db_path.with_suffix(db_path.suffix + ".lock")

    # Codex#9 (round 6, 2026-09-12), reproduced exactly as reported:
    # parent-directory creation, lock-file opening, and the initial
    # flock() all ran outside any try/except -
    # `reindex_atomic("knowledge", "/proc/1/skos-audit.sqlite")` raised a
    # raw FileNotFoundError instead of the POLICY_BLOCKED ReindexReport
    # every other failure path in this module returns. The existing
    # index, if any, is never touched either way (this call never gets
    # far enough to read or write one) - a contract/operability gap, not
    # a fail-open one, but every caller of this function is entitled to
    # get a ReindexReport back, not an arbitrary exception type.
    try:
        # Codex#4 (round 8, 2026-09-12), reproduced exactly as reported:
        # this chmod ran unconditionally, even when the parent directory
        # already existed and was not ours to re-permission (e.g. a
        # relative db_path like "index.sqlite" made `db_path.parent`
        # resolve to the current working directory, which always
        # "exists" - reindexing chmod'd the caller's cwd to 0700). Only
        # chmod a directory this call actually created.
        parent_already_existed = db_path.parent.exists()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        if not parent_already_existed:
            with contextlib.suppress(OSError):
                os.chmod(db_path.parent, 0o700)
        # Codex#4 (round 8, 2026-09-12), reproduced exactly as reported:
        # plain `open(lock_path, "a")` + `os.chmod(lock_path, ...)` both
        # follow a symlink at `lock_path` - precreating it as a symlink to
        # an unrelated file caused the chmod to silently re-permission
        # that unrelated TARGET. `open_no_follow` (app.storage.db) opens
        # with O_NOFOLLOW, so a symlink here raises OSError (ELOOP)
        # instead, and fchmod on the resulting fd can never be redirected.
        lock_fd = open_no_follow(lock_path, 0o600)
        with contextlib.suppress(OSError):
            os.fchmod(lock_fd, 0o600)
        lock_file = os.fdopen(lock_fd, "a", encoding="utf-8")
    except OSError as exc:
        return ReindexReport(
            decision=stop(
                PolicyOutcome.POLICY_BLOCKED, "reindex", f"could not prepare the lock file: {exc}"
            )
        )

    with lock_file:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
        except OSError as exc:
            return ReindexReport(
                decision=stop(
                    PolicyOutcome.POLICY_BLOCKED,
                    "reindex",
                    f"could not acquire the reindex lock: {exc}",
                )
            )
        try:
            return _reindex_atomic_locked(knowledge_root, db_path)
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def _cleanup(*paths: Path) -> None:
    for p in paths:
        with contextlib.suppress(OSError):  # best-effort - never let cleanup itself raise
            p.unlink(missing_ok=True)


def _restore_or_remove(db_path: Path, backup: Path, had_existing: bool) -> bool:
    """Try to put the last known-good index back at ``db_path``.

    Returns True if ``db_path`` is now known to be back in its pre-reindex
    state (restored from ``backup``, or correctly absent if there was none).
    Returns False if the restore itself failed.

    Codex#3 / Antigravity SKOS-ADV-12 (round 4, 2026-09-12): the previous
    version did `with contextlib.suppress(OSError): os.replace(backup,
    db_path)` and unconditionally returned/reported "previous index
    restored" regardless of whether that replace actually succeeded - a
    second, unrelated failure right after the first (e.g. the backup itself
    became unreadable) left the known-bad/unverified content live at
    db_path while the caller told the operator recovery had happened.
    Restoration failure must never be silently swallowed: if it happens,
    fail closed by removing the bad content from service entirely (no index
    is safer than a known-bad one) and leave `backup` on disk for manual
    recovery, and tell the caller so it can report the truth.
    """
    if not had_existing:
        _cleanup(db_path)
        return not db_path.exists()
    try:
        os.replace(backup, db_path)
        return True
    except OSError:
        with contextlib.suppress(OSError):
            db_path.unlink(missing_ok=True)
        return False


def _restore_note(restored: bool, had_existing: bool, backup: Path, db_path: Path) -> str:
    """A truthful, human-readable suffix for the POLICY_BLOCKED reason - never
    claims "restored" unless the restore actually succeeded, and never
    claims the bad index was "removed from service" unless it actually is
    gone.

    Codex#4 sub-point 3 (round 5, 2026-09-12): `_restore_or_remove` can
    itself fail to remove `db_path` (its own `unlink()` suppressed an
    OSError) - this used to unconditionally say "removed from service" in
    that case even though `db_path` could still hold the unverified/bad
    content. Checking `db_path.exists()` here (called immediately after
    `_restore_or_remove` returns, so the state is still current) reports
    which one actually happened.
    """
    if restored:
        return "; previous index restored" if had_existing else "; no previous index existed"
    if db_path.exists():
        return (
            "; RESTORE ALSO FAILED - db_path STILL CONTAINS the unverified/bad "
            f"index (removal also failed); manual recovery required from backup "
            f"at {backup}"
        )
    return (
        "; RESTORE ALSO FAILED - unverified/bad index removed from service; "
        f"manual recovery required from backup at {backup}"
    )


def _reindex_atomic_locked(knowledge_root: Path, db_path: Path) -> ReindexReport:
    # Codex#1 / #2 (round 7, 2026-09-12), reproduced exactly as reported:
    # a file changed transiently during the build and restored right after
    # still passed integrity (its hash describes whatever got read, not
    # what was there just before/after); separately, O_NOFOLLOW (round 6,
    # Codex#5) protects only the FINAL pathname component of a read - an
    # ANCESTOR directory swapped to an outside-the-root symlink between
    # check_containment() and the actual read was never checked. Both close
    # the same way: read the entire tree exactly once, through a
    # directory-fd walk that never re-resolves a pathname from scratch,
    # into a private temp directory only this process knows about - see
    # app/ingestion/snapshot.py. Every step below (validation, chunking,
    # hashing) then operates on that private, immutable snapshot; there is
    # no live, externally-mutable tree left to race against by the time
    # any of it runs.
    try:
        snapshot_root = snapshot_tree(knowledge_root)
    except OSError as exc:
        return ReindexReport(
            decision=stop(
                PolicyOutcome.POLICY_BLOCKED,
                "reindex",
                f"could not safely snapshot the knowledge root: {exc}",
            )
        )
    try:
        return _reindex_atomic_locked_on_snapshot(snapshot_root, db_path)
    finally:
        shutil.rmtree(snapshot_root, ignore_errors=True)


def _reindex_atomic_locked_on_snapshot(knowledge_root: Path, db_path: Path) -> ReindexReport:
    # Codex#4 sub-point 1 (round 5, 2026-09-12): reading the OLD index's
    # revision and the initial validation walk used to run outside any
    # try/except in this function - a corrupt EXISTING index (e.g. missing
    # `meta`) made _current_revision() raise sqlite3.OperationalError
    # straight out of reindex_atomic() instead of the POLICY_BLOCKED
    # ReindexReport every other failure path in this function returns.
    try:
        old_revision = _current_revision(db_path)
        expected_file_count = len(iter_knowledge_files(knowledge_root))
        issues = validate_tree(knowledge_root)
    except (OSError, sqlite3.Error, ForeignDatabaseError, ValueError) as exc:
        # Codex#5 (round 7, 2026-09-12): validate_tree() above reads every
        # file's content too (validate_file() -> read_markdown()) - a
        # malformed-content failure there (invalid UTF-8, deeply-nested
        # YAML) is a ValueError/RecursionError-derived exception, same
        # class this function's LATER except clause (build step) already
        # broadened for in round 5; this earlier one had not been.
        return ReindexReport(
            decision=stop(
                PolicyOutcome.POLICY_BLOCKED,
                "reindex",
                f"could not read the existing index or validate the knowledge "
                f"root: {exc}",
            )
        )

    # 1. knowledge must validate clean (no ERROR-level issues)
    # Codex#2 / Antigravity SKOS-ADV-11 (round 4, 2026-09-12): the file count
    # seen here is recorded so it can be cross-checked against what
    # build_index() -> load_corpus() sees below - see that check for why.
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

    # Codex#3 (round 6, 2026-09-12), reproduced exactly as reported: a
    # valid but EMPTY knowledge root has zero validation errors, so this
    # function happily replaced a populated index with an empty one - and
    # the API's /v1/knowledge/reindex calls this function directly, with no
    # guard of its own. This was previously fixed only at the
    # scripts/build_index.py CLI layer (Codex#7, round 5); fixing it here
    # closes it for every caller, library and API alike, in one place.
    if expected_file_count == 0:
        return ReindexReport(
            decision=stop(
                PolicyOutcome.POLICY_BLOCKED,
                "reindex",
                f"refusing to publish a zero-unit index: no knowledge files found "
                f"under {knowledge_root}",
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

        # Codex#2 / Antigravity SKOS-ADV-11 (round 4, 2026-09-12): a file
        # that simply DISAPPEARS between step 1's enumeration and this
        # build's own re-enumeration is invisible to the build.skipped check
        # right below - load_corpus() only records a skip for a file it
        # FOUND and then rejected; a vanished file (removed, an unmounted
        # subtree, an interrupted corpus sync) is never seen at all, so
        # units_indexed can silently drop to zero with build.skipped == [].
        # A fault-injected repro reproduced exactly that: step 1 saw a full
        # corpus (0 errors), the build saw none of it, and the resulting
        # empty index passed every check below as ALLOWED. Comparing the
        # file COUNT the two independent walks actually saw closes this -
        # any mismatch (fewer OR more files) means the tree changed under
        # us, and reindex must refuse to publish from an inconsistent read.
        actual_file_count = build.units_indexed + len(build.skipped)
        if actual_file_count != expected_file_count:
            raise _ReindexAbort(
                f"knowledge root changed during reindex: step 1 saw "
                f"{expected_file_count} file(s), the build saw {actual_file_count}; "
                "refusing to publish from an inconsistent read"
            )

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
    except (_ReindexAbort, IndexBuildError, OSError, sqlite3.Error, ValueError) as abort:
        # any failure before the swap - including an unexpected OSError while
        # building, not just our own _ReindexAbort - leaves db_path untouched.
        # Codex#4 sub-point 2 (round 5, 2026-09-12): ValueError is included as
        # defense-in-depth for any ingestion-content failure (pydantic
        # ValidationError subclasses ValueError; so does FrontMatterError)
        # that reaches this far - load_corpus() itself now converts per-file
        # parse/schema failures into a `skipped` entry rather than raising
        # (see Codex#3 above), which the `build.skipped` check already turns
        # into a `_ReindexAbort`, but this remains a defensive backstop.
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
            restored = _restore_or_remove(db_path, backup, had_existing)
            _cleanup(staging)
            reason = f"publication failed: {exc}" + _restore_note(
                restored, had_existing, backup, db_path
            )
        else:
            _cleanup(staging, backup)
            reason = f"publication failed: {exc}"
        return ReindexReport(
            decision=stop(PolicyOutcome.POLICY_BLOCKED, "reindex", reason),
            old_revision=old_revision,
            new_revision=build.knowledge_revision,
        )

    if not post.is_allowed:
        restored = _restore_or_remove(db_path, backup, had_existing)
        reason = (
            f"post-swap integrity check failed: {post.reasons}"
            + _restore_note(restored, had_existing, backup, db_path)
        )
        return ReindexReport(
            decision=stop(PolicyOutcome.POLICY_BLOCKED, "reindex", reason),
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
