"""Build the knowledge index from a configurable knowledge root (spec Section 10).

The knowledge root is a parameter, not a constant: today it points at ``knowledge/``,
later it can point at ``active/knowledge/`` populated by the Pack Manager.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import os
import re
import shutil
import sqlite3
import stat
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
from app.storage.db import (
    ForeignDatabaseError,
    FTS5Unavailable,
    UntrustedStateDirectoryError,
    connect,
    describe_db_error,
    ensure_dir_no_follow,
    existing_ancestors_untrusted_reason,
    open_no_follow,
    untrusted_state_dir_reason,
    verify_application_id,
)
from app.storage.integrity import verify_chunk_hashes
from app.storage.repository import ChunkRepository

# Matches app/storage/integrity.py's own _HEX_DIGEST_RE: knowledge_revision is
# always a hashlib.sha256(...).hexdigest() (see round-30 fix below).
_HEX_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


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
        revision = ChunkRepository(conn).knowledge_revision()
        # Codex#4 / Antigravity SKOS-ADV-32 (round 21, 2026-09-15),
        # reproduced exactly as reported: `meta.value` is a TEXT-affinity
        # column, but SQLite's type affinity only converts values it CAN
        # convert - a BLOB literal (`UPDATE meta SET value=X'FF' WHERE
        # key='knowledge_revision'`, corruption or a local attacker with
        # write access to the index file) is stored and read back as raw
        # `bytes`, even though `knowledge_revision()`'s return type says
        # `str | None`. That bytes value used to flow all the way through
        # `_current_revision()` into `old_revision` untouched, past every
        # try/except in this function, and only blew up much later as a
        # raw, uncaught Pydantic `ValidationError` when constructing the
        # final `ReindexReport(old_revision=old_revision, ...)` -
        # potentially AFTER a successful publish and backup cleanup, so
        # the crash misrepresented a successful reindex as a failure to
        # any caller. Rejecting a non-str revision HERE, as a ValueError -
        # already caught by this function's own caller just below,
        # converting it to a clean POLICY_BLOCKED report before any build
        # or swap ever begins - fails closed at the earliest possible
        # point instead of leaving a poisoned value to detonate later.
        if revision is not None and not isinstance(revision, str):
            raise ValueError(
                f"{db_path}: stored knowledge_revision is not text (got "
                f"{type(revision).__name__}); refusing to trust this index"
            )
        # Codex round-30 (2026-09-25), reproduced exactly as reported: this
        # only checked the type, not the shape - `knowledge_revision` is
        # always a `hashlib.sha256(...).hexdigest()` (see
        # app/storage/integrity.py's own _HEX_DIGEST_RE check for the same
        # column), but a hand-forged or corrupted value that merely happens
        # to be a str (e.g. an embedded marker string) passed through
        # untouched into `ReindexReport.old_revision`, which the API returns
        # verbatim in its HTTP 422 body and logs on failure. Reject anything
        # that is not a 64-hex-digit digest here, at the same point the
        # non-str case above is already rejected.
        if revision is not None and not _HEX_DIGEST_RE.match(revision):
            raise ValueError(
                f"{db_path}: stored knowledge_revision is not a valid sha256 hex "
                "digest; refusing to trust this index"
            )
        return revision
    finally:
        conn.close()


def reindex_atomic(
    knowledge_root: Path | str, db_path: Path | str, *, blocking: bool = True
) -> ReindexReport:
    """Rebuild the index from an already-verified, read-only knowledge root.

    This never changes knowledge *content* - it only re-derives the FTS index.
    classification + integrity are verified before the swap; on any failure the
    existing index is left untouched (no partial update). Serialized across
    concurrent callers (same or different process) via an flock on a sibling
    ``.lock`` file, and the previous index is restored if the post-swap
    integrity check fails (Codex cross-review finding #3 / Antigravity B6.2,
    2026-09-11).

    Codex#2 (round 13, 2026-09-13), reproduced exactly as reported:
    app/main.py's ``_REINDEX_LOCK`` (a ``threading.Lock``) only serializes
    callers within ONE process - with multiple Uvicorn API workers, two
    concurrent requests reaching DIFFERENT worker processes each pass
    that check, and the flock below (which DOES correctly serialize
    across processes) used to always BLOCK, so the second process's
    request occupied a worker thread waiting instead of getting an
    immediate 429, and then still performed a full, redundant rebuild
    once admitted. ``blocking=False`` (the API endpoint's choice; the CLI
    and scripts keep the default ``True``, matching prior behaviour)
    makes the flock attempt non-blocking instead: contention returns a
    ``POLICY_BLOCKED`` report with `subject="reindex-busy"` (a DIFFERENT,
    checkable subject from every other failure's plain "reindex", not a
    string the caller has to pattern-match a message against) rather than
    waiting.
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
        #
        # Codex#2 (round 15, 2026-09-14), reproduced exactly as reported:
        # "only chmod if we created it" was itself still check-then-act -
        # `.exists()` (check) then `.mkdir(exist_ok=True)` (act) leaves a
        # window where an attacker able to write into the parent's own
        # parent can plant a symlink to an unrelated, differently-owned
        # directory in between; `Path.mkdir(exist_ok=True)` silently
        # accepts a pre-existing symlink-to-a-directory (only `is_dir()`
        # is checked, which follows symlinks), so the "not already
        # existed" branch still ran and `os.chmod()` - which follows
        # symlinks by default - re-permissioned the attacker's directory
        # instead. Fixed identically to `app.storage.db.connect()`'s own
        # version of this same bug (Codex#2, round 15): atomic `os.mkdir`
        # (EEXIST for a symlink too - no exist_ok to swallow that) and
        # chmod only ever through an fd opened O_DIRECTORY|O_NOFOLLOW.
        #
        # Codex#3 / Antigravity SKOS-ADV-18 (round 17, 2026-09-14),
        # reproduced exactly as reported: `.parent.mkdir(parents=True,
        # exist_ok=True)` resolves and creates through an EXISTING
        # symlink exactly like a normal `mkdir -p` would - an attacker-
        # owned symlink ancestor got a directory CREATED through it
        # before the trust check below ever ran and refused to WRITE
        # there. Validating whatever currently EXISTS along the ancestor
        # chain first - before creating anything - catches a pre-planted
        # symlink here, before mkdir ever touches it.
        untrusted = existing_ancestors_untrusted_reason(db_path.parent)
        if untrusted is not None:
            return ReindexReport(
                decision=stop(PolicyOutcome.POLICY_BLOCKED, "reindex", untrusted)
            )
        # Codex#3 (round 23) / Codex#1 (round 24): the whole `mkdir -p`, the
        # last component and the fchmod happen inside one descriptor-relative
        # walk - no pathname is re-resolved after the trust check above.
        try:
            ensure_dir_no_follow(db_path.parent)
        except UntrustedStateDirectoryError as exc:
            return ReindexReport(decision=stop(PolicyOutcome.POLICY_BLOCKED, "reindex", str(exc)))
        # Codex#3 (round 11, 2026-09-13): finding #1/#2 (round 10) each
        # narrowed a symlink-substitution TOCTOU window in this function to
        # a single stat-then-use gap, but a residual window is provably
        # unavoidable through more syscalls alone - POSIX has no
        # rename-from-fd or replace-from-fd primitive, so the pathname must
        # always be re-resolved at the moment of use. The actual guarantee
        # against every attack in this class is that an untrusted writer
        # cannot write into this directory in the first place; verifying
        # that (not owned by this process, or group/world-writable) closes
        # the THREAT rather than continuing to chase an unwinnable race.
        # Shared with connect()'s own write-path check (Codex#6, round 11)
        # via app.storage.db.untrusted_state_dir_reason() - one definition.
        untrusted = untrusted_state_dir_reason(db_path.parent)
        if untrusted is not None:
            return ReindexReport(
                decision=stop(PolicyOutcome.POLICY_BLOCKED, "reindex", untrusted)
            )
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
        flags = fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB
        try:
            fcntl.flock(lock_file, flags)
        except OSError as exc:
            if not blocking and exc.errno in (errno.EACCES, errno.EAGAIN):
                return ReindexReport(
                    decision=stop(
                        PolicyOutcome.POLICY_BLOCKED,
                        "reindex-busy",
                        "a reindex is already running; retry shortly",
                    )
                )
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


def _copy_no_follow_exclusive(src: Path, dst: Path) -> None:
    """Copy `src`'s content into a brand-new `dst`, refusing to write
    through anything already present at `dst` - a pre-existing file OR a
    symlink.

    Codex#1 (round 10, 2026-09-13), reproduced exactly as reported:
    `shutil.copy2(db_path, backup)` opens `backup` the normal way - a
    writer able to precreate `backup` (its filename is derived from the
    same `unique` suffix as the `staging` path, which sits on disk under
    that name for the whole build and is therefore observable) as a
    symlink caused `copy2()` to silently overwrite the symlink's TARGET
    with the live database's content instead of writing to `backup`
    itself. `O_EXCL` refuses to create a new file at a path that already
    has anything at it (symlink or regular file); `O_NOFOLLOW` is
    additional defense-in-depth for the same refusal. This only copies
    the DATA (a disaster-recovery backup, not a byte-identical clone -
    unlike `shutil.copy2()`, file metadata such as mtime/permissions is
    not preserved, which does not matter for this purpose).
    """
    src_fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        dst_fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with (
                os.fdopen(src_fd, "rb", closefd=False) as src_file,
                os.fdopen(dst_fd, "wb", closefd=False) as dst_file,
            ):
                shutil.copyfileobj(src_file, dst_file)
        finally:
            os.close(dst_fd)
    finally:
        os.close(src_fd)


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
    except (OSError, sqlite3.Error, ForeignDatabaseError, FTS5Unavailable, ValueError) as exc:
        # Codex#3 (round 15, 2026-09-14), reproduced exactly as reported:
        # FTS5Unavailable (raised by connect() -> _current_revision() when
        # the SQLite build lacks the FTS5 extension) is a RuntimeError
        # subclass, not one of the types this tuple caught - a supported
        # environmental failure escaped as a raw exception instead of the
        # typed POLICY_BLOCKED ReindexReport every other failure path here
        # returns. The existing index is never touched either way (this
        # never gets far enough to write one); this is a contract gap, not
        # a fail-open one.
        #
        # Codex#5 (round 7, 2026-09-12): validate_tree() above reads every
        # file's content too - a malformed-content failure there (invalid
        # UTF-8, deeply-nested
        # YAML) is a ValueError/RecursionError-derived exception, same
        # class this function's LATER except clause (build step) already
        # broadened for in round 5; this earlier one had not been.
        return ReindexReport(
            decision=stop(
                PolicyOutcome.POLICY_BLOCKED,
                "reindex",
                f"could not read the existing index or validate the knowledge "
                f"root: {describe_db_error(exc)}",
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

        # Codex#2 (round 10, 2026-09-13), reproduced exactly as reported:
        # `staging` was verified by PATHNAME above, the connection then
        # closed - the publish step below can take real time (copying the
        # EXISTING db_path to `backup`, proportional to its size), during
        # which a writer able to write in this directory could replace
        # `staging` with a symlink to a separately-built, internally
        # self-consistent "valid" database. `os.replace()` does not follow
        # symlinks - it moves the SYMLINK ENTRY itself into db_path's
        # place, so db_path becomes a symlink into attacker-controlled
        # content, and every later read of db_path (including the
        # post-swap integrity check right after the swap) transparently
        # follows it and verifies the attacker's own database instead.
        # Capturing staging's identity now, right after it was verified,
        # and re-checking it immediately before the swap (see below)
        # narrows this window to the stat-then-replace gap; it cannot
        # eliminate the race entirely (no fd-based replace API exists),
        # matching this project's existing inode-identity-check posture
        # elsewhere (app/storage/db.py's connect()).
        verified_staging_stat = os.stat(staging, follow_symlinks=False)
        verified_staging_identity = (verified_staging_stat.st_dev, verified_staging_stat.st_ino)
    except (
        _ReindexAbort,
        IndexBuildError,
        OSError,
        sqlite3.Error,
        ValueError,
        UntrustedStateDirectoryError,
        FTS5Unavailable,
    ) as abort:
        # Codex#3 (round 15, 2026-09-14): see the identical FTS5Unavailable
        # gap fixed above for _current_revision() - this build-step try
        # block also opens SQLite connections (connect(staging, ...) for
        # the integrity check) that can raise it, and this is likewise a
        # pre-swap failure path (db_path is never touched here either way).
        #
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
            # Codex round-34 (2026-09-26): str(abort) put a real
            # sqlite3.Error's text - which quotes content from the corrupt
            # file - into the reason the reindex endpoint logs.
            decision=stop(PolicyOutcome.POLICY_BLOCKED, "reindex", describe_db_error(abort)),
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
            _copy_no_follow_exclusive(db_path, backup)
        # Codex#2 (round 10, 2026-09-13): re-verify staging's identity
        # immediately before the swap - see the comment where
        # `verified_staging_identity` was captured above for why. A
        # symlink at `staging` reports its OWN (dev, ino) here (`lstat`
        # never follows), which can never equal the original regular
        # file's identity, so a swap either way is caught.
        current_staging_stat = os.stat(staging, follow_symlinks=False)
        if (
            current_staging_stat.st_dev,
            current_staging_stat.st_ino,
        ) != verified_staging_identity or not stat.S_ISREG(current_staging_stat.st_mode):
            raise _StagingSubstituted(
                f"{staging}: changed after verification and before publish; refusing to publish"
            )
        os.replace(staging, db_path)  # atomic; db_path is never absent
        published = True

        conn = connect(db_path, read_only=True)
        try:
            post = verify_chunk_hashes(conn)
            # Codex#1 (round 19, 2026-09-14), reproduced exactly as
            # reported: `verify_chunk_hashes` proves internal consistency
            # (every chunk's hash matches its own content), not that the
            # content is the one we just published - a stale-but-valid
            # revision surviving underneath (see connect()'s own comment
            # on the WAL sidecar gap this closes) passes this check
            # outright, because it IS a real, internally-consistent
            # index, just not THIS one. Requiring the visible revision to
            # equal what build_index() just reported catches that
            # mismatch directly, independent of the exact mechanism that
            # produced it - defense in depth alongside the WAL fix, not a
            # replacement for it.
            visible_revision = ChunkRepository(conn).knowledge_revision()
        finally:
            conn.close()
        if visible_revision != build.knowledge_revision:
            raise _RevisionMismatch(
                f"published revision {build.knowledge_revision!r} but a fresh "
                f"read of {db_path} shows {visible_revision!r} instead"
            )
    except (OSError, sqlite3.Error, RuntimeError) as exc:
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
        #
        # Codex#3 (round 13, 2026-09-13), reproduced exactly as reported:
        # `connect(db_path, read_only=True)` right above can itself raise
        # `ForeignDatabaseError`/`UntrustedStateDirectoryError`/
        # `FTS5Unavailable` - all `RuntimeError` subclasses, none of them
        # `OSError` or `sqlite3.Error` - which escaped this except clause
        # entirely: the newly-swapped, UNVERIFIED index stayed live and the
        # last-known-good backup stayed stranded, contradicting the "old
        # index kept on any post-swap failure" guarantee this whole
        # restore path exists to provide.
        if published:
            restored = _restore_or_remove(db_path, backup, had_existing)
            _cleanup(staging)
            reason = f"publication failed: {describe_db_error(exc)}" + _restore_note(
                restored, had_existing, backup, db_path
            )
        else:
            _cleanup(staging, backup)
            reason = f"publication failed: {describe_db_error(exc)}"
        return ReindexReport(
            decision=stop(PolicyOutcome.POLICY_BLOCKED, "reindex", reason),
            old_revision=old_revision,
            new_revision=build.knowledge_revision,
        )
    except BaseException:
        # Codex#3 (round 13, 2026-09-13): a genuinely UNEXPECTED exception
        # (anything not already anticipated above) must still trigger
        # restoration before propagating - silently converting it into a
        # POLICY_BLOCKED report the way the clause above does would
        # misrepresent an actual bug as an expected operational failure
        # (the same "do not misrepresent unexpected exceptions" principle
        # app/reviewer/report.py's build_report() already applies to
        # PolicyStop). Restore, then re-raise unchanged.
        if published:
            _restore_or_remove(db_path, backup, had_existing)
            _cleanup(staging)
        else:
            _cleanup(staging, backup)
        raise

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

    # Codex#1 (round 19, 2026-09-14): belt-and-suspenders cleanup - the
    # revision check above already proved the PUBLISHED content is what
    # we just built, and connect()'s own journal_mode=DELETE forcing (see
    # its comment) means none of OUR connections ever leaves WAL sidecars
    # behind. This removes any that predate this reindex entirely (e.g.
    # left by an external writer, per the same repro), so a stale sidecar
    # can never sit next to a freshly-published, already-verified index.
    _cleanup(
        db_path.with_name(db_path.name + "-wal"),
        db_path.with_name(db_path.name + "-shm"),
        db_path.with_name(db_path.name + "-journal"),
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


class _StagingSubstituted(OSError):
    """The verified staging database was replaced (with a symlink or a
    different regular file) between verification and publish - see the
    Codex#2 (round 10, 2026-09-13) comment where this is raised. An
    OSError subclass so it is caught by the same publish-failure handling
    as any other OSError during the swap."""


class _RevisionMismatch(OSError):
    """The revision visible through a fresh post-swap connection does not
    match what build_index() just reported publishing - see the Codex#1
    (round 19, 2026-09-14) comment where this is raised. An OSError
    subclass so it is caught by the same publish-failure handling
    (restore the previous index) as any other post-swap failure."""
