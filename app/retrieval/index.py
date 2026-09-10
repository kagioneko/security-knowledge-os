"""Build the knowledge index from a configurable knowledge root (spec Section 10).

The knowledge root is a parameter, not a constant: today it points at ``knowledge/``,
later it can point at ``active/knowledge/`` populated by the Pack Manager.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

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


def build_index(knowledge_root: Path | str, db_path: Path | str) -> IndexBuildReport:
    knowledge_root = Path(knowledge_root)
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
    existing index is left untouched (no partial update).
    """
    knowledge_root = Path(knowledge_root)
    db_path = Path(db_path)
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

    # 2. build into a staging database
    staging = db_path.with_suffix(db_path.suffix + ".staging")
    if staging.exists():
        staging.unlink()
    try:
        build = build_index(knowledge_root, staging)

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

        # 4. atomic swap, then re-verify the live index
        os.replace(staging, db_path)
        conn = connect(db_path, read_only=True)
        try:
            post = verify_chunk_hashes(conn)
        finally:
            conn.close()
        if not post.is_allowed:
            return ReindexReport(
                decision=stop(
                    PolicyOutcome.POLICY_BLOCKED,
                    "reindex",
                    f"post-swap integrity check failed: {post.reasons}",
                ),
                old_revision=old_revision,
                new_revision=build.knowledge_revision,
            )
    except _ReindexAbort as abort:
        if staging.exists():
            staging.unlink()
        return ReindexReport(
            decision=stop(PolicyOutcome.POLICY_BLOCKED, "reindex", str(abort)),
            old_revision=old_revision,
        )

    return ReindexReport(
        decision=allow("reindex"),
        old_revision=old_revision,
        new_revision=build.knowledge_revision,
        chunks_indexed=build.chunks_indexed,
        units_indexed=build.units_indexed,
    )


class _ReindexAbort(Exception):
    pass
