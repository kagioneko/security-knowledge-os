"""Build the knowledge index from a configurable knowledge root (spec Section 10).

The knowledge root is a parameter, not a constant: today it points at ``knowledge/``,
later it can point at ``active/knowledge/`` populated by the Pack Manager.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from app.ingestion.loader import LoadedUnit, compute_knowledge_revision, load_corpus
from app.models.retrieval import Chunk
from app.storage.db import connect
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
