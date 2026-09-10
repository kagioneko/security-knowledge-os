"""BM25 retrieval over the SQLite FTS5 index (spec Section 11).

Order of operations: query classification -> category filter -> classification
filter -> BM25 -> best-chunk-per-unit dedupe -> (rerank is a no-op in the MVP) ->
defence-in-depth re-check. ``top_k`` counts Knowledge Units, each represented by
its best-scoring section.
"""

from __future__ import annotations

import sqlite3

from app.config import Settings
from app.models.retrieval import Chunk, RetrievalResponse, RetrievedChunk
from app.policy.classification import PolicyBlocked, allowed_classifications, is_retrievable
from app.retrieval.base import (
    Retriever,
    classify_query,
    knowledge_categories_for,
    to_fts_match_query,
)
from app.storage.repository import ChunkRepository


class Bm25Retriever(Retriever):
    def __init__(self, conn: sqlite3.Connection, settings: Settings) -> None:
        self._repo = ChunkRepository(conn)
        self._settings = settings

    def retrieve(self, query: str) -> RetrievalResponse:
        settings = self._settings
        categories = classify_query(query)
        knowledge_categories = knowledge_categories_for(categories)
        allowed = sorted(
            classification.value
            for classification in allowed_classifications(
                settings.mode, settings.allow_confidential
            )
        )
        match_query = to_fts_match_query(query)

        hits = self._search(match_query, allowed, sorted(knowledge_categories) or None)
        if not hits and knowledge_categories:
            # graceful fallback: drop the category filter, keep the classification filter
            hits = self._search(match_query, allowed, None)

        results: list[RetrievedChunk] = []
        seen_units: set[str] = set()
        for chunk, score in hits:
            if chunk.knowledge_id in seen_units:
                continue
            seen_units.add(chunk.knowledge_id)
            self._enforce_classification(chunk)
            results.append(
                RetrievedChunk(chunk=chunk, score=score, rank=len(results) + 1)
            )
            if len(results) >= settings.top_k:
                break

        return RetrievalResponse(
            query=query,
            query_categories=categories,
            mode=settings.mode.value,
            knowledge_revision=self._repo.knowledge_revision() or "",
            results=results,
        )

    def _search(
        self, match_query: str, allowed: list[str], categories: list[str] | None
    ) -> list[tuple[Chunk, float]]:
        # Over-fetch sections so the per-unit dedupe still has top_k distinct units.
        limit = max(self._settings.top_k * 10, 50)
        return self._repo.search(match_query, allowed, categories, limit)

    def _enforce_classification(self, chunk: Chunk) -> None:
        # spec Section 9 / Section 33 fail-closed: never return disallowed content,
        # even if the SQL classification filter was wrong.
        if not is_retrievable(
            chunk.classification, self._settings.mode, self._settings.allow_confidential
        ):
            raise PolicyBlocked(
                f"classification '{chunk.classification.value}' leaked past the index "
                f"filter for mode '{self._settings.mode.value}'"
            )
