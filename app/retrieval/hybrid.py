"""Hybrid retriever placeholder (spec Section 6, Section 30).

The MVP has no embeddings, so the "hybrid" retriever is BM25 plus an identity
rerank. Embedding retrieval and a real reranker are future work; keeping this
seam now means the orchestrator does not change when they land.
"""

from __future__ import annotations

import sqlite3

from app.config import Settings
from app.models.retrieval import RetrievalResponse
from app.retrieval.base import Retriever
from app.retrieval.bm25 import Bm25Retriever


def identity_rerank(response: RetrievalResponse) -> RetrievalResponse:
    return response


class HybridRetriever(Retriever):
    def __init__(self, conn: sqlite3.Connection, settings: Settings) -> None:
        self._bm25 = Bm25Retriever(conn, settings)

    def retrieve(self, query: str) -> RetrievalResponse:
        return identity_rerank(self._bm25.retrieve(query))
