"""Query classification and the retriever protocol (spec Section 11)."""

from __future__ import annotations

import re
from typing import Protocol

from app.models.knowledge import KnowledgeCategory
from app.models.retrieval import QueryCategory, RetrievalResponse

# Keyword -> query category. Deterministic and intentionally simple for the MVP.
_QUERY_KEYWORDS: dict[QueryCategory, tuple[str, ...]] = {
    QueryCategory.PROMPT: (
        "prompt", "instruction", "jailbreak", "system message", "role confusion",
    ),
    QueryCategory.RAG: (
        "rag", "retrieval", "retrieved", "document", "grounding", "knowledge base",
    ),
    QueryCategory.AGENT: ("agent", "autonomous", "orchestrat", "multi-step"),
    QueryCategory.TOOL: (
        "tool", "function call", "shell", "command", "delete", "send", "email", "file write",
    ),
    QueryCategory.MEMORY: (
        "memory", "persistence", "persistent", "long-term", "history", "remember",
    ),
    QueryCategory.CREDENTIAL: (
        "credential", "api key", "secret", "token", ".env", "vault", "password",
    ),
    QueryCategory.GOVERNANCE: (
        "governance", "approval", "policy", "oversight", "human review", "sign-off",
    ),
    QueryCategory.INCIDENT: ("incident", "breach", "compromise", "postmortem", "intrusion"),
}

QUERY_CATEGORY_TO_KNOWLEDGE: dict[QueryCategory, KnowledgeCategory] = {
    QueryCategory.PROMPT: KnowledgeCategory.PROMPT_SECURITY,
    QueryCategory.RAG: KnowledgeCategory.RAG_SECURITY,
    QueryCategory.AGENT: KnowledgeCategory.AGENT_SECURITY,
    QueryCategory.TOOL: KnowledgeCategory.AGENT_SECURITY,
    QueryCategory.MEMORY: KnowledgeCategory.MEMORY_SECURITY,
    QueryCategory.CREDENTIAL: KnowledgeCategory.CREDENTIAL_SECURITY,
    QueryCategory.GOVERNANCE: KnowledgeCategory.GOVERNANCE,
    QueryCategory.INCIDENT: KnowledgeCategory.INCIDENT,
}

# ASCII words, or runs of CJK / kana (so a Japanese query yields usable terms).
_TOKEN_RE = re.compile(r"[a-z0-9]{3,}|[぀-ヿ㐀-鿿ｦ-ﾟ]{3,}")
_CJK_START_RE = re.compile(r"[぀-ヿ㐀-鿿ｦ-ﾟ]")
_CJK_NGRAM = 4


def classify_query(query: str) -> list[QueryCategory]:
    lowered = query.casefold()
    return [
        category
        for category, keywords in _QUERY_KEYWORDS.items()
        if any(keyword in lowered for keyword in keywords)
    ]


def knowledge_categories_for(categories: list[QueryCategory]) -> set[str]:
    return {
        QUERY_CATEGORY_TO_KNOWLEDGE[category].value
        for category in categories
        if category in QUERY_CATEGORY_TO_KNOWLEDGE
    }


def to_fts_match_query(query: str) -> str:
    # trigram matching needs >= 3 characters per term. A long CJK run has no word
    # boundaries, so it is expanded into overlapping n-grams for partial matching.
    terms: list[str] = []
    for token in _TOKEN_RE.findall(query.casefold()):
        if len(token) < 3:
            continue
        if _CJK_START_RE.match(token) and len(token) > _CJK_NGRAM:
            terms.extend(
                token[i : i + _CJK_NGRAM] for i in range(len(token) - _CJK_NGRAM + 1)
            )
        else:
            terms.append(token)
    if not terms:
        return '"__no_match__"'
    seen: list[str] = []
    for term in terms:
        if term not in seen:
            seen.append(term)
    return " OR ".join(f'"{term}"' for term in seen[:48])


class Retriever(Protocol):
    def retrieve(self, query: str) -> RetrievalResponse: ...
