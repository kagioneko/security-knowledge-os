"""Resolve the configured LLM client. ``provider=none`` returns ``None``."""

from __future__ import annotations

import os

from app.config import LLMProvider, Settings
from app.llm.base import LLMClient, LLMConfigError
from app.llm.mock import MockClient


def get_client(settings: Settings) -> LLMClient | None:
    provider = settings.llm_provider

    if provider is LLMProvider.NONE:
        return None
    if provider is LLMProvider.MOCK:
        return MockClient()
    if provider is LLMProvider.ANTHROPIC:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not api_key:
            raise LLMConfigError(
                "SKOS_LLM_PROVIDER=anthropic but ANTHROPIC_API_KEY is not set"
            )
        from app.llm.anthropic_client import AnthropicClient

        return AnthropicClient(api_key=api_key, model=settings.llm_model)

    raise LLMConfigError(f"provider '{provider.value}' is not implemented in this build")
