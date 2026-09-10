"""Anthropic client (optional dependency: ``pip install security-knowledge-os[llm]``)."""

from __future__ import annotations

from app.llm.base import LLMError, Message

DEFAULT_MODEL = "claude-sonnet-5"


class AnthropicClient:
    name = "anthropic"

    def __init__(self, *, api_key: str, model: str | None = None, max_tokens: int = 2048) -> None:
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise LLMError(
                "the 'anthropic' package is required; install security-knowledge-os[llm]"
            ) from exc
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model or DEFAULT_MODEL
        self._max_tokens = max_tokens

    def complete(self, messages: list[Message]) -> str:
        system = "\n\n".join(m.content for m in messages if m.role == "system")
        turns = [
            {"role": m.role, "content": m.content}
            for m in messages
            if m.role in ("user", "assistant")
        ]
        try:
            response = self._client.messages.create(
                model=self._model,
                system=system or None,
                messages=turns,
                max_tokens=self._max_tokens,
            )
        except Exception as exc:  # pragma: no cover - network path
            raise LLMError(f"anthropic request failed: {exc}") from exc
        return "".join(
            block.text for block in response.content if getattr(block, "type", None) == "text"
        )
