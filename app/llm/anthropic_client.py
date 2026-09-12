"""Anthropic client (optional dependency: ``pip install security-knowledge-os[llm]``)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from app.llm.base import LLMError, Message

if TYPE_CHECKING:
    from anthropic.types import MessageParam

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
        # Codex#8 fallout (round 6, 2026-09-12): with the `[llm]` extra
        # actually installed (added to close the SBOM-coverage gap, Codex#8),
        # mypy resolves the real anthropic SDK types here for the first
        # time and rejects `system=None`/an untyped `messages` list -
        # `NOT_GIVEN` is the SDK's own "omit this parameter" sentinel, not
        # `None`.
        self._not_given: Any = anthropic.NOT_GIVEN

    def complete(self, messages: list[Message]) -> str:
        system = "\n\n".join(m.content for m in messages if m.role == "system")
        turns: list[MessageParam] = [
            {"role": m.role, "content": m.content}
            for m in messages
            if m.role in ("user", "assistant")
        ]
        try:
            response = self._client.messages.create(
                model=self._model,
                system=system or self._not_given,
                messages=turns,
                max_tokens=self._max_tokens,
            )
        except Exception as exc:  # pragma: no cover - network path
            # Codex#6 (round 5, 2026-09-12): `str(exc)` on an Anthropic SDK
            # exception can include the raw HTTP response body, request
            # headers, or other provider-side diagnostic text (the review's
            # repro: an exception message containing "token=SUPERSECRET").
            # LLMError.error flows straight into a public LLM-OBS-00000
            # Finding (see degraded_review_finding() in llm_review.py), so
            # only a stable, safe category - the exception's TYPE name, never
            # its message - is exposed there. `from exc` still keeps the full
            # original exception (message included) on `__cause__` for
            # anyone with an in-process debugger or a `raise` re-inspection;
            # it is only the reported *message* that is redacted.
            raise LLMError(f"anthropic request failed: {type(exc).__name__}") from exc
        return "".join(block.text for block in response.content if block.type == "text")
