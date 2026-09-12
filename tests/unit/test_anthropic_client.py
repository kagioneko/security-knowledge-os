"""app/llm/anthropic_client.py: the optional Anthropic provider client.

The `anthropic` package itself is an optional extra (`pip install
security-knowledge-os[llm]`) and is not a dependency of the test suite, so
these tests construct an AnthropicClient instance directly (bypassing
`__init__`, which imports `anthropic`) with a fake `_client` standing in for
the SDK object.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.llm.anthropic_client import AnthropicClient
from app.llm.base import LLMError, Message


def _client_with_fake_sdk(create: Any) -> AnthropicClient:
    client = object.__new__(AnthropicClient)
    client._model = "claude-sonnet-5"  # type: ignore[attr-defined]
    client._max_tokens = 2048  # type: ignore[attr-defined]
    client._not_given = None  # type: ignore[attr-defined]

    class _FakeMessages:
        pass

    fake_messages = _FakeMessages()
    fake_messages.create = create  # type: ignore[attr-defined]

    class _FakeSdkClient:
        messages = fake_messages

    client._client = _FakeSdkClient()  # type: ignore[attr-defined]
    return client


def test_a_failed_request_never_leaks_the_raw_exception_message() -> None:
    """Regression for Codex#6 (round 5, 2026-09-12), reproduced exactly as
    reported: str(exc) on the underlying SDK exception can carry a response
    body, an internal endpoint, or credential-bearing diagnostic text (here,
    a secret-shaped string). LLMError.error flows straight into a public
    LLM-OBS-00000 Finding (app/reviewer/llm_review.py), so only the
    exception's TYPE name - never its message - may end up there."""

    def _create(**kwargs: Any) -> None:
        raise RuntimeError("Authorization failed for token=SUPERSECRET")

    client = _client_with_fake_sdk(_create)

    with pytest.raises(LLMError) as exc_info:
        client.complete([Message("user", "hi")])

    message = str(exc_info.value)
    assert "SUPERSECRET" not in message
    assert "RuntimeError" in message  # a stable category is still reported
    assert exc_info.value.__cause__ is not None  # full detail stays on __cause__
