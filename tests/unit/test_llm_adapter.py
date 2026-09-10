"""M4: LLM client interface and factory."""

from __future__ import annotations

import pytest

from app.config import LLMProvider, Mode, Settings
from app.llm.base import LLMClient, LLMConfigError, Message
from app.llm.factory import get_client
from app.llm.mock import DEFAULT_MOCK_RESPONSE, MockClient


def test_provider_none_returns_no_client() -> None:
    assert get_client(Settings(llm_provider=LLMProvider.NONE)) is None


def test_provider_mock_returns_mock_client() -> None:
    client = get_client(Settings(llm_provider=LLMProvider.MOCK))
    assert isinstance(client, MockClient)
    assert isinstance(client, LLMClient)


def test_provider_anthropic_without_key_is_config_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(LLMConfigError):
        get_client(Settings(llm_provider=LLMProvider.ANTHROPIC))


def test_unimplemented_provider_is_config_error() -> None:
    with pytest.raises(LLMConfigError):
        get_client(Settings(llm_provider=LLMProvider.OPENAI))


def test_mock_client_returns_canned_then_repeats_last() -> None:
    client = MockClient(["a", "b"])
    msgs = [Message("user", "x")]
    assert client.complete(msgs) == "a"
    assert client.complete(msgs) == "b"
    assert client.complete(msgs) == "b"
    assert client.calls == 3


def test_default_mock_response_is_valid_json_for_the_schema() -> None:
    from app.models.reviewer_output import ReviewerObservations

    parsed = ReviewerObservations.model_validate_json(DEFAULT_MOCK_RESPONSE)
    assert parsed.observations and parsed.questions


def test_settings_mode_unused_here_but_constructs() -> None:
    assert Settings(mode=Mode.PUBLIC).llm_provider is LLMProvider.NONE
