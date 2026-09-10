"""Deterministic mock LLM client for tests and offline demos."""

from __future__ import annotations

import json

from app.llm.base import Message

_DEFAULT_PAYLOAD = {
    "observations": [
        {
            "title": "Prompt boundary not verified",
            "detail": (
                "The deterministic engine cannot confirm that untrusted content is "
                "isolated from instructions; a human should review the system prompt."
            ),
            "level": "UNKNOWN",
            "relates_to_risk_id": "PI-003",
            "evidence_refs": [],
        }
    ],
    "questions": [
        {
            "text": (
                "Is retrieved content wrapped in an explicit untrusted-data boundary "
                "before it reaches the model?"
            ),
            "field": "system_prompt",
            "why": "Determines whether indirect prompt injection is mitigated.",
        }
    ],
    "evidence_notes": [],
    "limitations": ["Mock reviewer output; not a real model assessment."],
    "safe_test_suggestions": [],
}

DEFAULT_MOCK_RESPONSE = json.dumps(_DEFAULT_PAYLOAD, indent=2)


class MockClient:
    """Returns canned responses in order; repeats the last one when exhausted."""

    name = "mock"

    def __init__(self, responses: list[str] | None = None) -> None:
        self._responses = responses or [DEFAULT_MOCK_RESPONSE]
        self._calls = 0

    @property
    def calls(self) -> int:
        return self._calls

    def complete(self, messages: list[Message]) -> str:
        response = self._responses[min(self._calls, len(self._responses) - 1)]
        self._calls += 1
        return response
