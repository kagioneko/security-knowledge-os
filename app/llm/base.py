"""LLM client interface (spec Section 16).

A client turns a list of messages into raw assistant text. Parsing, schema
validation and the single repair attempt live in the reviewer, not here, so the
interface stays trivial to implement for any provider.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

Role = Literal["system", "user", "assistant"]


@dataclass(frozen=True)
class Message:
    role: Role
    content: str


class LLMError(RuntimeError):
    """A provider call failed (network, auth, quota, ...)."""


class LLMConfigError(RuntimeError):
    """The requested provider is not usable with the current configuration."""


@runtime_checkable
class LLMClient(Protocol):
    name: str

    def complete(self, messages: list[Message]) -> str: ...
