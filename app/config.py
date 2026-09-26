"""Runtime configuration.

Every setting has a safe default and is read from the environment. The system is
designed to run fully offline: the default LLM provider is ``none`` (deterministic
rule engine only). External LLMs are opt-in (decision A3, 2026-09-10).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

# Default data (rules / knowledge / safe_tests) is shipped inside the package
# so `pip install security-knowledge-os` then `skos assess ...` works without a
# checkout. `[tool.hatch.build.targets.wheel.force-include]` maps the repo's
# top-level data dirs here; in a source checkout this directory does not exist
# and the repo-relative paths are used instead.
_BUNDLED = Path(__file__).resolve().parent / "_bundled"


def _root_default(name: str, env_name: str) -> str:
    """Resolve a data-root default: explicit env wins; then a same-named dir in
    the current directory (a source checkout); then the packaged copy shipped
    in the wheel; otherwise the bare name (a clear 'not found' downstream)."""
    from_env = os.environ.get(env_name, "").strip()
    if from_env:
        return from_env
    if Path(name).is_dir():
        return name
    bundled = _BUNDLED / name
    if bundled.is_dir():
        return str(bundled)
    return name


class Mode(StrEnum):
    """Retrieval mode. Controls which classifications are searchable."""

    PUBLIC = "public"
    PRIVATE = "private"


class LLMProvider(StrEnum):
    NONE = "none"
    MOCK = "mock"
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    LOCAL = "local"


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default).strip()


def _env_bool(name: str, default: bool) -> bool:
    return _env(name, str(default)).lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    mode: Mode = Mode.PRIVATE
    allow_confidential: bool = False
    llm_provider: LLMProvider = LLMProvider.NONE
    llm_model: str | None = None
    knowledge_root: str = "knowledge"
    rules_root: str = "rules"
    safe_tests_root: str = "safe_tests"
    db_path: str = "var/index.sqlite"
    top_k: int = 5

    @property
    def deterministic_only(self) -> bool:
        return self.llm_provider in {LLMProvider.NONE, LLMProvider.MOCK}

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            mode=Mode(_env("SKOS_MODE", Mode.PRIVATE.value)),
            allow_confidential=_env_bool("SKOS_ALLOW_CONFIDENTIAL", False),
            llm_provider=LLMProvider(_env("SKOS_LLM_PROVIDER", LLMProvider.NONE.value)),
            llm_model=_env("SKOS_LLM_MODEL", "") or None,
            knowledge_root=_root_default("knowledge", "SKOS_KNOWLEDGE_ROOT"),
            rules_root=_root_default("rules", "SKOS_RULES_ROOT"),
            safe_tests_root=_root_default("safe_tests", "SKOS_SAFE_TESTS_ROOT"),
            db_path=_env("SKOS_DB_PATH", "var/index.sqlite"),
            top_k=int(_env("SKOS_TOP_K", "5")),
        )
