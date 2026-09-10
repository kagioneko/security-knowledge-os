from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def fixture_knowledge_root(fixtures_dir: Path) -> Path:
    return fixtures_dir / "knowledge"


@pytest.fixture(scope="session")
def corpus_root(fixtures_dir: Path) -> Path:
    """A clean knowledge corpus: 5 loadable units (public/internal/confidential)
    plus one secret unit that must never be indexed."""
    return fixtures_dir / "corpus"


@pytest.fixture(scope="session")
def corpus_alt_root(fixtures_dir: Path) -> Path:
    """A different corpus containing only KU-2001, for knowledge-root-switch tests."""
    return fixtures_dir / "corpus_alt"
