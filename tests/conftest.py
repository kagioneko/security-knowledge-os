from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def fixture_knowledge_root(fixtures_dir: Path) -> Path:
    return fixtures_dir / "knowledge"
