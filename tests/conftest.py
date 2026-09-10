from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

from app.models.assessment import AssessmentInput
from app.reviewer.rule_loader import RuleCatalogue, load_rules


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


@pytest.fixture(scope="session")
def rules_root() -> Path:
    return Path(__file__).resolve().parents[1] / "rules"


@pytest.fixture(scope="session")
def catalogue(rules_root: Path) -> RuleCatalogue:
    return load_rules(rules_root)


@pytest.fixture(scope="session")
def safe_tests_root() -> Path:
    return Path(__file__).resolve().parents[1] / "safe_tests"


@pytest.fixture(scope="session")
def safe_test_templates(safe_tests_root: Path):
    from app.policy.safe_test import load_safe_test_templates

    return load_safe_test_templates(safe_tests_root)


@pytest.fixture(scope="session")
def assessments_dir(fixtures_dir: Path) -> Path:
    return fixtures_dir / "assessments"


@pytest.fixture(scope="session")
def load_assessment(assessments_dir: Path) -> Callable[[str], AssessmentInput]:
    def _load(name: str) -> AssessmentInput:
        path = assessments_dir / f"{name}.yaml"
        return AssessmentInput.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))

    return _load
