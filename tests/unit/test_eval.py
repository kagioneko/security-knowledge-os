"""M7 / §24: evaluation metrics over the labelled fixtures + initial gates."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

from app.config import Mode, Settings
from app.eval.metrics import LabelledResult, compute_metrics
from app.models.assessment import AssessmentInput
from app.retrieval.index import build_index
from app.reviewer.assess import assess
from app.reviewer.rule_loader import RuleCatalogue
from app.storage.db import connect

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures" / "assessments"

Loader = Callable[[str], AssessmentInput]


@pytest.fixture(scope="module")
def index_conn():
    import tempfile

    db = Path(tempfile.mkdtemp()) / "k.sqlite"
    build_index(REPO / "knowledge", db)
    conn = connect(db, read_only=True)
    yield conn
    conn.close()


@pytest.fixture
def labelled(catalogue: RuleCatalogue, safe_test_templates, index_conn) -> list[LabelledResult]:
    out: list[LabelledResult] = []
    for path in sorted(FIXTURES.rglob("*.yaml")):
        label = path.parent.name
        inp = AssessmentInput.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
        result = assess(
            inp,
            catalogue,
            settings=Settings(mode=Mode.PRIVATE),
            index_conn=index_conn,
            safe_tests=safe_test_templates,
        )
        out.append(LabelledResult(label=label, result=result))
    return out


def test_metrics_separate_the_three_classes(
    labelled: list[LabelledResult], catalogue: RuleCatalogue
) -> None:
    m = compute_metrics(labelled, catalogue)
    assert m.n_vulnerable == 4 and m.n_safe == 4 and m.n_unknown == 5
    assert m.known_risk_recall == 1.0
    assert m.false_positive_rate == 0.0
    assert m.unknown_appropriateness == 1.0
    assert m.evidence_coverage == 1.0


def test_initial_gates_hold(labelled: list[LabelledResult], catalogue: RuleCatalogue) -> None:
    m = compute_metrics(labelled, catalogue)
    assert m.false_positive_rate == 0.0
    assert m.safe_test_safety_violations == 0
    assert m.gates_pass


def test_citation_source_match_uses_the_indexed_corpus(
    labelled: list[LabelledResult], catalogue: RuleCatalogue
) -> None:
    m = compute_metrics(labelled, catalogue)
    # with the 13 public KUs indexed, rule findings that carry knowledge_refs
    # should mostly retrieve at least one of them
    assert m.citation_source_match is not None
    assert m.citation_source_match >= 0.5
