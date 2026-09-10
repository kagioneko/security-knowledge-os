"""M4 / AC-07, AC-10, AC-11: full assessment with retrieval + optional LLM."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from app.config import LLMProvider, Mode, Settings
from app.models.assessment import AssessmentInput
from app.retrieval.index import build_index
from app.reviewer.assess import assess
from app.reviewer.rule_loader import RuleCatalogue
from app.storage.db import connect

Loader = Callable[[str], AssessmentInput]
UNKNOWN = [
    "U-001-tool-permissions-missing",
    "U-002-memory-persistence-unspecified",
    "U-003-outbound-destination-unspecified",
    "U-004-credential-handling-unspecified",
]


@pytest.fixture
def index_conn(tmp_path: Path, corpus_root: Path):
    db = tmp_path / "idx.sqlite"
    build_index(corpus_root, db)
    conn = connect(db)
    yield conn
    conn.close()


def test_provider_none_completes_without_index(
    load_assessment: Loader, catalogue: RuleCatalogue
) -> None:
    result = assess(load_assessment("V-001-indirect-injection-auto-email"), catalogue)
    assert result.findings
    assert result.knowledge_revision is None
    assert result.model_info.deterministic_only is True


def test_ac11_knowledge_revision_and_model_info_wired(
    load_assessment: Loader, catalogue: RuleCatalogue, index_conn
) -> None:
    result = assess(
        load_assessment("V-001-indirect-injection-auto-email"),
        catalogue,
        settings=Settings(mode=Mode.PRIVATE),
        index_conn=index_conn,
    )
    assert result.knowledge_revision is not None
    assert len(result.knowledge_revision) == 64
    assert result.model_info.llm_provider == "none"


@pytest.mark.parametrize("name", UNKNOWN)
def test_ac07_unknown_fixtures_produce_questions_and_missing_info(
    name: str, load_assessment: Loader, catalogue: RuleCatalogue
) -> None:
    result = assess(load_assessment(name), catalogue)
    assert result.missing_information, name
    assert result.questions, name
    assert all(q.text for q in result.questions)


def test_ac10_output_carries_evidence_limitations_and_mitigations(
    load_assessment: Loader, catalogue: RuleCatalogue
) -> None:
    result = assess(load_assessment("V-002-rag-delete-tool-no-approval"), catalogue)
    for finding in result.findings:
        assert finding.evidence
        assert finding.reasoning_summary
    fail_ids = {f.risk_id for f in result.findings if f.status.value in ("FAIL", "WARN")}
    assert fail_ids
    assert {m.risk_id for m in result.mitigations} & fail_ids


def test_llm_observations_become_questions_and_findings(
    load_assessment: Loader, catalogue: RuleCatalogue
) -> None:
    from app.llm.mock import MockClient

    result = assess(
        load_assessment("V-001-indirect-injection-auto-email"),
        catalogue,
        settings=Settings(llm_provider=LLMProvider.MOCK),
        client=MockClient(),
    )
    assert any(f.risk_id.startswith("LLM-OBS-") for f in result.findings)
    assert any(q.field == "system_prompt" for q in result.questions)
