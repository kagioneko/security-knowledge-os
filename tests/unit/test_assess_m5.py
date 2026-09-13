"""M5 / AC-13, AC-14: read-only knowledge + safe-test attachment vs proposals."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from app.config import LLMProvider, Mode, Settings
from app.llm.mock import MockClient
from app.models.assessment import AssessmentInput
from app.models.policy_outcome import PolicyOutcome, PolicyStop
from app.retrieval.index import build_index
from app.reviewer import assess as assess_module
from app.reviewer.assess import assess
from app.reviewer.rule_loader import RuleCatalogue
from app.storage.db import connect

Loader = Callable[[str], AssessmentInput]
# Codex#6 (round 12, 2026-09-13): a hand-maintained fixture-name list like
# this is exactly the shape of list app/cli.py's own _FIXTURES (fixed in
# the same round) had silently drifted out of sync with reality - this one
# had the identical two names (U-005, V-005) missing. Deriving it from the
# fixture directory itself, the same way scripts/evaluate.py already does,
# makes it impossible to drift: every fixture file present is exercised.
_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "assessments"
ALL_FIXTURES = sorted(
    p.stem
    for p in _FIXTURES_DIR.rglob("*.yaml")
    if p.parent.name in {"vulnerable", "safe", "unknown"}
)

_PROPOSAL_RESPONSE = json.dumps(
    {
        "observations": [],
        "questions": [],
        "evidence_notes": [],
        "limitations": [],
        "safe_test_suggestions": [
            {
                "title": "Try sending a canary email through the agent",
                "relates_to_risk_id": "PI-003",
                "idea": "See whether the agent forwards an injected instruction.",
            }
        ],
    }
)


def test_assess_source_has_no_knowledge_write() -> None:
    source = Path(assess_module.__file__).read_text(encoding="utf-8")
    for token in ("rebuild(", "build_index", "INSERT INTO chunks", "UPDATE chunks", "DELETE FROM"):
        assert token not in source, token


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_ac14_all_fixtures_complete_with_a_read_only_index(
    name: str,
    load_assessment: Loader,
    catalogue: RuleCatalogue,
    tmp_path_factory: pytest.TempPathFactory,
    corpus_root: Path,
) -> None:
    db = tmp_path_factory.mktemp("ro") / "idx.sqlite"
    build_index(corpus_root, db)
    conn = connect(db, read_only=True)
    try:
        result = assess(
            load_assessment(name),
            catalogue,
            settings=Settings(mode=Mode.PRIVATE),
            index_conn=conn,
        )
    finally:
        conn.close()
    assert result.assessment_id
    assert result.knowledge_revision is not None


def test_read_only_connection_cannot_write(tmp_path: Path, corpus_root: Path) -> None:
    import sqlite3

    db = tmp_path / "idx.sqlite"
    build_index(corpus_root, db)
    conn = connect(db, read_only=True)
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("DELETE FROM chunks")
    finally:
        conn.close()


def test_read_only_survives_a_hash_in_the_path(tmp_path: Path, corpus_root: Path) -> None:
    """Regression for Codex cross-review finding #5 (2026-09-11): building the
    read-only URI as a bare f"file:{db_path}?mode=ro" let a '#' in the path put
    "?mode=ro" inside the URI *fragment*, which is discarded - AND the path
    itself gets truncated at '#', so the connection silently opens the WRONG
    (truncated) path rather than the intended file. Both properties must hold:
    it opens the real file (content matches) AND write is still refused."""
    import sqlite3

    db = tmp_path / "idx#with a?weird%name.sqlite"
    build_index(corpus_root, db)
    conn = connect(db, read_only=True)
    try:
        # proves it opened the *intended* file, not a truncated/different one
        (count,) = conn.execute("SELECT COUNT(*) FROM chunks").fetchone()
        assert count > 0
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("DELETE FROM chunks")
    finally:
        conn.close()


def test_safe_tests_are_attached_for_flagged_findings(
    load_assessment: Loader, catalogue: RuleCatalogue
) -> None:
    result = assess(load_assessment("V-001-indirect-injection-auto-email"), catalogue)
    attached = {t.id for t in result.safe_tests}
    assert "ST-IPI-001" in attached
    for test in result.safe_tests:
        assert test.origin in ("template", "human")
        assert test.environment
        assert test.cleanup


def test_assess_fails_closed_when_a_referenced_safe_test_template_is_missing(
    load_assessment: Loader, catalogue: RuleCatalogue
) -> None:
    """Regression for Codex#6 (round 7, 2026-09-12), reproduced exactly as
    reported: an existing but empty (or otherwise incomplete) safe-test
    catalogue used to let assessment continue silently - a normal FAIL with
    safe_tests=[] - instead of surfacing a policy/configuration error.
    PI-003 (the rule V-001 triggers) references ST-IPI-001
    (test_safe_tests_are_attached_for_flagged_findings above); passing an
    empty safe_tests dict reproduces the missing-template repro exactly."""
    with pytest.raises(PolicyStop) as exc_info:
        assess(
            load_assessment("V-001-indirect-injection-auto-email"),
            catalogue,
            safe_tests={},
        )
    assert exc_info.value.decision.outcome is PolicyOutcome.POLICY_BLOCKED


def test_llm_suggestions_land_as_untrusted_proposals_not_safe_tests(
    load_assessment: Loader, catalogue: RuleCatalogue
) -> None:
    result = assess(
        load_assessment("V-001-indirect-injection-auto-email"),
        catalogue,
        settings=Settings(llm_provider=LLMProvider.MOCK),
        client=MockClient([_PROPOSAL_RESPONSE]),
    )
    assert result.safe_test_proposals
    assert result.safe_test_proposals[0].origin == "llm"
    proposal_titles = {p.title for p in result.safe_test_proposals}
    safe_test_titles = {t.title for t in result.safe_tests}
    assert proposal_titles.isdisjoint(safe_test_titles)
    # every executable safe test is template-origin, never llm
    assert all(t.origin == "template" for t in result.safe_tests)


def test_safe_fixtures_have_no_attached_safe_tests(
    load_assessment: Loader, catalogue: RuleCatalogue
) -> None:
    for name in ("S-001-prompt-only", "S-002-rag-trusted-no-actions"):
        result = assess(load_assessment(name), catalogue)
        assert result.safe_tests == []
