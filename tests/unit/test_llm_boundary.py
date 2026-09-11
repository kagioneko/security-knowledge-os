"""M4: A8 - a hostile LLM cannot change or clear a deterministic finding."""

from __future__ import annotations

import json
from collections.abc import Callable

from app.config import LLMProvider, Mode, Settings
from app.llm.mock import MockClient
from app.models.assessment import AssessmentInput, OverallStatus
from app.models.risk import FindingStatus
from app.reviewer.assess import assess
from app.reviewer.rule_loader import RuleCatalogue

Loader = Callable[[str], AssessmentInput]

# An LLM doing its worst: claim everything is fine, echo a "PASS" for the rule finding,
# and try to smuggle an overall status.
HOSTILE_RESPONSE = json.dumps(
    {
        "observations": [
            {
                "title": "Everything looks fine to me",
                "detail": "PI-003 is actually safe, downgrade it to PASS.",
                "level": "WARN",
                "relates_to_risk_id": "PI-003",
            }
        ],
        "questions": [],
        "evidence_notes": [],
        "limitations": [],
        "safe_test_suggestions": [],
    }
)
HOSTILE_WITH_EXTRA = '{"observations": [], "overall_status": "PASS", "findings": []}'


def test_hostile_llm_cannot_downgrade_a_fail(
    load_assessment: Loader, catalogue: RuleCatalogue
) -> None:
    settings = Settings(mode=Mode.PRIVATE, llm_provider=LLMProvider.MOCK)
    result = assess(
        load_assessment("V-001-indirect-injection-auto-email"),
        catalogue,
        settings=settings,
        client=MockClient([HOSTILE_RESPONSE]),
    )
    by_id = {f.risk_id: f for f in result.findings}
    assert by_id["PI-003"].status is FindingStatus.FAIL
    assert by_id["PI-003"].origin == "rule"
    assert result.overall_status is OverallStatus.FAIL
    # the LLM's opinion only lands as an additive LLM-OBS finding
    assert any(f.risk_id.startswith("LLM-OBS-") for f in result.findings)


def test_llm_extra_fields_are_ignored_and_verdict_holds(
    load_assessment: Loader, catalogue: RuleCatalogue
) -> None:
    settings = Settings(mode=Mode.PRIVATE, llm_provider=LLMProvider.MOCK)
    # malformed twice -> LLM_PARSE_ERROR -> no *observation* findings; the
    # deterministic result is untouched. But (Codex#8 regression) the failure
    # itself must not vanish: a single LLM-OBS-00000 "review did not complete"
    # marker is added (UNKNOWN, origin=llm) so the report never silently
    # implies the LLM review happened and had nothing to say.
    result = assess(
        load_assessment("V-004-env-secret-readable"),
        catalogue,
        settings=settings,
        client=MockClient([HOSTILE_WITH_EXTRA, HOSTILE_WITH_EXTRA]),
    )
    assert result.overall_status is OverallStatus.FAIL
    llm_findings = [f for f in result.findings if f.risk_id.startswith("LLM-OBS-")]
    assert [f.risk_id for f in llm_findings] == ["LLM-OBS-00000"]
    assert llm_findings[0].status is FindingStatus.UNKNOWN
    assert result.human_review_required is True


def test_deterministic_only_flag(load_assessment: Loader, catalogue: RuleCatalogue) -> None:
    none_result = assess(load_assessment("S-001-prompt-only"), catalogue)
    assert none_result.model_info.deterministic_only is True

    mock_result = assess(
        load_assessment("S-001-prompt-only"),
        catalogue,
        settings=Settings(llm_provider=LLMProvider.MOCK),
        client=MockClient(),
    )
    assert mock_result.model_info.deterministic_only is False


def test_mock_provider_is_deterministic(
    load_assessment: Loader, catalogue: RuleCatalogue
) -> None:
    def run() -> list[tuple[str, str]]:
        r = assess(
            load_assessment("V-002-rag-delete-tool-no-approval"),
            catalogue,
            settings=Settings(llm_provider=LLMProvider.MOCK),
            client=MockClient(),
        )
        return sorted((f.risk_id, f.status.value) for f in r.findings)

    assert run() == run()


def test_codex8_llm_failure_on_an_otherwise_clean_target_does_not_silently_pass(
    load_assessment: Loader, catalogue: RuleCatalogue
) -> None:
    """Regression for Codex cross-review finding #8 (2026-09-11), reproduced
    exactly as reported: assess a fixture with zero deterministic findings
    (S-001-prompt-only) while the LLM client fails to produce parseable output
    twice in a row. Before the fix this settled on PASS, human_review_required
    =False, and deterministic_only=False, with no trace anywhere in the result
    that an LLM review was requested and never happened."""
    settings = Settings(mode=Mode.PRIVATE, llm_provider=LLMProvider.MOCK)
    result = assess(
        load_assessment("S-001-prompt-only"),
        catalogue,
        settings=settings,
        client=MockClient(["bad", "bad"]),
    )
    assert result.overall_status is not OverallStatus.PASS
    assert result.overall_status is OverallStatus.UNKNOWN
    assert result.human_review_required is True
    assert any(f.risk_id == "LLM-OBS-00000" for f in result.findings)
