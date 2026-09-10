"""M4: the LLM output schema structurally cannot change a verdict (decision A8)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.models.reviewer_output import (
    LLMObservation,
    ObservationLevel,
    ReviewerObservations,
)


def test_schema_has_no_status_or_overall_fields() -> None:
    assert set(ReviewerObservations.model_fields) == {
        "observations",
        "questions",
        "evidence_notes",
        "limitations",
        "safe_test_suggestions",
    }
    assert "status" not in LLMObservation.model_fields
    assert "overall_status" not in LLMObservation.model_fields


def test_extra_keys_are_rejected() -> None:
    payload = {
        "observations": [],
        "questions": [],
        "overall_status": "PASS",  # a hallucinated verdict
    }
    with pytest.raises(ValidationError):
        ReviewerObservations.model_validate(payload)


def test_observation_level_is_capped() -> None:
    assert {level.value for level in ObservationLevel} == {"WARN", "UNKNOWN"}
    with pytest.raises(ValidationError):
        ReviewerObservations.model_validate(
            {"observations": [{"title": "x", "detail": "y", "level": "FAIL"}]}
        )


def test_observation_that_tries_to_set_a_finding_status_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ReviewerObservations.model_validate(
            {
                "observations": [
                    {"title": "x", "detail": "y", "level": "WARN", "status": "PASS"}
                ]
            }
        )
