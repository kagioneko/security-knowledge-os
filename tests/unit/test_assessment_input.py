"""AssessmentInput field-level validators (schema level, not the full assess() pipeline)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.models.assessment import AssessmentInput


def test_name_rejects_a_known_credential_shape() -> None:
    """Regression for Codex#6 / Antigravity SKOS-ADV-21 (round 17,
    2026-09-14), reproduced exactly as reported: unlike every other
    free-text field on this model (system_prompt, developer_prompt),
    `name` had no reject_credential_shapes validator -
    AssessmentInput(name="AKIA...") validated and was retained/returned
    in reports (as `scope`), while the identical value in system_prompt
    was correctly rejected."""
    fake_key = "AKIA" + "IOSFODNN7EXAMPLE"
    with pytest.raises(ValidationError):
        AssessmentInput(name=fake_key)


def test_name_still_accepts_an_ordinary_value() -> None:
    """Mirror case: an ordinary assessment name must still validate."""
    inp = AssessmentInput(name="Q3 vendor integration review")
    assert inp.name == "Q3 vendor integration review"
