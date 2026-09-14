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


def test_remaining_scalar_fields_reject_a_known_credential_shape() -> None:
    """Regression for Codex#3 / Antigravity SKOS-ADV-24 (round 18,
    2026-09-14), reproduced exactly as reported: MemoryInput.scope,
    ToolInput.permissions, CredentialInput.storage, and CredentialInput.
    exposed_to_model were the only externally-supplied string fields on
    this model still missing reject_credential_shapes -
    normalize.py maps an unrecognized value to UNKNOWN before it reaches
    the LLM, but the raw value was retained in the in-memory store
    regardless, contradicting this module's own stated invariant that
    every free-text field gets shape validation."""
    fake_key = "AKIA" + "Q" * 16
    with pytest.raises(ValidationError):
        AssessmentInput(name="x", memory={"scope": fake_key})
    with pytest.raises(ValidationError):
        AssessmentInput(name="x", tools=[{"name": "t", "permissions": fake_key}])
    with pytest.raises(ValidationError):
        AssessmentInput(name="x", credentials={"storage": fake_key})
    with pytest.raises(ValidationError):
        AssessmentInput(name="x", credentials={"exposed_to_model": fake_key})


def test_remaining_scalar_fields_still_accept_ordinary_values() -> None:
    """Mirror case: the ordinary, legitimate values these fields actually
    hold in real use must still validate."""
    inp = AssessmentInput(
        name="x",
        memory={"scope": "session"},
        tools=[{"name": "email_send", "permissions": "send"}],
        credentials={"storage": "vault", "exposed_to_model": "false"},
    )
    assert inp.memory.scope == "session"
    assert inp.tools[0].permissions == "send"
    assert inp.credentials.storage == "vault"
    assert inp.credentials.exposed_to_model == "false"
