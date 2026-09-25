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


def test_jwt_shape_detection_is_linear_time() -> None:
    """Regression for Codex round-32 (2026-09-25), reproduced exactly as
    reported: the JWT pattern took ~1.1 s on 48 KB of repeated `eyJ` (and
    ~20 s on the reported 0.9 MB request) because every `eyJ` restarted a
    scan of the rest of the run. The rewritten pattern must stay fast on
    that input and still find real JWTs, including one glued to a
    preceding word (the old pattern found those too)."""
    import time

    from app.models._credential_shapes import CREDENTIAL_SHAPE_PATTERNS

    jwt = CREDENTIAL_SHAPE_PATTERNS["jwt"]
    start = time.perf_counter()
    assert jwt.search("eyJ" * 100_000) is None
    assert time.perf_counter() - start < 0.5

    # Joined with `+` (not implicit concatenation, which ruff format merges
    # into one literal) so the pre-publication secret scan does not flag
    # this test file itself - same intent as test_secret_scan.py's fixture.
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0" + ".abcdefghijklmn"
    )
    assert jwt.search(f"Authorization: Bearer {token}") is not None
    assert jwt.search(f"prefix{token}") is not None
    assert jwt.search("eyJshort.eyJalsoshort.x") is None


def test_oversized_raw_input_is_rejected_before_field_scanning() -> None:
    """Regression for Codex round-32 (2026-09-25): the 300 KB whole-input
    bound was an `after` validator, so every field's credential-shape scan
    ran over the full input first. One prompt here also carries a
    credential shape: if field validation still ran first, that field error
    would be reported (and the `after` size check would never run); the
    `before` pre-check must reject the input on size alone."""
    fake_key = "AKIA" + "IOSFODNN7EXAMPLE"
    prompts = [f"{fake_key} " + "x" * 40_000] + ["x" * 40_000] * 9
    with pytest.raises(ValidationError) as info:
        AssessmentInput.model_validate({"name": "t", "user_prompts": prompts})
    errors = info.value.errors()
    assert len(errors) == 1
    assert "total limit" in errors[0]["msg"]
