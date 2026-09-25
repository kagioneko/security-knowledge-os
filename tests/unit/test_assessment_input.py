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


_ALIAS_BOMB_CHILD = """
import resource, sys
resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
from app.ingestion.parser import safe_load_bounded
from app.models.assessment import AssessmentInput
text = "name: t\\nx0: &x0 [a,a,a,a,a,a,a,a,a,a]\\n" + "".join(
    f"x{i}: &x{i} [" + ",".join([f"*x{i - 1}"] * 10) + "]\\n" for i in range(1, 7)
) + "user_prompts: [" + ",".join(["*x6"] * 10) + "]\\n"
data = safe_load_bounded(text, max_bytes=500_000)
try:
    AssessmentInput.model_validate({"name": "t", "user_prompts": data["user_prompts"]})
except Exception as exc:
    print(type(exc).__name__)
"""


def test_yaml_alias_bomb_is_rejected_without_expanding_it() -> None:
    """Regression for Codex round-33 (2026-09-26), reproduced exactly as
    reported: round 32's early size check measured the input with
    json.dumps(), which fully expands a YAML alias bomb - a few hundred
    bytes of nested anchors that load as a small shared graph but serialize
    to ~10^8 elements - and ran out of memory (~8 s) where the pre-round-32
    code rejected the same input instantly. Run in a child process under a
    512 MiB address-space cap and a timeout, so a regression fails this
    test instead of exhausting the test runner's memory or hanging it."""
    import subprocess
    import sys
    from pathlib import Path

    result = subprocess.run(
        [sys.executable, "-c", _ALIAS_BOMB_CHILD],
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.stdout.strip() == "ValidationError", (result.stdout, result.stderr[-500:])
