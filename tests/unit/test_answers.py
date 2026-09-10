"""M6.1: typed AnswerPatch, nested application, full re-evaluation."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from pydantic import ValidationError

from app.models.answer import AnswerPatch
from app.models.assessment import AssessmentInput, OverallStatus
from app.reviewer.answers import AnswerValidationError, apply_patch
from app.reviewer.assess import assess
from app.reviewer.rule_loader import RuleCatalogue

Loader = Callable[[str], AssessmentInput]


# --------------------------------------------------------------------------- #
# schema-level rejection
# --------------------------------------------------------------------------- #
def test_unknown_field_is_rejected() -> None:
    with pytest.raises(ValidationError):
        AnswerPatch.model_validate({"memory_persistant": True})  # typo


def test_type_mismatch_is_rejected() -> None:
    with pytest.raises(ValidationError):
        AnswerPatch.model_validate({"memory_persistent": "maybe"})
    with pytest.raises(ValidationError):
        AnswerPatch.model_validate({"memory_scope": "forever"})
    with pytest.raises(ValidationError):
        AnswerPatch.model_validate({"credential_storage": "hardcoded"})
    with pytest.raises(ValidationError):
        AnswerPatch.model_validate({"tool_permissions": {"t": "superuser"}})


def test_no_raw_secret_field_exists() -> None:
    banned = ("key", "secret", "token", "password", "credential_value")
    for name in AnswerPatch.model_fields:
        assert not any(b in name for b in banned), name


def test_allow_list_of_fields() -> None:
    assert set(AnswerPatch.model_fields) == {
        "system_prompt",
        "developer_prompt",
        "rag_enabled",
        "rag_sources",
        "memory_enabled",
        "memory_persistent",
        "memory_scope",
        "outbound_enabled",
        "outbound_destinations",
        "credential_storage",
        "credential_exposed_to_model",
        "tool_permissions",
        "human_approval",
    }


# --------------------------------------------------------------------------- #
# apply_patch
# --------------------------------------------------------------------------- #
def test_nested_fields_are_applied(load_assessment: Loader) -> None:
    original = load_assessment("U-002-memory-persistence-unspecified")
    patched = apply_patch(
        original, AnswerPatch(memory_persistent=True, memory_scope="user")
    )
    assert patched.memory.persistent is True
    assert patched.memory.scope == "user"
    # untouched fields are preserved
    assert patched.rag.sources == original.rag.sources


def test_credential_exposed_bool_becomes_string(load_assessment: Loader) -> None:
    patched = apply_patch(
        load_assessment("U-004-credential-handling-unspecified"),
        AnswerPatch(credential_storage="proxy", credential_exposed_to_model=False),
    )
    assert patched.credentials.storage == "proxy"
    assert patched.credentials.exposed_to_model == "false"


def test_unknown_tool_is_rejected(load_assessment: Loader) -> None:
    with pytest.raises(AnswerValidationError, match="unknown tool"):
        apply_patch(
            load_assessment("U-001-tool-permissions-missing"),
            AnswerPatch(tool_permissions={"ghost_tool": "read"}),
        )


def test_known_tool_permission_is_applied(load_assessment: Loader) -> None:
    patched = apply_patch(
        load_assessment("U-001-tool-permissions-missing"),
        AnswerPatch(tool_permissions={"mystery_tool": "read"}),
    )
    assert patched.tools[0].permissions == "read"


def test_unknown_approval_action_is_rejected(load_assessment: Loader) -> None:
    with pytest.raises(AnswerValidationError, match="unknown approval action"):
        apply_patch(
            load_assessment("V-002-rag-delete-tool-no-approval"),
            AnswerPatch(human_approval={"launch_missiles": True}),
        )


# --------------------------------------------------------------------------- #
# UNKNOWN -> answer -> full re-evaluation
# --------------------------------------------------------------------------- #
def test_unknown_resolves_to_a_definite_verdict_after_answer(
    load_assessment: Loader, catalogue: RuleCatalogue
) -> None:
    original = load_assessment("U-002-memory-persistence-unspecified")
    before = assess(original, catalogue)
    assert before.overall_status is OverallStatus.UNKNOWN

    yes = assess(apply_patch(original, AnswerPatch(memory_persistent=True)), catalogue)
    assert yes.overall_status is OverallStatus.CONDITIONAL  # MEM-001 now WARN
    assert not any(f.status.value == "UNKNOWN" for f in yes.findings if f.risk_id == "MEM-001")

    no = assess(apply_patch(original, AnswerPatch(memory_persistent=False)), catalogue)
    assert no.overall_status is OverallStatus.PASS  # MEM-001 not applicable


def test_reevaluation_replaces_findings_not_edits_them(
    load_assessment: Loader, catalogue: RuleCatalogue
) -> None:
    original = load_assessment("U-001-tool-permissions-missing")
    answered = assess(
        apply_patch(original, AnswerPatch(tool_permissions={"mystery_tool": "delete"})),
        catalogue,
    )
    # a fresh assessment: mystery_tool is now a delete tool with no approval
    assert any(f.risk_id == "TOOL-001" and f.status.value == "FAIL" for f in answered.findings)
    assert not any(f.risk_id == "TOOL-000" for f in answered.findings)
