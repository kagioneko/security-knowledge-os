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


def test_no_dedicated_raw_secret_field_exists() -> None:
    """Only checks field NAMES - AnswerPatch has no field dedicated to
    holding a credential value. This does NOT mean arbitrary secret-shaped
    text is rejected; see the test immediately below (Codex#12, round 7,
    2026-09-12)."""
    banned = ("key", "secret", "token", "password", "credential_value")
    for name in AnswerPatch.model_fields:
        assert not any(b in name for b in banned), name


def test_free_text_fields_accept_a_raw_secret_this_is_a_known_limitation() -> None:
    """Regression for Codex#12 (round 7, 2026-09-12), reproduced exactly as
    reported: `test_no_dedicated_raw_secret_field_exists` above checks only
    field names - that is a stronger claim than the schema provides.
    Every free-text field here accepts arbitrary text, including a value
    that happens to look like a credential; nothing in this schema detects
    or redacts one. This test documents that limitation explicitly rather
    than leaving it implicit."""
    patch = AnswerPatch.model_validate(
        {
            "system_prompt": "arbitrary-free-text-value-12345",
            "rag_sources": ["arbitrary-free-text-value-12345"],
            "tool_permissions": {"arbitrary-free-text-value-12345": "read"},
        }
    )
    assert patch.system_prompt == "arbitrary-free-text-value-12345"
    assert patch.rag_sources == ["arbitrary-free-text-value-12345"]
    assert patch.tool_permissions == {"arbitrary-free-text-value-12345": "read"}


def test_list_elements_and_mapping_keys_are_length_bounded() -> None:
    """Regression for Codex#12 (round 7, 2026-09-12), reproduced exactly as
    reported: rag_sources/outbound_destinations capped the number of
    entries but not each entry's length; tool_permissions/human_approval
    capped the number of keys but not each key's length."""
    with pytest.raises(ValidationError):
        AnswerPatch.model_validate({"rag_sources": ["x" * 501]})
    with pytest.raises(ValidationError):
        AnswerPatch.model_validate({"outbound_destinations": ["x" * 501]})
    with pytest.raises(ValidationError):
        AnswerPatch.model_validate({"tool_permissions": {"x" * 501: "read"}})
    with pytest.raises(ValidationError):
        AnswerPatch.model_validate({"human_approval": {"x" * 501: True}})


def test_assessment_input_rejects_an_oversized_total_payload() -> None:
    """Regression for Codex cross-review finding #3 (round 3, 2026-09-12),
    reproduced exactly as reported: every individual field bound
    (user_prompts item <= 50,000 chars, <= 200 items) is satisfied, but the
    combination serializes to ~10 MB - AssessmentInput had no bound on the
    total request size, only on each field in isolation."""
    with pytest.raises(ValidationError):
        AssessmentInput(name="size", user_prompts=["x" * 50_000] * 200)


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


def test_existing_tool_permission_is_replaced(load_assessment: Loader) -> None:
    patched = apply_patch(
        load_assessment("U-001-tool-permissions-missing"),
        AnswerPatch(tool_permissions={"mystery_tool": "read"}),
    )
    assert len(patched.tools) == 1
    assert patched.tools[0].name == "mystery_tool"
    assert patched.tools[0].permissions == "read"


def test_new_tool_name_is_added_to_the_assessment(load_assessment: Loader) -> None:
    # a diagnosed system can have any tool name; a new name adds the tool
    original = load_assessment("S-001-prompt-only")
    assert original.tools == []
    patched = apply_patch(original, AnswerPatch(tool_permissions={"db_wipe": "delete"}))
    assert [t.name for t in patched.tools] == ["db_wipe"]
    assert patched.tools[0].permissions == "delete"


def test_bad_permission_value_is_rejected() -> None:
    with pytest.raises(ValidationError):
        AnswerPatch.model_validate({"tool_permissions": {"t": "root"}})


def test_oversized_single_field_is_rejected_by_the_patch_schema_itself() -> None:
    """Regression for Codex cross-review finding #6 (round 3, 2026-09-12):
    AnswerPatch had none of AssessmentInput's field-level bounds, so an
    oversized single field passed this schema untouched (and only failed
    later, inside apply_patch)."""
    with pytest.raises(ValidationError):
        AnswerPatch.model_validate({"system_prompt": "x" * 50_001})
    with pytest.raises(ValidationError):
        AnswerPatch.model_validate({"rag_sources": ["s"] * 201})


def test_merge_exceeding_assessment_bounds_is_a_clean_answer_validation_error(
    load_assessment: Loader,
) -> None:
    """Regression for Codex cross-review finding #6, part 2 (round 3,
    2026-09-12), reproduced exactly as reported: a patch that adds new tool
    names can push the MERGED `tools` list over AssessmentInput's max_length
    even when the patch itself is small and individually within bounds.
    apply_patch() used to let pydantic's ValidationError escape uncaught here
    - the API layer only catches AnswerValidationError - turning this into an
    HTTP 500 instead of the controlled rejection every other bad patch in
    this module produces."""
    original = load_assessment("S-001-prompt-only")
    original = AssessmentInput.model_validate(
        original.model_dump()
        | {
            "tools": [
                {"name": f"tool-{i}", "permissions": "read", "requires_approval": None}
                for i in range(199)
            ]
        }
    )
    patch = AnswerPatch(tool_permissions={"new-tool-a": "read", "new-tool-b": "read"})
    with pytest.raises(AnswerValidationError):
        apply_patch(original, patch)


def test_arbitrary_approval_action_is_merged(load_assessment: Loader) -> None:
    patched = apply_patch(
        load_assessment("V-002-rag-delete-tool-no-approval"),
        AnswerPatch(human_approval={"doc_delete": True}),
    )
    assert patched.human_approval == {"doc_delete": True}


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
