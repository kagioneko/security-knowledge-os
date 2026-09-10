"""M3: input normalization is deterministic and conservative."""

from __future__ import annotations

from collections.abc import Callable

from app.models.assessment import AssessmentInput
from app.models.context import CredentialStorage, ToolPermission
from app.reviewer.facts import build_facts
from app.reviewer.normalize import to_context

Loader = Callable[[str], AssessmentInput]


def test_untrusted_rag_source_marks_external_ingestion(load_assessment: Loader) -> None:
    ctx = to_context(load_assessment("V-001-indirect-injection-auto-email"))
    assert ctx.external_content_ingestion is True


def test_trusted_only_rag_is_not_external_ingestion(load_assessment: Loader) -> None:
    ctx = to_context(load_assessment("S-002-rag-trusted-no-actions"))
    assert ctx.external_content_ingestion is False


def test_disabled_memory_makes_persistence_false_not_none(load_assessment: Loader) -> None:
    ctx = to_context(load_assessment("S-001-prompt-only"))
    assert ctx.memory_persistent is False


def test_enabled_memory_without_persistence_stays_unknown(load_assessment: Loader) -> None:
    ctx = to_context(load_assessment("U-002-memory-persistence-unspecified"))
    assert ctx.memory_persistent is None


def test_unrecognised_credential_storage_is_unknown(load_assessment: Loader) -> None:
    ctx = to_context(load_assessment("U-004-credential-handling-unspecified"))
    assert ctx.credential_storage is CredentialStorage.UNKNOWN
    assert ctx.credential_exposed_to_model is None


def test_permission_aliases(load_assessment: Loader) -> None:
    ctx = to_context(load_assessment("V-001-indirect-injection-auto-email"))
    perms = {t.name: t.permission for t in ctx.tools}
    assert perms["email_send"] is ToolPermission.SEND
    assert perms["file_read"] is ToolPermission.READ


def test_missing_tool_permission_is_unknown(load_assessment: Loader) -> None:
    ctx = to_context(load_assessment("U-001-tool-permissions-missing"))
    facts = build_facts(ctx)
    assert facts["tools_with_unknown_permission"] is True
    assert facts["has_delete_tool"] is False
