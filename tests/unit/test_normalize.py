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


def test_any_named_rag_source_marks_external_ingestion(load_assessment: Loader) -> None:
    """Regression for SKOS-ADV-05 (Antigravity, round 2, 2026-09-11): a named
    source used to be checked against a fixed DENY-list of "known untrusted"
    names, so an unlisted-but-still-external source (or, as here, a source
    the fixture's author simply called "internal_docs") evaluated to False -
    fail-open. There is no schema field to positively assert a source is
    first-party/curated, so any named source now means ingestion of content
    the system did not author, regardless of what it's called."""
    ctx = to_context(load_assessment("S-002-rag-trusted-no-actions"))
    assert ctx.external_content_ingestion is True


def test_rag_enabled_with_no_named_source_is_indeterminate(load_assessment: Loader) -> None:
    from app.models.assessment import AssessmentInput, RagInput

    inp = AssessmentInput(name="t", rag=RagInput(enabled=True, sources=[]))
    ctx = to_context(inp)
    assert ctx.external_content_ingestion is None


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
