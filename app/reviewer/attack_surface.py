"""Attack Surface Extraction (spec Sections 12 step 3, 13)."""

from __future__ import annotations

from app.models.assessment import AttackSurface
from app.models.context import AssessmentContext, ToolPermission

_HIGH_IMPACT = {
    ToolPermission.WRITE,
    ToolPermission.DELETE,
    ToolPermission.SEND,
    ToolPermission.SHELL,
}


def extract_attack_surface(ctx: AssessmentContext) -> AttackSurface:
    approved = {action for action, granted in ctx.human_approval.items() if granted}
    return AttackSurface(
        input_channels=sorted(ctx.input_channels),
        external_content_sources=sorted(ctx.retrieval_sources)
        if ctx.external_content_ingestion
        else [],
        retrieval_sources=sorted(ctx.retrieval_sources),
        tools=sorted(t.name for t in ctx.tools),
        tool_permissions={t.name: t.permission.value for t in ctx.tools},
        memory_scope=ctx.memory_scope.value,
        persistence=ctx.memory_persistent,
        outbound_channels=sorted(ctx.outbound_destinations or []),
        credentials=[ctx.credential_storage.value],
        human_approval_points=sorted(approved),
        high_impact_actions=sorted(
            [f"tool:{t.name}" for t in ctx.tools if t.permission in _HIGH_IMPACT]
            + (["outbound_send"] if ctx.outbound_enabled else [])
        ),
    )
