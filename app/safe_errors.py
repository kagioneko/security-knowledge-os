"""Render pydantic validation errors without echoing the rejected input.

Codex#1 (round 22, 2026-09-19), reproduced exactly as reported: the
credential validators reject a recognised secret, but pydantic keeps the
rejected value in the error (`input`, and `ctx` for value errors). FastAPI's
default 422 handler returns that verbatim, and the CLI paths printed
``str(ValidationError)``, which includes it too - so a real credential
submitted by mistake still ended up in HTTP-client, terminal, CI, or wrapper
logs. Only where the problem is (`loc`), what kind it is (`type`) and the
fixed message (`msg`) are safe to surface.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from pydantic import ValidationError

_SAFE_KEYS = ("type", "loc", "msg")


def sanitize_errors(errors: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Keep only `type`/`loc`/`msg` of each error - an allowlist, so any key a
    future pydantic release adds (as `input` and `ctx` once were) is dropped
    by default instead of leaking by default."""
    return [
        {
            key: list(err[key]) if key == "loc" else err[key]
            for key in _SAFE_KEYS
            if key in err
        }
        for err in errors
    ]


def format_validation_error(exc: ValidationError) -> str:
    """One `loc: msg` line per error, for CLI stderr."""
    lines = []
    for err in sanitize_errors(exc.errors(include_input=False, include_url=False)):
        loc = ".".join(str(part) for part in err.get("loc", ())) or "<root>"
        lines.append(f"{loc}: {err.get('msg', 'invalid value')}")
    return "; ".join(lines) or "validation failed"
