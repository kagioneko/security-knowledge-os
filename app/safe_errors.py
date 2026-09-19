"""Render pydantic validation errors without echoing the rejected input.

Codex#1 (round 22, 2026-09-19), reproduced exactly as reported: the
credential validators reject a recognised secret, but pydantic keeps the
rejected value in the error (`input`, and `ctx` for value errors). FastAPI's
default 422 handler returns that verbatim, and the CLI paths printed
``str(ValidationError)``, which includes it too - so a real credential
submitted by mistake still ended up in HTTP-client, terminal, CI, or wrapper
logs.

Codex#2 (round 23, 2026-09-20), reproduced exactly as reported: the first
fix still treated `loc` as trusted. It is not - pydantic puts attacker-
supplied property names and mapping keys in it (`{"AKIA...": 1}` ->
`loc: ["body", "AKIA..."]`). A location component is therefore only
rendered when it is an index, a fixed framework label, or a field name that
one of this project's own models declares; anything else becomes
`<redacted>`. The failure mode of the allowlist is a less specific message,
never a leak.
"""

from __future__ import annotations

import functools
import importlib
import inspect
import pkgutil
from collections.abc import Iterable, Mapping
from typing import Any

from pydantic import BaseModel, ValidationError

_SAFE_KEYS = ("type", "loc", "msg")
_FRAMEWORK_LOC_LABELS = frozenset({"body", "query", "path", "header", "cookie", "[key]"})
_REDACTED = "<redacted>"


@functools.cache
def _declared_field_names() -> frozenset[str]:
    """Every field name (and alias) declared by a model in `app.models`.
    Imported lazily: `app.models` does not import this module, but doing it
    at module scope would make any future import of this from a model
    a cycle."""
    import app.models as models_pkg

    names: set[str] = set()
    for info in pkgutil.iter_modules(models_pkg.__path__):
        module = importlib.import_module(f"{models_pkg.__name__}.{info.name}")
        for _, cls in inspect.getmembers(module, inspect.isclass):
            if issubclass(cls, BaseModel) and cls is not BaseModel:
                for field_name, field in cls.model_fields.items():
                    names.add(field_name)
                    if isinstance(field.alias, str):
                        names.add(field.alias)
    return frozenset(names)


def safe_loc(loc: Iterable[Any]) -> list[Any]:
    known = _declared_field_names()
    return [
        part
        if isinstance(part, int)
        or (isinstance(part, str) and (part in _FRAMEWORK_LOC_LABELS or part in known))
        else _REDACTED
        for part in loc
    ]


def format_loc(loc: Iterable[Any]) -> str:
    return ".".join(str(part) for part in safe_loc(loc)) or "<root>"


def sanitize_errors(errors: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Keep only `type`/`loc`/`msg` of each error - an allowlist, so any key a
    future pydantic release adds (as `input` and `ctx` once were) is dropped
    by default instead of leaking by default."""
    return [
        {key: safe_loc(err[key]) if key == "loc" else err[key] for key in _SAFE_KEYS if key in err}
        for err in errors
    ]


def format_validation_error(exc: ValidationError) -> str:
    """One `loc: msg` line per error, for CLI stderr and loader messages."""
    lines = [
        f"{format_loc(err.get('loc', ()))}: {err.get('msg', 'invalid value')}"
        for err in sanitize_errors(exc.errors(include_input=False, include_url=False))
    ]
    return "; ".join(lines) or "validation failed"
