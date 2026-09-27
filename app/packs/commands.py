"""Run a pack's own CLI command (``skos <pack> <command> ...``).

This is the ONLY place pack code is executed, and never on the assessment
path. The code is imported from the pack's verified snapshot (the copy whose
every file hash was just checked against the signed/enabled manifest), under
its own package name, via an explicit file location - never through a
``sys.path`` search, so nothing else on the path can stand in for it.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path

from app.packs.loader import PackState, PackStatus


class PackCommandError(Exception):
    """The command cannot be run."""


def _inside(path: str | None, root: Path) -> bool:
    if path is None:
        return False
    try:
        Path(path).resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def run_command(status: PackStatus, command: str, argv: list[str]) -> int:
    manifest = status.manifest
    if status.state is not PackState.ACTIVE or manifest is None or status.snapshot is None:
        raise PackCommandError(f"pack {status.label!r} is not active: {status.reason}")
    target = manifest.commands.get(command)
    if target is None:
        available = ", ".join(sorted(manifest.commands)) or "none"
        raise PackCommandError(
            f"pack {manifest.name!r} has no command {command!r} (available: {available})"
        )
    module_name, func_name = target.split(":")
    package = manifest.package
    root = status.snapshot
    init = root / "__init__.py"
    if not init.is_file():
        raise PackCommandError(f"pack {manifest.name!r} ships commands but no __init__.py")

    existing = sys.modules.get(package)
    if existing is not None and not _inside(getattr(existing, "__file__", None), root):
        raise PackCommandError(f"a different module named {package!r} is already imported")
    if existing is None:
        spec = importlib.util.spec_from_file_location(
            package, init, submodule_search_locations=[str(root)]
        )
        if spec is None or spec.loader is None:  # pragma: no cover - defensive
            raise PackCommandError(f"cannot load package {package!r}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[package] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            del sys.modules[package]
            raise

    module = importlib.import_module(module_name)
    if not _inside(getattr(module, "__file__", None), root):
        raise PackCommandError(f"{module_name!r} did not resolve inside the verified pack")
    func = getattr(module, func_name, None)
    if not callable(func):
        raise PackCommandError(f"{target!r} is not callable")
    result = func(argv)
    return int(result) if isinstance(result, int) else 0
