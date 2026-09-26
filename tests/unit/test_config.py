"""Data-root resolution, incl. the packaged fallback used by pip installs."""

from __future__ import annotations

from pathlib import Path

import pytest

import app.config as config
from app.config import _root_default


def test_env_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SKOS_RULES_ROOT", "/custom/rules")
    assert _root_default("rules", "SKOS_RULES_ROOT") == "/custom/rules"


def test_cwd_dir_preferred_over_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Both a cwd dir AND a bundle exist: the cwd (source checkout) must win.
    monkeypatch.delenv("SKOS_RULES_ROOT", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "rules").mkdir()
    bundled = tmp_path / "_bundled"
    (bundled / "rules").mkdir(parents=True)
    monkeypatch.setattr(config, "_BUNDLED", bundled)
    assert _root_default("rules", "SKOS_RULES_ROOT") == "rules"


def test_bundled_fallback_when_no_cwd_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression for the pip-install case (2026-09-26): with no same-named
    dir in the current directory, the packaged copy shipped in the wheel is
    used, so `skos assess` works without a source checkout."""
    monkeypatch.delenv("SKOS_RULES_ROOT", raising=False)
    monkeypatch.chdir(tmp_path)  # no ./rules here
    bundled = tmp_path / "_bundled"
    (bundled / "rules").mkdir(parents=True)
    monkeypatch.setattr(config, "_BUNDLED", bundled)
    assert _root_default("rules", "SKOS_RULES_ROOT") == str(bundled / "rules")


def test_bare_name_when_nothing_exists(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SKOS_RULES_ROOT", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(config, "_BUNDLED", tmp_path / "nonexistent")
    assert _root_default("rules", "SKOS_RULES_ROOT") == "rules"


# The ONLY directories that may be force-included into the public wheel.
# An allowlist, not a denylist: a new bundled tree is rejected until it is
# added here on purpose (Codex round-36, 2026-09-26).
_ALLOWED_BUNDLE_ROOTS = {"rules", "knowledge/public", "safe_tests"}
_ALLOWED_DATA_EXT = {".yaml", ".yml", ".md"}
_FORBIDDEN_SEGMENTS = {"private", "internal", "confidential", "secret"}


def test_bundled_source_is_publishable() -> None:
    """Regression for Codex round-35/36 (2026-09-26): hatchling force-include
    copies a directory recursively and ignores .gitignore/exclude, so anything
    left in a bundled tree ships in the PUBLIC wheel. Guard, as an allowlist:
    only _ALLOWED_BUNDLE_ROOTS may be bundled, and every path element (the
    force-include root included, directories included) must avoid a
    private/internal segment or a hidden name, contain no symlink, and every
    file must be a data type."""
    import os
    import tomllib

    repo = Path(__file__).resolve().parents[2]
    cfg = tomllib.loads((repo / "pyproject.toml").read_text(encoding="utf-8"))
    bundled = cfg["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    assert bundled, "no force-include entries found"

    # Every bundled root must be explicitly allowlisted (catches a future
    # `knowledge/private` entry that per-file checks below would not see).
    assert set(bundled) <= _ALLOWED_BUNDLE_ROOTS, (
        f"force-include has non-allowlisted roots: {set(bundled) - _ALLOWED_BUNDLE_ROOTS}"
    )

    def bad_segment(seg: str) -> bool:
        return seg in _FORBIDDEN_SEGMENTS or (seg.startswith(".") and seg != ".gitkeep")

    problems: list[str] = []
    for src in bundled:
        # Check the force-include root's own path segments too (e.g. a
        # `knowledge/private` root, or a hidden component in the src path).
        for seg in Path(src).parts:
            if bad_segment(seg):
                problems.append(f"{src}: forbidden path segment '{seg}'")
        root = repo / src
        assert root.is_dir() and not root.is_symlink(), f"bundled source missing/symlink: {src}"
        # os.walk with followlinks=False so symlinked dirs are not descended,
        # and every dir/file name is inspected (a hidden dir like `.internal`
        # is not silently skipped).
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            here = Path(dirpath)
            for seg in here.relative_to(root).parts:
                if bad_segment(seg):
                    problems.append(f"{here.relative_to(repo).as_posix()}: forbidden dir '{seg}'")
            for name in dirnames + filenames:
                p = here / name
                rel = p.relative_to(repo).as_posix()
                if p.is_symlink():
                    problems.append(f"{rel}: symlink not allowed in bundled data")
                if bad_segment(name):
                    problems.append(f"{rel}: forbidden/hidden name")
                if name in filenames and name != ".gitkeep" and p.suffix not in _ALLOWED_DATA_EXT:
                    problems.append(f"{rel}: unexpected file type '{p.suffix}'")
    assert not problems, "non-publishable files in bundled data:\n" + "\n".join(
        sorted(set(problems))
    )


def test_empty_or_whitespace_env_falls_through(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An empty or whitespace-only env var must not count as an explicit
    override; it falls through to the cwd/bundle/bare resolution."""
    monkeypatch.chdir(tmp_path)  # no ./rules
    monkeypatch.setattr(config, "_BUNDLED", tmp_path / "nope")
    for val in ("", "   "):
        monkeypatch.setenv("SKOS_RULES_ROOT", val)
        assert _root_default("rules", "SKOS_RULES_ROOT") == "rules"
