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


def test_bundled_source_is_publishable() -> None:
    """Regression for Codex round-35 (2026-09-26): force-include copies a
    directory recursively and ignores .gitignore/exclude, so a private/internal
    path, a stray dotfile, or a non-data file left in a bundled tree would ship
    in the public wheel. Read the exact force-include list from pyproject and
    fail if any bundled source tree is not publish-clean."""
    import tomllib

    repo = Path(__file__).resolve().parents[2]
    cfg = tomllib.loads((repo / "pyproject.toml").read_text(encoding="utf-8"))
    bundled = cfg["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    assert bundled, "no force-include entries found"

    allowed_ext = {".yaml", ".yml", ".md"}
    forbidden_segments = {"private", "internal", "confidential", "secret"}
    problems: list[str] = []
    for src in bundled:  # e.g. "rules", "knowledge/public", "safe_tests"
        root = repo / src
        assert root.is_dir(), f"bundled source missing: {src}"
        for f in root.rglob("*"):
            if f.is_dir():
                continue
            rel = f.relative_to(repo).as_posix()
            parts = set(f.relative_to(root).parts)
            if parts & forbidden_segments:
                problems.append(f"{rel}: private/internal path")
            if f.name == ".gitkeep":
                continue
            if f.name.startswith("."):
                problems.append(f"{rel}: stray dotfile")
            elif f.suffix not in allowed_ext:
                problems.append(f"{rel}: unexpected file type '{f.suffix}'")
    assert not problems, "non-publishable files in bundled data:\n" + "\n".join(problems)
