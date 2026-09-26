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
    monkeypatch.delenv("SKOS_RULES_ROOT", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "rules").mkdir()
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
