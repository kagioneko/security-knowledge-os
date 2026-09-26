"""Data-root resolution, incl. the packaged fallback used by pip installs."""

from __future__ import annotations

from collections.abc import Iterable
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


def _bad_segment(seg: str) -> bool:
    return seg in _FORBIDDEN_SEGMENTS or (seg.startswith(".") and seg != ".gitkeep")


def _bundled_publishability_problems(repo: Path, bundled: Iterable[str]) -> list[str]:
    """Return why the force-included trees are not publish-safe (empty = clean).

    Every force-include tree that ships in the PUBLIC wheel is checked: only
    allowlisted roots, no private/internal/hidden path segment anywhere (the
    src root and every directory included), no symlink at any level - including
    an ancestor of the root, e.g. a `knowledge` symlink pointing outside the
    repo (Codex round-37) - and every file a data type."""
    import os

    problems: list[str] = []
    for src in bundled:
        for seg in Path(src).parts:
            if _bad_segment(seg):
                problems.append(f"{src}: forbidden path segment '{seg}'")
        # Reject a symlink at ANY ancestor from repo down to the root, so a
        # `repo/knowledge -> /outside` link cannot smuggle in outside content
        # via an otherwise-normal-looking `knowledge/public`.
        cur = repo
        for seg in Path(src).parts:
            cur = cur / seg
            if cur.is_symlink():
                problems.append(
                    f"{src}: ancestor '{cur.relative_to(repo).as_posix()}' is a symlink"
                )
        root = repo / src
        if not root.is_dir():
            problems.append(f"{src}: missing")
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            here = Path(dirpath)
            for seg in here.relative_to(root).parts:
                if _bad_segment(seg):
                    problems.append(f"{here.relative_to(repo).as_posix()}: forbidden dir '{seg}'")
            for name in dirnames + filenames:
                p = here / name
                rel = p.relative_to(repo).as_posix()
                if p.is_symlink():
                    problems.append(f"{rel}: symlink not allowed in bundled data")
                if _bad_segment(name):
                    problems.append(f"{rel}: forbidden/hidden name")
                if name in filenames and name != ".gitkeep" and p.suffix not in _ALLOWED_DATA_EXT:
                    problems.append(f"{rel}: unexpected file type '{p.suffix}'")
    return sorted(set(problems))


def _force_include_roots(repo: Path) -> dict[str, str]:
    import tomllib

    cfg = tomllib.loads((repo / "pyproject.toml").read_text(encoding="utf-8"))
    roots = cfg["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    assert isinstance(roots, dict)
    return roots


def test_bundled_source_is_publishable() -> None:
    """The real force-included trees ship nothing private/internal in the wheel."""
    repo = Path(__file__).resolve().parents[2]
    bundled = _force_include_roots(repo)
    assert bundled, "no force-include entries found"
    roots = set(bundled)
    assert roots <= _ALLOWED_BUNDLE_ROOTS, (
        f"force-include has non-allowlisted roots: {roots - _ALLOWED_BUNDLE_ROOTS}"
    )
    problems = _bundled_publishability_problems(repo, bundled)
    assert not problems, "non-publishable files in bundled data:\n" + "\n".join(problems)


def test_guard_rejects_a_symlinked_ancestor(tmp_path: Path) -> None:
    """Codex round-37 (2026-09-26): a symlinked ANCESTOR of the bundle root
    (repo/knowledge -> outside) must be rejected, not just the root itself."""
    outside = tmp_path / "outside"
    (outside / "public").mkdir(parents=True)
    (outside / "public" / "leak.md").write_text("internal", encoding="utf-8")
    (tmp_path / "knowledge").symlink_to(outside, target_is_directory=True)
    problems = _bundled_publishability_problems(tmp_path, ["knowledge/public"])
    assert any("symlink" in p for p in problems), problems


def test_guard_rejects_private_hidden_symlink_and_bad_type(tmp_path: Path) -> None:
    """Negative cases for the per-tree checks."""
    rules = tmp_path / "rules"
    (rules / "private").mkdir(parents=True)
    (rules / "private" / "memo.md").write_text("x", encoding="utf-8")  # forbidden dir
    (rules / ".internal").mkdir()  # hidden dir
    (rules / ".internal" / "note.md").write_text("x", encoding="utf-8")
    (rules / "script.py").write_text("x", encoding="utf-8")  # non-data type
    target = tmp_path / "elsewhere.md"
    target.write_text("x", encoding="utf-8")
    (rules / "link.md").symlink_to(target)  # symlinked file
    problems = _bundled_publishability_problems(tmp_path, ["rules"])
    joined = "\n".join(problems)
    assert "private" in joined and ".internal" in joined
    assert "script.py" in joined and "symlink" in joined


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
