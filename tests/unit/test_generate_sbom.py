"""scripts/generate_sbom.py.

Regression for Codex cross-review finding #12 (2026-09-11): a hand-maintained
allowlist of "root" package names omitted every installed transitive
dependency (pydantic-core, annotated-types, typing-extensions,
typing-inspection, starlette, anyio were all installed but not listed).
"""

from __future__ import annotations

import sys
from importlib import metadata
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from generate_sbom import build_sbom, declared_dependencies, main  # noqa: E402


def test_sbom_includes_transitive_dependencies() -> None:
    """Codex#9 (round 7, 2026-09-12) narrowed this from "every installed
    distribution" to "the project's actual dependency closure" -
    `security-knowledge-os` (the project's own component, not a dependency
    of itself) is excluded intentionally. `_dependency_closure()` skips
    every requirement gated behind ANY optional extra as an approximation
    (it does not track which specific extra a dependent actually selected,
    e.g. pip-audit legitimately selects CacheControl's own `filecache`
    extra, pulling in `filelock` for real - a full PEP 508 marker
    evaluator would be needed to distinguish that from mypy's unrelated,
    unselected `install-types` extra, which also happens to depend on
    `pip`). This under-inclusion on dev-tool-only edge cases is an
    accepted, documented trade-off; everything else genuinely reachable
    must still appear - nothing silently dropped by a hardcoded allowlist
    (the original, round-2 finding #12 concern)."""
    sbom = build_sbom()
    names = {c["name"].lower() for c in sbom["components"]}
    installed = {d.metadata["Name"].lower() for d in metadata.distributions()}
    missing = installed - names
    assert missing <= {"security-knowledge-os", "filelock"}


def test_sbom_has_no_duplicate_components() -> None:
    sbom = build_sbom()
    names = [c["name"].lower() for c in sbom["components"]]
    assert len(names) == len(set(names))


def test_sbom_components_have_a_version_and_license() -> None:
    sbom = build_sbom()
    for c in sbom["components"]:
        assert c["version"]
        assert c["licenses"][0]["license"].get("name") or c["licenses"][0]["license"].get("id")


def test_no_unknown_licences_for_a_real_specific_osi_classifier() -> None:
    """Regression for Codex#9 (round 7, 2026-09-12), reproduced exactly as
    reported: `"OSI Approved" not in text` excluded every classifier that
    names a *specific* OSI-approved license too, since almost all of them
    read "License :: OSI Approved :: <name>" and legitimately contain that
    substring - trove-classifiers (Apache-licensed, no License-Expression/
    License header, only this classifier) resolved to UNKNOWN instead of
    "Apache Software License"."""
    sbom = build_sbom()
    by_name = {c["name"].lower(): c for c in sbom["components"]}
    assert "trove-classifiers" in by_name, "test assumption: still an installed dependency"
    licence = by_name["trove-classifiers"]["licenses"][0]["license"]
    assert licence.get("name") == "Apache Software License"


def test_sbom_excludes_the_projects_own_component() -> None:
    """Regression for Codex#9 (round 7, 2026-09-12), reproduced exactly as
    reported: the generator inventoried every installed distribution -
    including the project's own component - rather than computing the
    project's actual dependency closure (the project is not a dependency
    of itself)."""
    sbom = build_sbom()
    names = {c["name"].lower() for c in sbom["components"]}
    assert "security-knowledge-os" not in names


def test_dependency_closure_skips_a_requirement_gated_by_an_unselected_extra() -> None:
    """Regression for Codex#9 (round 7, 2026-09-12), reproduced exactly as
    reported: `mypy`'s own `install-types` extra optionally depends on
    `pip` - installing plain `mypy` (no extras selected) does not pull
    `pip` in for real, so it must not appear in the closure just because
    mypy's metadata MENTIONS it."""
    import generate_sbom as sbom_module

    closure = sbom_module._dependency_closure({"mypy"})
    assert "mypy" in closure
    assert "pip" not in closure


def test_dependency_closure_includes_a_dependency_activated_through_a_requested_extra() -> None:
    """Regression for Codex#6 (round 14, 2026-09-13), reproduced exactly as
    reported: `pip-audit` declares `CacheControl[filecache]`, requesting
    CacheControl's own "filecache" extra; CacheControl in turn declares
    `filelock ; extra == "filecache"`. Fixing `extra` to `""` for EVERY
    requirement (the round-9 fix above) discarded which extras a PARENT
    requirement had actually requested, so `filelock` (installed and
    genuinely required through that one selected extra) was invisible to
    the closure and absent from sbom.json, even though the SBOM claimed
    completeness. This is the finding's own exact repro, against the real
    installed environment."""
    import generate_sbom as sbom_module

    closure = sbom_module._dependency_closure({"pip-audit"})
    assert "cachecontrol" in closure, "test assumption: still an installed dependency"
    assert "filelock" in closure


def test_dependency_closure_reprocesses_a_package_once_a_later_edge_requests_an_extra() -> None:
    """Synthetic, fully-controlled version of the test above - independent
    of pip-audit's real dependency graph ever changing upstream, and
    covering an ordering edge case: `root_a` requires plain `dep` (no
    extras); `root_b` requires `dep[an_extra]`. `dep`'s own
    `activated-by-extra ; extra == "an_extra"` requirement must end up
    considered reachable regardless of which root's edge to `dep` the BFS
    happens to process first - a package already marked `seen` (from an
    earlier, extra-less visit) must still be RE-processed once a new
    extra is learned for it, not skipped as already-visited."""
    import importlib.metadata as importlib_metadata
    import unittest.mock as mock

    import generate_sbom as sbom_module

    class _RootA:
        requires = ["dep"]
        metadata = {"Name": "root-a"}
        version = "0.0.0"

    class _RootB:
        requires = ["dep[an_extra]"]
        metadata = {"Name": "root-b"}
        version = "0.0.0"

    class _Dep:
        requires = ['activated-by-extra ; extra == "an_extra"']
        metadata = {"Name": "dep"}
        version = "0.0.0"

    class _Leaf:
        requires: list[str] = []
        metadata = {"Name": "leaf"}
        version = "0.0.0"

    fakes = {"root-a": _RootA(), "root-b": _RootB(), "dep": _Dep()}
    real_distribution = importlib_metadata.distribution

    def fake_distribution(name: str) -> object:
        if name in fakes:
            return fakes[name]
        if name == "activated-by-extra":
            return _Leaf()
        return real_distribution(name)

    with mock.patch.object(importlib_metadata, "distribution", side_effect=fake_distribution):
        closure = sbom_module._dependency_closure({"root-a", "root-b"})

    assert closure == {"root-a", "root-b", "dep", "activated-by-extra"}


def test_dependency_closure_skips_a_platform_inapplicable_requirement() -> None:
    """Regression for Codex#9 (round 9, 2026-09-12), reproduced exactly as
    reported: the old `"extra ==" in req` substring test only ever handled
    the extras marker - `httpx2`'s own `httpx2-jsfetch; sys_platform ==
    "emscripten" and python_version >= "3.12"` requirement has nothing to
    do with extras, so it was never evaluated at all and was always
    treated as applicable, even on a platform (Linux, here) it plainly
    is not for."""
    import generate_sbom as sbom_module

    closure = sbom_module._dependency_closure({"httpx2"})
    assert "httpx2" in closure, "test assumption: still an installed dependency"
    assert "httpx2-jsfetch" not in closure


def test_build_sbom_flags_an_applicable_missing_transitive_dependency() -> None:
    """Regression for Codex#9 (round 9, 2026-09-12), reproduced exactly as
    reported: `missing` only ever checked DIRECTLY declared roots - an
    applicable transitive dependency absent from the environment was
    silently omitted from `missing` while coverage still said "complete".
    Mocking an installed declared root whose metadata requires an absent,
    unconditional package simulates exactly that."""
    import importlib.metadata as importlib_metadata

    import generate_sbom as sbom_module

    class _FakeDistribution:
        requires = ["definitely-not-installed-anywhere-xyz"]
        metadata = {"Name": "pydantic"}
        version = "0.0.0"

    real_distribution = importlib_metadata.distribution

    def fake_distribution(name: str) -> object:
        if name == "pydantic":
            return _FakeDistribution()
        return real_distribution(name)

    import unittest.mock as mock

    with mock.patch.object(importlib_metadata, "distribution", side_effect=fake_distribution):
        sbom = sbom_module.build_sbom()

    coverage = next(
        p["value"] for p in sbom["metadata"]["properties"] if p["name"] == "skos:sbom-coverage"
    )
    assert coverage.startswith("PARTIAL")
    assert "definitely-not-installed-anywhere-xyz" in coverage
    assert "TRANSITIVE" in coverage


def test_declared_dependencies_covers_every_pyproject_group() -> None:
    """Regression for Codex#10 (round 5, 2026-09-12): pyproject.toml declares
    anthropic/uvicorn/hatchling, none of which appeared in the SBOM (only
    what happened to be installed in this particular dev environment)."""
    declared = declared_dependencies()
    assert declared["pydantic"] == "runtime"
    assert declared["pyyaml"] == "runtime"
    assert declared["anthropic"] == "llm"
    assert declared["uvicorn"] == "api"
    assert declared["hatchling"] == "build"
    assert declared["pytest"] == "dev"


def test_sbom_flags_a_declared_dependency_missing_from_this_environment() -> None:
    """Regression for Codex#10 (round 5, 2026-09-12), reproduced exactly as
    reported: `anthropic`/`uvicorn` are declared in pyproject.toml but not
    installed in this (base, no extras) dev environment, and the generated
    sbom.json said nothing about it - a declared-but-uninstalled dependency
    looked identical to a full-closure release SBOM. The coverage property
    must name what is missing instead of silently omitting it."""
    sbom = build_sbom()
    coverage = next(
        p["value"] for p in sbom["metadata"]["properties"] if p["name"] == "skos:sbom-coverage"
    )
    installed = {d.metadata["Name"].lower() for d in metadata.distributions()}
    if "anthropic" not in installed:
        assert "anthropic" in coverage
    if "uvicorn" not in installed:
        assert "uvicorn" in coverage


def test_a_transitive_only_package_required_at_runtime_is_marked_required() -> None:
    """Regression for Codex#9 (round 8, 2026-09-12), reproduced exactly as
    reported: a transitive-only package (never itself a direct
    pyproject.toml entry, e.g. pydantic_core - only reachable via
    pydantic) got `group = declared.get(norm)` = None and was therefore
    always marked CycloneDX scope "optional", even though it is required
    at runtime through pydantic (a "runtime" root)."""
    by_name = {c["name"].lower(): c for c in build_sbom()["components"]}
    assert "pydantic_core" in by_name, "test assumption: still an installed dependency"
    assert by_name["pydantic_core"]["scope"] == "required"
    assert by_name["pydantic_core"]["properties"] == [
        {"name": "skos:dependency-group", "value": "runtime"}
    ]


def test_sbom_components_are_tagged_with_their_declared_scope_and_group() -> None:
    by_name = {c["name"].lower(): c for c in build_sbom()["components"]}
    assert by_name["pydantic"]["scope"] == "required"
    assert by_name["pydantic"]["properties"] == [
        {"name": "skos:dependency-group", "value": "runtime"}
    ]
    assert by_name["pytest"]["scope"] == "optional"
    assert by_name["pytest"]["properties"] == [{"name": "skos:dependency-group", "value": "dev"}]


def test_require_complete_fails_when_coverage_is_partial(
    tmp_path, monkeypatch, capsys
) -> None:
    """Regression for Codex#8 (round 6, 2026-09-12), reproduced exactly as
    reported: generate_sbom.py overwrote sbom.json and exited 0 even when
    the committed coverage property said PARTIAL - preflight invoked it
    plainly and treated that as a passing check. --require-complete must
    make the generator itself refuse."""
    import generate_sbom as sbom_module

    original = sbom_module.declared_dependencies

    def _with_a_missing_package():
        declared = dict(original())
        declared["definitely-not-installed-anywhere"] = "runtime"
        return declared

    monkeypatch.setattr(sbom_module, "declared_dependencies", _with_a_missing_package)

    exit_code = main(["--out", str(tmp_path / "sbom.json"), "--require-complete"])
    assert exit_code == 1
    assert "PARTIAL" in capsys.readouterr().out


def test_require_complete_never_overwrites_a_previously_valid_sbom(
    tmp_path, monkeypatch
) -> None:
    """Regression for Codex#8 (round 7, 2026-09-12), reproduced exactly as
    reported: the output was written BEFORE incomplete coverage was
    rejected, so a failing --require-complete run could overwrite a
    previously valid, complete sbom.json with a new, partial one."""
    import generate_sbom as sbom_module

    out = tmp_path / "sbom.json"
    out.write_text('{"victim": true}', encoding="utf-8")

    original = sbom_module.declared_dependencies

    def _with_a_missing_package():
        declared = dict(original())
        declared["definitely-not-installed-anywhere"] = "runtime"
        return declared

    monkeypatch.setattr(sbom_module, "declared_dependencies", _with_a_missing_package)

    exit_code = main(["--out", str(out), "--require-complete"])
    assert exit_code == 1
    assert out.read_text(encoding="utf-8") == '{"victim": true}'  # untouched
    assert list(tmp_path.glob("sbom.json.tmp.*")) == []  # no stray temp file left behind


def test_main_rejects_a_precreated_symlinked_temp_path(tmp_path) -> None:
    """Regression for Codex#10 (round 8, 2026-09-12), reproduced exactly as
    reported: `Path.write_text()` on the temp path follows a symlink
    planted there - precreating the predictable `sbom.json.tmp.<pid>` path
    as a symlink to an unrelated file caused the write to silently
    overwrite that unrelated TARGET before the atomic os.replace() ran."""
    import os

    out = tmp_path / "sbom.json"
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_text("not an sbom", encoding="utf-8")
    tmp_for_pid = out.with_suffix(out.suffix + f".tmp.{os.getpid()}")
    tmp_for_pid.symlink_to(unrelated)

    with pytest.raises(OSError):
        main(["--out", str(out)])

    assert unrelated.read_text(encoding="utf-8") == "not an sbom", "symlink TARGET must be intact"
    assert not out.exists()


def test_check_mode_does_not_write_the_output_file(tmp_path) -> None:
    out = tmp_path / "sbom.json"
    exit_code = main(["--out", str(out), "--check"])
    assert exit_code == 0
    assert not out.exists()


def test_sbom_has_the_schema_required_top_level_version() -> None:
    """Regression for Codex cross-review finding #9 (round 2, 2026-09-11): the
    CycloneDX 1.5 schema requires a top-level integer 'version' field (the
    BOM's own edition number). It was missing; a schema-validating consumer
    could reject the document despite preflight reporting success."""
    sbom = build_sbom()
    assert sbom.get("version") == 1
    assert isinstance(sbom["version"], int)
