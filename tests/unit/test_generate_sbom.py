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

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from generate_sbom import build_sbom, declared_dependencies, main  # noqa: E402


def test_sbom_includes_transitive_dependencies() -> None:
    sbom = build_sbom()
    names = {c["name"].lower() for c in sbom["components"]}
    installed = {d.metadata["Name"].lower() for d in metadata.distributions()}
    # every distribution actually installed in this environment must appear -
    # nothing silently dropped by a hardcoded allowlist
    assert installed <= names


def test_sbom_has_no_duplicate_components() -> None:
    sbom = build_sbom()
    names = [c["name"].lower() for c in sbom["components"]]
    assert len(names) == len(set(names))


def test_sbom_components_have_a_version_and_license() -> None:
    sbom = build_sbom()
    for c in sbom["components"]:
        assert c["version"]
        assert c["licenses"][0]["license"].get("name") or c["licenses"][0]["license"].get("id")


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
