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
from generate_sbom import build_sbom  # noqa: E402


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


def test_sbom_has_the_schema_required_top_level_version() -> None:
    """Regression for Codex cross-review finding #9 (round 2, 2026-09-11): the
    CycloneDX 1.5 schema requires a top-level integer 'version' field (the
    BOM's own edition number). It was missing; a schema-validating consumer
    could reject the document despite preflight reporting success."""
    sbom = build_sbom()
    assert sbom.get("version") == 1
    assert isinstance(sbom["version"], int)
