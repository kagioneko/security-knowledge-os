#!/usr/bin/env python3
"""Write a minimal CycloneDX SBOM (sbom.json) from the installed distributions.

  python scripts/generate_sbom.py [--out sbom.json]
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import tomllib
from importlib import metadata
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")

# PyPI packages whose licence metadata is not machine-readable in older formats.
_KNOWN_LICENSES = {
    "pydantic": "MIT",
    "fastapi": "MIT",
    "mypy": "MIT",
    "pytest": "MIT",
    "ruff": "MIT",
    "uvicorn": "BSD-3-Clause",
    "anthropic": "MIT",
    "pathspec": "MPL-2.0",
}


def _normalize(name: str) -> str:
    """PyPI-style name comparison: case-insensitive, '_'/'.' == '-'."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def _requirement_name(spec: str) -> str:
    """A PEP 508 requirement string's bare package name, e.g.
    'fastapi>=0.132' -> 'fastapi'."""
    match = _NAME_RE.match(spec.strip())
    return _normalize(match.group(0) if match else spec)


def declared_dependencies() -> dict[str, str]:
    """Codex#10 (round 5, 2026-09-12): every package pyproject.toml
    declares, mapped to the dependency group it is declared under
    ('runtime', an extras name such as 'api'/'llm'/'dev', or 'build' for
    the build backend). The SBOM only ever lists what is *installed* in
    THIS generation environment - a base `pip install -e .` and
    `pip install -e ".[llm,api,dev]"` legitimately produce different SBOMs
    - so a declared-but-not-installed package is expected, not a defect,
    and must be disclosed (build_sbom()'s `skos:sbom-coverage` property)
    rather than silently absent with no way to tell the two cases apart.
    """
    data = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared: dict[str, str] = {}
    for spec in data.get("build-system", {}).get("requires", []):
        declared[_requirement_name(spec)] = "build"
    project = data.get("project", {})
    for spec in project.get("dependencies", []):
        declared[_requirement_name(spec)] = "runtime"
    for group, specs in project.get("optional-dependencies", {}).items():
        for spec in specs:
            declared.setdefault(_requirement_name(spec), group)
    return declared


def _license(dist: metadata.Distribution) -> str:
    meta = dist.metadata
    expr = str(meta.get("License-Expression") or "").strip()
    if expr:
        return expr
    lic = str(meta.get("License") or "").strip()
    if lic and lic.lower() not in {"unknown", "", "license"} and len(lic) < 60:
        return lic.splitlines()[0]
    for classifier in meta.get_all("Classifier") or []:
        text = str(classifier)
        if text.startswith("License :: ") and "OSI Approved" not in text:
            return text.split(" :: ")[-1]
    return _KNOWN_LICENSES.get(str(meta["Name"]).lower(), "UNKNOWN")


def build_sbom() -> dict[str, object]:
    # Codex cross-review finding #12 (2026-09-11): a hand-maintained allowlist
    # of "root" package names omitted every installed TRANSITIVE dependency
    # (pydantic-core, annotated-types, typing-extensions, typing-inspection,
    # starlette, anyio were all installed but not in the SBOM) - it drifts out
    # of sync with reality by construction. List every distribution actually
    # installed in this (dedicated project) environment instead, deduped by
    # name in case of duplicate metadata entries.
    declared = declared_dependencies()
    seen: set[str] = set()
    installed_normalized: set[str] = set()
    components = []
    for dist in sorted(metadata.distributions(), key=lambda d: d.metadata["Name"].lower()):
        name = dist.metadata["Name"]
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        norm = _normalize(name)
        installed_normalized.add(norm)
        group = declared.get(norm)
        component: dict[str, object] = {
            "type": "library",
            "name": name,
            "version": dist.version,
            "purl": f"pkg:pypi/{name.lower()}@{dist.version}",
            "licenses": [{"license": {"name": _license(dist)}}],
            # Codex#10 (round 5, 2026-09-12): CycloneDX 1.5's binary scope -
            # "required" for the sole runtime dependency group, "optional"
            # for every extras/dev/build group (and for anything not
            # declared in pyproject.toml at all, i.e. a transitive-only
            # package).
            "scope": "required" if group == "runtime" else "optional",
        }
        if group is not None:
            # the finer-grained declared group, beyond CycloneDX's binary
            # scope - a supported extensible "properties" entry, not a
            # fabricated schema field.
            component["properties"] = [{"name": "skos:dependency-group", "value": group}]
        components.append(component)

    # Codex#10 (round 5, 2026-09-12): the SBOM only ever lists what is
    # INSTALLED in this generation environment - a base `pip install -e .`
    # and `pip install -e ".[llm,api,dev]"` legitimately produce different,
    # both-correct SBOMs. Recording which declared groups are fully covered
    # here (and which are not, by name) turns "this SBOM silently omits
    # anthropic/uvicorn" into an explicit, machine-readable statement of
    # what this particular SBOM does and does not claim to cover, instead
    # of looking identical to a full-closure release SBOM either way.
    missing = sorted(name for name, group in declared.items() if name not in installed_normalized)
    coverage = (
        "complete: every declared dependency (all groups) is installed in this environment"
        if not missing
        else (
            "PARTIAL: generated from an environment missing these declared "
            f"dependencies: {', '.join(missing)} - regenerate after "
            '`pip install -e ".[llm,api,dev]"` for full release coverage'
        )
    )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        # Codex cross-review finding #9 (round 2, 2026-09-11): the CycloneDX
        # 1.5 schema requires this top-level integer field (the BOM's own
        # serial/edition number, not a dependency version); a schema-
        # validating consumer could reject the whole document without it,
        # despite preflight reporting success.
        "version": 1,
        "metadata": {
            "timestamp": dt.datetime.now(dt.UTC).isoformat(),
            "component": {
                "type": "application",
                "name": "security-knowledge-os",
                "version": "0.1.0",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
            "tools": [{"name": "generate_sbom.py"}],
            "properties": [{"name": "skos:sbom-coverage", "value": coverage}],
        },
        "components": components,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("sbom.json"))
    args = parser.parse_args(argv)
    sbom = build_sbom()
    args.out.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out}")
    for prop in sbom["metadata"]["properties"]:  # type: ignore[index]
        if prop["name"] == "skos:sbom-coverage":
            print(prop["value"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
