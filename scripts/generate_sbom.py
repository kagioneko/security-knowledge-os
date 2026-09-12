#!/usr/bin/env python3
"""Write a minimal CycloneDX SBOM (sbom.json) from the installed distributions.

  python scripts/generate_sbom.py [--out sbom.json]
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
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
        # Codex#9 (round 7, 2026-09-12), reproduced exactly as reported:
        # `"OSI Approved" not in text` excluded every classifier that names
        # a *specific* OSI-approved license too, since almost all of them
        # read "License :: OSI Approved :: <name>" and legitimately contain
        # that substring - "License :: OSI Approved :: Apache Software
        # License" was skipped entirely instead of yielding "Apache
        # Software License". The intent was only to skip the bare, two-part
        # "License :: OSI Approved" classifier (no specific name attached);
        # requiring at least 3 " :: "-separated parts does that correctly.
        parts = text.split(" :: ")
        if text.startswith("License :: ") and len(parts) >= 3:
            return parts[-1]
    return _KNOWN_LICENSES.get(str(meta["Name"]).lower(), "UNKNOWN")


def _dependency_closure(roots: set[str]) -> set[str]:
    """BFS over each installed distribution's own ``requires()``, starting
    from `roots` (normalized package names), returning every name
    transitively reachable from them.

    Codex#9 (round 7, 2026-09-12), reproduced exactly as reported: the SBOM
    used to inventory EVERY installed distribution - `pip`, unrelated
    environment packages, and the project's own component included -
    rather than the project's actual dependency closure. "Complete" (the
    coverage property above) only ever meant "every directly-declared
    package is installed", never "this list is exactly what the project
    depends on". Walking outward from the declared roots (round 5, Codex#10)
    keeps the round-2 fix's goal (never hand-maintain a drifting allowlist -
    Codex cross-review finding #12) while excluding whatever else happens
    to be installed in this venv for unrelated reasons.
    """
    seen: set[str] = set()
    frontier = set(roots)
    while frontier:
        name = frontier.pop()
        if name in seen:
            continue
        seen.add(name)
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue  # declared but not installed here - already in "missing" below
        for req in dist.requires or []:
            if "extra ==" in req or "extra==" in req:
                # gated behind one of THAT package's own optional extras
                # (e.g. mypy's `pip; extra == "install-types"`) - we never
                # select extras when installing a transitive dependency, so
                # walking into these pulls in packages nothing in this
                # project's closure actually needs (Codex#9's own repro).
                continue
            req_name = _requirement_name(req)
            if req_name not in seen:
                frontier.add(req_name)
    return seen


def build_sbom() -> dict[str, object]:
    # Codex cross-review finding #12 (2026-09-11): a hand-maintained allowlist
    # of "root" package names omitted every installed TRANSITIVE dependency
    # (pydantic-core, annotated-types, typing-extensions, typing-inspection,
    # starlette, anyio were all installed but not in the SBOM) - it drifts out
    # of sync with reality by construction. List every distribution actually
    # installed in this (dedicated project) environment instead, deduped by
    # name in case of duplicate metadata entries.
    declared = declared_dependencies()
    closure = _dependency_closure(set(declared))
    seen: set[str] = set()
    installed_normalized: set[str] = set()
    components = []
    for dist in sorted(metadata.distributions(), key=lambda d: d.metadata["Name"].lower()):
        name = dist.metadata["Name"]
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        if _normalize(name) not in closure:
            # not reachable from anything this project declares - pip, a
            # stray dev tool, or similar environment noise (Codex#9).
            continue
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
    parser.add_argument(
        "--check",
        action="store_true",
        help="build and report coverage without writing --out (non-mutating)",
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help=(
            "exit non-zero if any package declared in pyproject.toml (any "
            "group) is not installed in this environment - use in CI/preflight "
            "so a partial-coverage SBOM fails loudly instead of being written "
            "and reported as a passing check (Codex#8, round 6, 2026-09-12)"
        ),
    )
    args = parser.parse_args(argv)
    sbom = build_sbom()
    coverage = next(
        p["value"] for p in sbom["metadata"]["properties"] if p["name"] == "skos:sbom-coverage"  # type: ignore[index]
    )
    print(coverage)

    # Codex#8 (round 7, 2026-09-12), reproduced exactly as reported:
    # completeness used to be decided AFTER the output was already written,
    # so a failing `--require-complete` run could overwrite a previously
    # valid, complete sbom.json with a new, partial one before ever
    # reporting failure. Decide first; only write if not rejected.
    if args.require_complete and coverage.startswith("PARTIAL"):
        print(
            "refusing: --require-complete was set and coverage is not complete",
            file=sys.stderr,
        )
        return 1

    if not args.check:
        # Codex#8 (round 7, 2026-09-12): write atomically (temp file + one
        # os.replace) so a crash or a concurrent reader never observes a
        # half-written sbom.json.
        tmp = args.out.with_suffix(args.out.suffix + f".tmp.{os.getpid()}")
        tmp.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, args.out)
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
