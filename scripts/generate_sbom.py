#!/usr/bin/env python3
"""Write a minimal CycloneDX SBOM (sbom.json) from the installed distributions.

  python scripts/generate_sbom.py [--out sbom.json]
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import json
import os
import re
import sys
import tomllib
from importlib import metadata
from pathlib import Path

from packaging.requirements import Requirement

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

    Codex#9 (round 9, 2026-09-12), reproduced exactly as reported: the
    original `"extra ==" in req` substring test only ever handled the
    extras marker, never platform/Python-version markers (`sys_platform`,
    `platform_system`, `python_version`, ...) - the raw closure included
    inapplicable packages for this environment (`colorama` on non-Windows,
    an emscripten-only fetch shim, ...), proving markers were not actually
    evaluated. Parsing each requirement with `packaging.requirements.
    Requirement` and evaluating its marker for real (against this
    interpreter's true environment, with `extra` fixed to "") correctly
    handles every PEP 508 marker type at once, not just extras.

    Codex#6 (round 14, 2026-09-13), reproduced exactly as reported: fixing
    `extra` to `""` for EVERY requirement discards which extras a PARENT
    requirement actually activated on its dependency - `pip-audit`
    declares `CacheControl[filecache]`, requesting CacheControl's own
    "filecache" extra; CacheControl in turn declares
    `filelock ; extra == "filecache"`, applicable only when THAT extra is
    active. `req.extras` (the bracketed names on one requirement string)
    is carried forward per edge and accumulated per package (a package
    reached through two different requested extras keeps both), so a
    dependency's own conditional requirements are evaluated against every
    extra actually requested of it - not just its unconditional
    (`extra == ""`) base install - closing this for any such multi-hop
    chain, not just this one concrete case.
    """
    seen: set[str] = set()
    active_extras: dict[str, frozenset[str]] = {}
    frontier: list[tuple[str, frozenset[str]]] = [(name, frozenset()) for name in roots]
    while frontier:
        name, extras = frontier.pop()
        already_covered = extras <= active_extras.get(name, frozenset())
        if name in seen and already_covered:
            continue
        seen.add(name)
        active_extras[name] = active_extras.get(name, frozenset()) | extras
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue  # declared but not installed here - already in "missing" below
        # "" (no extra - the base install) is always active alongside
        # whatever extras were actually requested of this package.
        candidate_extras = active_extras[name] | {""}
        for req_str in dist.requires or []:
            req = Requirement(req_str)
            if req.marker is not None and not any(
                req.marker.evaluate({"extra": extra}) for extra in candidate_extras
            ):
                # not applicable to this environment/interpreter, or
                # gated behind an extra nothing in this closure requested.
                continue
            req_name = _normalize(req.name)
            frontier.append((req_name, frozenset(req.extras)))
    return seen


def _closure_by_group(declared: dict[str, str]) -> dict[str, set[str]]:
    """For every package reachable from ANY declared root, which
    declared group(s) it is reachable FROM (not just whether it is
    itself directly declared).

    Codex#9 (round 8, 2026-09-12), reproduced exactly as reported: a
    transitive-only package (never itself in pyproject.toml, e.g.
    pydantic_core, only reachable via pydantic) got `group = None` from
    `declared.get(norm)` and was therefore always marked CycloneDX scope
    "optional" - including one required at runtime through a "runtime"
    root. Walking the closure separately per declared group and taking
    the union of "which roots' closures reach this name" is what actually
    determines whether a package is required, not merely whether it
    happens to also be a *direct* pyproject.toml entry.
    """
    roots_by_group: dict[str, set[str]] = {}
    for name, group in declared.items():
        roots_by_group.setdefault(group, set()).add(name)
    reachable_from: dict[str, set[str]] = {}
    for group, roots in roots_by_group.items():
        for name in _dependency_closure(roots):
            reachable_from.setdefault(name, set()).add(group)
    return reachable_from


def build_sbom() -> dict[str, object]:
    # Codex cross-review finding #12 (2026-09-11): a hand-maintained allowlist
    # of "root" package names omitted every installed TRANSITIVE dependency
    # (pydantic-core, annotated-types, typing-extensions, typing-inspection,
    # starlette, anyio were all installed but not in the SBOM) - it drifts out
    # of sync with reality by construction. List every distribution actually
    # installed in this (dedicated project) environment instead, deduped by
    # name in case of duplicate metadata entries.
    declared = declared_dependencies()
    reachable_from = _closure_by_group(declared)
    closure = set(reachable_from)
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
        # Codex#9 (round 8, 2026-09-12): a package's effective group is
        # the union of its own direct pyproject.toml declaration (if any)
        # and every group whose closure reaches it transitively - "runtime"
        # wins if present in that union, since that is what actually makes
        # a package required, regardless of it also being e.g. a direct
        # dev-only entry.
        groups = set(reachable_from.get(norm, set()))
        if norm in declared:
            groups.add(declared[norm])
        group = "runtime" if "runtime" in groups else (min(groups) if groups else None)
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
    # Codex#9 (round 9, 2026-09-12), reproduced exactly as reported: this
    # only ever checked DIRECTLY declared roots - an applicable transitive
    # dependency that is absent from the environment (a broken/inconsistent
    # venv; pip's own resolver should prevent this in a healthy install, but
    # nothing here verified that) was silently omitted from `missing` while
    # coverage still said "complete". `closure` (built above from
    # `reachable_from`) is always a superset of `declared`'s own keys - every
    # declared root is added to a `_dependency_closure()` walk's `seen` set
    # even when it turns out to be uninstalled - so checking the closure
    # subsumes the direct-only check and adds the transitive case.
    transitively_missing = sorted(name for name in closure if name not in installed_normalized)
    coverage = (
        "complete: every declared dependency (all groups) is installed in this environment"
        if not missing and not transitively_missing
        else (
            "PARTIAL: generated from an environment missing these declared "
            f"dependencies: {', '.join(missing)} - regenerate after "
            '`pip install -e ".[llm,api,dev]"` for full release coverage'
            + (
                f"; also missing these applicable TRANSITIVE dependencies: "
                f"{', '.join(sorted(set(transitively_missing) - set(missing)))} "
                "(a broken/inconsistent environment - pip's own resolver should "
                "have installed these automatically)"
                if set(transitively_missing) - set(missing)
                else ""
            )
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
        #
        # Codex#10 (round 8, 2026-09-12), reproduced exactly as reported:
        # `Path.write_text()` opens its target the normal way, following a
        # symlink there - precreating this predictable `sbom.json.tmp.<pid>`
        # path as a symlink to an unrelated file caused this write to
        # silently overwrite that unrelated TARGET before the os.replace()
        # below ever ran. O_CREAT|O_EXCL|O_NOFOLLOW makes the open itself
        # fail (FileExistsError/ELOOP) instead of writing through anything
        # already there, symlink or otherwise.
        tmp = args.out.with_suffix(args.out.suffix + f".tmp.{os.getpid()}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(json.dumps(sbom, indent=2) + "\n")
            os.replace(tmp, args.out)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
