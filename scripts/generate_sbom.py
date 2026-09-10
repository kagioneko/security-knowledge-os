#!/usr/bin/env python3
"""Write a minimal CycloneDX SBOM (sbom.json) from the installed distributions.

  python scripts/generate_sbom.py [--out sbom.json]
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from importlib import metadata
from pathlib import Path

_ROOT_DISTS = {
    "security-knowledge-os",
    "pydantic",
    "pyyaml",
    "fastapi",
    "uvicorn",
    "anthropic",
    "httpx",
    "pytest",
    "ruff",
    "mypy",
}


# PyPI packages whose licence metadata is not machine-readable in older formats.
_KNOWN_LICENSES = {
    "pydantic": "MIT",
    "fastapi": "MIT",
    "mypy": "MIT",
    "pytest": "MIT",
    "ruff": "MIT",
    "uvicorn": "BSD-3-Clause",
    "anthropic": "MIT",
}


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
    components = []
    for dist in sorted(metadata.distributions(), key=lambda d: d.metadata["Name"].lower()):
        name = dist.metadata["Name"]
        if name.lower() not in {d.lower() for d in _ROOT_DISTS}:
            continue
        components.append(
            {
                "type": "library",
                "name": name,
                "version": dist.version,
                "purl": f"pkg:pypi/{name.lower()}@{dist.version}",
                "licenses": [{"license": {"name": _license(dist)}}],
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "timestamp": dt.datetime.now(dt.UTC).isoformat(),
            "component": {
                "type": "application",
                "name": "security-knowledge-os",
                "version": "0.1.0",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
            "tools": [{"name": "generate_sbom.py"}],
        },
        "components": components,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("sbom.json"))
    args = parser.parse_args(argv)
    args.out.write_text(json.dumps(build_sbom(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
