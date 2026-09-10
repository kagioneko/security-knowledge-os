#!/usr/bin/env python3
"""Pre-publish preflight check. Run before the first push.

  python scripts/preflight.py

Bundles: knowledge / rules / safe-test validation, secret scan, tracked-file
classification check, and a reminder of the manual gates that a script cannot do
(licence choice, cross-AI review). Exit 0 only if every automated check passes.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(name: str, cmd: list[str]) -> bool:
    result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    ok = result.returncode == 0
    print(f"[{'ok ' if ok else 'FAIL'}] {name}")
    if not ok:
        print(result.stdout.strip())
        print(result.stderr.strip())
    return ok


def _tracked_knowledge_all_public() -> bool:
    files = subprocess.run(
        ["git", "ls-files", "knowledge"], cwd=ROOT, capture_output=True, text=True
    ).stdout.splitlines()
    bad = []
    for rel in files:
        if not rel.endswith(".md") or rel.endswith("README.md"):
            continue
        text = (ROOT / rel).read_text(encoding="utf-8")
        if "classification: public" not in text:
            bad.append(rel)
    ok = not bad
    print(f"[{'ok ' if ok else 'FAIL'}] tracked knowledge/ is all classification: public")
    for rel in bad:
        print(f"    non-public: {rel}")
    return ok


def _no_private_or_secret_tracked() -> bool:
    files = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True
    ).stdout.splitlines()
    offenders = [
        f
        for f in files
        if f.startswith("secret/")
        or f == ".env"
        or (f.startswith("knowledge/private/") and not f.endswith((".gitkeep", "README.md")))
    ]
    ok = not offenders
    print(f"[{'ok ' if ok else 'FAIL'}] no secret/ , .env , or private knowledge content tracked")
    for f in offenders:
        print(f"    {f}")
    return ok


def _license_files_present() -> bool:
    ok = (ROOT / "LICENSE").exists() and (ROOT / "NOTICE").exists()
    print(f"[{'ok ' if ok else 'FAIL'}] LICENSE and NOTICE present")
    return ok


def main() -> int:
    py = sys.executable
    checks = [
        _run("pytest", [py, "-m", "pytest", "-q"]),
        _run("ruff", [py, "-m", "ruff", "check", "."]),
        _run("mypy", [py, "-m", "mypy"]),
        _run("validate-knowledge", [py, "scripts/validate_knowledge.py", "knowledge"]),
        _run("validate-rules", [py, "scripts/validate_rules.py", "rules"]),
        _run("validate-safe-tests", [py, "scripts/validate_safe_tests.py", "safe_tests"]),
        _run("secret-scan", [py, "scripts/secret_scan.py"]),
        _run("sbom", [py, "scripts/generate_sbom.py"]),
        _tracked_knowledge_all_public(),
        _no_private_or_secret_tracked(),
        _license_files_present(),
    ]

    print("\nManual gates still required before publishing:")
    print("  - cross-AI review (Codex / Antigravity) per AI_RULES.md, recorded in HANDOFF.md")
    print("  - confirm no real customer / private material in any commit")

    passed = all(checks)
    print(f"\npreflight: {'PASS' if passed else 'FAIL'}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
