#!/usr/bin/env python3
"""Pre-publish preflight check. Run before the first push.

  python scripts/preflight.py

Bundles: knowledge / rules / safe-test validation, secret scan, tracked-file
classification check, and a reminder of the manual gates that a script cannot do
(licence choice, cross-AI review). Exit 0 only if every automated check passes.
"""

from __future__ import annotations

import json
import re
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


def _constraints_file_present() -> bool:
    """Codex#15 (round 8, 2026-09-12), reproduced exactly as reported:
    pyproject.toml declares only lower bounds (>=), not a reviewed lock -
    two clean installations can resolve different dependency graphs, and
    nothing before this audited a specific, reviewed one.
    constraints.txt (see its own header for how to regenerate it) is that
    reviewed baseline; this only checks it exists and is non-empty, not
    that it is currently up to date with what is installed - regenerating
    it is a deliberate, reviewed action, not something to infer here."""
    path = ROOT / "constraints.txt"
    ok = path.exists() and any(
        line.strip() and not line.lstrip().startswith("#")
        for line in path.read_text(encoding="utf-8").splitlines()
    )
    print(f"[{'ok ' if ok else 'FAIL'}] constraints.txt present with pinned versions")
    return ok


def _parse_manifest_claims(text: str) -> tuple[int, int] | None:
    """Extract the `(tracked files, tests)` counts PUBLICATION_MANIFEST.md
    claims for itself, from its "Tracked files: **N**" / "Tests: **N**
    items" lines. Returns None if either line is missing/unparseable."""
    claimed_files_match = re.search(r"Tracked files:\s*\*\*(\d+)\*\*", text)
    claimed_tests_match = re.search(r"Tests:\s*\*\*(\d+)\*\*\s*items", text)
    if claimed_files_match is None or claimed_tests_match is None:
        return None
    return int(claimed_files_match.group(1)), int(claimed_tests_match.group(1))


def _parse_manifest_component_count(text: str) -> int | None:
    """Extract the SBOM component count PUBLICATION_MANIFEST.md's own
    "## Dependencies" section claims. Returns None if no "N components"
    statement is present, OR if more than one such statement is present
    and they disagree with each other.

    Codex#9 (round 8, 2026-09-12), reproduced exactly as reported: the
    tracked sbom.json had 62 components while the manifest's own
    "Dependencies" section said 29 - the tracked-files/tests counts above
    (Codex#9, round 5) were kept in sync, but nothing checked this third,
    independently-drifting number the same way.

    Codex#13 (round 9, 2026-09-12), reproduced exactly as reported: the
    manifest states the component count TWICE ("62 components — ..." and,
    later, "None of the 29 components conflict with ...") - the first fix
    above only matched the FIRST occurrence, at the start of a line, so it
    missed that the second one had drifted independently. Every "N
    components" occurrence anywhere in the text is now checked for
    agreement, not only the first one found.
    """
    matches = [int(m.group(1)) for m in re.finditer(r"(\d+)\s+components\b", text)]
    if not matches or len(set(matches)) > 1:
        return None
    return matches[0]


def _parse_manifest_commit(text: str) -> str | None:
    """Extract the short commit hash from PUBLICATION_MANIFEST.md's
    "Commit: `<hash>`" line. Returns None if that line is missing."""
    match = re.search(r"^-\s*Commit:\s*`([0-9a-f]{4,40})`", text, re.MULTILINE)
    return match.group(1) if match else None


def _commit_is_known_ancestor_of_head(root: Path, commit: str) -> bool:
    """Codex#10 (round 6, 2026-09-12), reproduced exactly as reported: the
    manifest named a commit that was neither HEAD nor found by
    inspection - preflight validated only the file/test counts (Codex#9,
    round 5), never that the referenced commit is even a real ancestor of
    the current branch. `git merge-base --is-ancestor` also fails on a
    hash that does not resolve to any commit at all (a typo, or one from
    an unrelated line of work), not just a genuinely unrelated one.
    Deliberately does NOT require an exact match with HEAD: the manifest
    documents "the commit whose CODE was actually audited", and every
    commit that updates the manifest's own numbers is, by construction,
    one commit ahead of whatever it names - see PUBLICATION_MANIFEST.md's
    own cross-AI-review section for why this is the accepted lifecycle,
    not drift.
    """
    return (
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", commit, "HEAD"],
            cwd=root,
            capture_output=True,
        ).returncode
        == 0
    )


def _actual_tracked_files_and_tests(root: Path) -> tuple[int, int]:
    actual_files = len(
        subprocess.run(
            ["git", "ls-files"], cwd=root, capture_output=True, text=True
        ).stdout.splitlines()
    )
    collect = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--collect-only"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    collected_match = re.search(r"^(\d+) tests? collected", collect.stdout, re.MULTILINE)
    actual_tests = int(collected_match.group(1)) if collected_match else -1
    return actual_files, actual_tests


def _publication_manifest_matches_reality() -> bool:
    """Codex#9 (round 5, 2026-09-12), reproduced exactly as reported:
    PUBLICATION_MANIFEST.md is hand-edited and drifts from the real
    tracked-file / test counts the moment another commit lands after it was
    last written (the audited commit had 200 tracked files / 393 tests
    against a manifest still claiming 199 / 371). A stale manifest is
    exactly the kind of publication-review claim that should fail loudly,
    not silently mislead whoever reads it before pushing. Regenerate the
    manifest's "Tracked files" / "Tests" lines to match reality, then rerun
    preflight, before actually publishing.
    """
    manifest = ROOT / "PUBLICATION_MANIFEST.md"
    if not manifest.exists():
        print("[FAIL] PUBLICATION_MANIFEST.md consistency check (file missing)")
        return False

    claimed = _parse_manifest_claims(manifest.read_text(encoding="utf-8"))
    if claimed is None:
        print(
            "[FAIL] PUBLICATION_MANIFEST.md consistency check "
            "(could not find 'Tracked files: **N**' / 'Tests: **N** items' lines)"
        )
        return False
    claimed_files, claimed_tests = claimed
    actual_files, actual_tests = _actual_tracked_files_and_tests(ROOT)
    counts_ok = claimed_files == actual_files and claimed_tests == actual_tests

    manifest_text = manifest.read_text(encoding="utf-8")
    claimed_components = _parse_manifest_component_count(manifest_text)
    sbom_path = ROOT / "sbom.json"
    actual_components = (
        len(json.loads(sbom_path.read_text(encoding="utf-8")).get("components", []))
        if sbom_path.exists()
        else None
    )
    components_ok = (
        claimed_components is not None
        and actual_components is not None
        and claimed_components == actual_components
    )

    manifest_commit = _parse_manifest_commit(manifest_text)
    commit_ok = manifest_commit is not None and _commit_is_known_ancestor_of_head(
        ROOT, manifest_commit
    )

    ok = counts_ok and components_ok and commit_ok
    print(f"[{'ok ' if ok else 'FAIL'}] PUBLICATION_MANIFEST.md matches reality")
    if not counts_ok:
        print(f"    tracked files: manifest says {claimed_files}, actual {actual_files}")
        print(f"    tests        : manifest says {claimed_tests}, actual {actual_tests}")
    if not components_ok:
        print(
            f"    sbom components: manifest says {claimed_components}, "
            f"actual {actual_components}"
        )
    if not commit_ok:
        print(
            f"    commit: manifest says `{manifest_commit}`, which is not a known "
            "ancestor of HEAD (missing, or from an unrelated line of work)"
        )
    if not ok:
        print("    regenerate PUBLICATION_MANIFEST.md before publishing")
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
        # Codex#8 (round 6, 2026-09-12): this used to invoke the generator
        # plainly - it overwrites sbom.json and exits 0 even when coverage
        # is PARTIAL, so a partial SBOM was written AND reported as a
        # passing preflight check. --require-complete makes generate_sbom.py
        # itself refuse (see scripts/generate_sbom.py::main()).
        #
        # Codex#10 (round 7, 2026-09-12): runs BEFORE secret-scan now -
        # secret-scan reads the CURRENT on-disk sbom.json, so running it
        # first would scan yesterday's content and never see what this
        # regeneration just wrote.
        _run("sbom", [py, "scripts/generate_sbom.py", "--require-complete"]),
        _run("secret-scan", [py, "scripts/secret_scan.py"]),
        # Codex#13 (round 7, 2026-09-12): "automated OSV/pip-audit
        # scanning" - queries the OSV database for every installed
        # distribution in this environment. Requires network access and
        # the `pip-audit` dev dependency; needs `pip install -e ".[dev]"`.
        _run("pip-audit", [py, "-m", "pip_audit", "--progress-spinner", "off"]),
        _tracked_knowledge_all_public(),
        _no_private_or_secret_tracked(),
        _license_files_present(),
        _constraints_file_present(),
        _publication_manifest_matches_reality(),
    ]

    print("\nManual gates still required before publishing:")
    print("  - cross-AI review (Codex / Antigravity) per AI_RULES.md, recorded in HANDOFF.md")
    print("  - confirm no real customer / private material in any commit")

    passed = all(checks)
    print(f"\npreflight: {'PASS' if passed else 'FAIL'}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
