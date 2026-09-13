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


def _parse_constraints(text: str) -> dict[str, str]:
    """Parse `name==version` pin lines from constraints.txt (comments and
    blank lines ignored). Keys are normalized (PyPI-style: case-insensitive,
    '_'/'.' treated as '-') so they compare correctly against installed
    distribution names regardless of which spelling either side uses."""
    pins: dict[str, str] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;]+)", line)
        if match:
            name = re.sub(r"[-_.]+", "-", match.group(1)).strip().lower()
            pins[name] = match.group(2)
    return pins


def _constraints_file_present() -> bool:
    """Codex#15 (round 8, 2026-09-12), reproduced exactly as reported:
    pyproject.toml declares only lower bounds (>=), not a reviewed lock -
    two clean installations can resolve different dependency graphs, and
    nothing before this audited a specific, reviewed one. constraints.txt
    (see its own header for how to regenerate it) is that reviewed
    baseline.

    Codex#8 (round 9, 2026-09-12), reproduced exactly as reported: this
    only ever checked the file exists and is non-empty - a stale or even
    fabricated constraints file still passed, since nothing compared it
    against what is actually installed. Every package this file pins AND
    that is currently installed must match its pinned version exactly;
    a pinned-but-not-installed package is a declared-dependency gap the
    SBOM completeness check (Codex#10, round 5 / #9, round 9) already
    catches, and an installed-but-unpinned package is not itself wrong
    (constraints.txt need not be perfectly exhaustive) - only a version
    MISMATCH for something both pinned and installed means this
    environment no longer matches the reviewed baseline it claims to."""
    from importlib import metadata

    path = ROOT / "constraints.txt"
    if not path.exists():
        print("[FAIL] constraints.txt present with pinned versions (file missing)")
        return False
    pins = _parse_constraints(path.read_text(encoding="utf-8"))
    if not pins:
        print("[FAIL] constraints.txt present with pinned versions (no pins found)")
        return False

    mismatches = []
    for name, pinned_version in sorted(pins.items()):
        try:
            installed_version = metadata.version(name)
        except metadata.PackageNotFoundError:
            continue  # not installed here - not this check's concern
        if installed_version != pinned_version:
            mismatches.append(
                f"{name}: constraints.txt says {pinned_version}, installed {installed_version}"
            )

    ok = not mismatches
    print(f"[{'ok ' if ok else 'FAIL'}] constraints.txt matches the installed environment")
    for m in mismatches:
        print(f"    {m}")
    return ok


def _constraints_pins_are_complete() -> bool:
    """Codex#9 (round 10, 2026-09-13), reproduced exactly as reported:
    `_constraints_file_present()` above confirms every PIN PRESENT matches
    what is installed, but never required every package in the project's
    actual dependency closure to have a pin at all - a constraints file
    with a single correctly-versioned pin (or none of the closure at all)
    passed that check while describing itself as a reproducible
    exact-version baseline for the whole environment.

    Reuses generate_sbom.py's own closure walk - the same one whose
    "declared and installed" completeness the `sbom` check earlier in
    `main()` already enforces with `--require-complete` - so "complete"
    here means exactly the project's real dependency set, not a second,
    independently (and possibly inconsistently) defined notion of it. Only
    closure members that are actually INSTALLED are required to have a
    pin; a closure member that is declared but not installed is the SBOM
    completeness check's concern, not this one's (constraints.txt cannot
    meaningfully pin a version nothing installed provides)."""
    from importlib import metadata

    sys.path.insert(0, str(ROOT / "scripts"))
    from generate_sbom import _dependency_closure, _normalize, declared_dependencies

    roots = {_normalize(name) for name in declared_dependencies()}
    closure = _dependency_closure(roots)

    installed_closure: set[str] = set()
    for name in closure:
        try:
            metadata.version(name)
        except metadata.PackageNotFoundError:
            continue  # declared but not installed - the SBOM check's concern
        installed_closure.add(name)

    path = ROOT / "constraints.txt"
    pins = _parse_constraints(path.read_text(encoding="utf-8")) if path.exists() else {}

    missing = sorted(installed_closure - set(pins))
    ok = not missing
    print(
        f"[{'ok ' if ok else 'FAIL'}] constraints.txt pins every installed "
        "dependency-closure package"
    )
    for name in missing:
        print(f"    missing pin: {name}")
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


def _parse_manifest_area_counts(text: str) -> dict[str, int] | None:
    """Extract the `app/` (.py), `tests/` (total files), `tests/` (Python
    test modules, from its notes column), and `root` counts from
    PUBLICATION_MANIFEST.md's "Tracked files by area" table. Returns None
    if any of the four cannot be found."""
    patterns = {
        "app_py": r"\|\s*`app/`\s*\|\s*(\d+)\s*\(\.py\)\s*\|",
        "tests_total": r"\|\s*`tests/`\s*\|\s*(\d+)\s*\|",
        "tests_modules": r"\|\s*`tests/`\s*\|\s*\d+\s*\|[^|\n]*?(\d+)\s+test modules",
        "root": r"\|\s*root\s*\|\s*(\d+)\s*\|",
    }
    counts: dict[str, int] = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, text)
        if match is None:
            return None
        counts[key] = int(match.group(1))
    return counts


def _actual_area_counts(root: Path) -> dict[str, int]:
    def _tracked(*pathspecs: str) -> list[str]:
        return subprocess.run(
            ["git", "ls-files", *pathspecs], cwd=root, capture_output=True, text=True
        ).stdout.splitlines()

    return {
        "app_py": len(_tracked("app/*.py", "app/**/*.py")),
        "tests_total": len(_tracked("tests")),
        "tests_modules": len(_tracked("tests/*.py", "tests/**/*.py")),
        "root": len([f for f in _tracked() if "/" not in f]),
    }


def _manifest_area_counts_match_reality() -> bool:
    """Codex#10 (round 10, 2026-09-13), reproduced exactly as reported: the
    "Tracked files by area" table's per-area counts (56 vs actual 58 `app/`
    files, 74/41 vs actual 76/45 `tests/` files/modules, 10 vs actual 11
    root files) are hand-maintained and drift independently of the
    header's own "Tracked files: **N**" total -
    `_publication_manifest_matches_reality()` above already keeps THAT
    total honest, but that says nothing about whether this table's
    BREAKDOWN still adds up to it correctly."""
    manifest = ROOT / "PUBLICATION_MANIFEST.md"
    if not manifest.exists():
        print("[FAIL] PUBLICATION_MANIFEST.md area-count table check (file missing)")
        return False
    claimed = _parse_manifest_area_counts(manifest.read_text(encoding="utf-8"))
    if claimed is None:
        print(
            "[FAIL] PUBLICATION_MANIFEST.md area-count table check "
            "(could not parse the 'Tracked files by area' table)"
        )
        return False
    actual = _actual_area_counts(ROOT)
    mismatches = [
        f"{key}: manifest says {claimed[key]}, actual is {actual[key]}"
        for key in sorted(claimed)
        if claimed[key] != actual[key]
    ]
    ok = not mismatches
    print(f"[{'ok ' if ok else 'FAIL'}] PUBLICATION_MANIFEST.md area-count table matches reality")
    for m in mismatches:
        print(f"    {m}")
    return ok


def _no_stale_license_undecided_text() -> bool:
    """Codex#10 (round 10, 2026-09-13), reproduced exactly as reported:
    `docs/threat-model.md` said "Project licence not yet chosen" despite
    Apache-2.0 having already been selected and LICENSE/NOTICE already
    committed (`_license_files_present()` above) - a stale residual-risk
    bullet directly contradicting the rest of the publication
    documentation."""
    stale_markers = ("licence not yet chosen", "license not yet chosen", "licence undecided")
    offenders = []
    for rel in ("docs/threat-model.md", "PUBLICATION_MANIFEST.md", "REVIEW_CHECKLIST.md"):
        path = ROOT / rel
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8").lower()
        if any(marker in text for marker in stale_markers):
            offenders.append(rel)
    ok = not offenders
    print(
        f"[{'ok ' if ok else 'FAIL'}] no stale 'licence not yet chosen' text "
        "(Apache-2.0 is selected)"
    )
    for rel in offenders:
        print(f"    {rel}")
    return ok


def _quickstart_install_command_installs_every_extra() -> bool:
    """Codex#9 (round 11, 2026-09-13), reproduced exactly as reported: the
    documented quickstart command `pip install -e ".[dev]"` does not
    install `anthropic` or `uvicorn` (the `api`/`llm` extras) - a fresh
    install following it fails this script's own SBOM completeness check
    (every declared dependency group must be installed), and does not
    apply `constraints.txt`, so it can resolve different (unreviewed)
    versions than the audited baseline. Every `pip install -e` line found
    in README.md / REVIEW_PACKAGE.md must request every optional-
    dependency group declared in pyproject.toml and pin `constraints.txt`.
    """
    import tomllib

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared_groups = set(pyproject.get("project", {}).get("optional-dependencies", {}))

    offenders = []
    for rel in ("README.md", "REVIEW_PACKAGE.md"):
        path = ROOT / rel
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if "pip install -e" not in line:
                continue
            extras_match = re.search(r'\.\[([^\]]+)\]', line)
            requested = set(extras_match.group(1).split(",")) if extras_match else set()
            missing = declared_groups - requested
            if missing or "constraints.txt" not in line:
                offenders.append(f"{rel}: {line.strip()!r} (missing: {sorted(missing)})")

    ok = not offenders
    print(f"[{'ok ' if ok else 'FAIL'}] quickstart install command installs every declared extra")
    for o in offenders:
        print(f"    {o}")
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
        _constraints_pins_are_complete(),
        _publication_manifest_matches_reality(),
        _manifest_area_counts_match_reality(),
        _no_stale_license_undecided_text(),
        _quickstart_install_command_installs_every_extra(),
    ]

    print("\nManual gates still required before publishing:")
    print("  - cross-AI review (Codex / Antigravity) per AI_RULES.md, recorded in HANDOFF.md")
    print("  - confirm no real customer / private material in any commit")

    passed = all(checks)
    print(f"\npreflight: {'PASS' if passed else 'FAIL'}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
