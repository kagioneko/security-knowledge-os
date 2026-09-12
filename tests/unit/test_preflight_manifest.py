"""scripts/preflight.py: PUBLICATION_MANIFEST.md consistency check.

Codex#9 (round 5, 2026-09-12): PUBLICATION_MANIFEST.md is hand-edited and
drifts from the real tracked-file / test counts as soon as another commit
lands. Only the pure text-parsing half is unit-tested here
(`_parse_manifest_claims`) - the subprocess-driven "gather actual counts"
half (`_actual_tracked_files_and_tests`) is exercised end-to-end whenever
`scripts/preflight.py` itself is run, the same way the rest of that script
is (it has no other unit tests either).
"""

from __future__ import annotations

import scripts.preflight as preflight


def test_parses_the_claimed_counts() -> None:
    text = "- Tracked files: **199**\n- Tests: **371** items (370 pass, 1 skip = JA-R02)\n"
    assert preflight._parse_manifest_claims(text) == (199, 371)


def test_returns_none_when_the_tracked_files_line_is_missing() -> None:
    text = "- Tests: **371** items (370 pass, 1 skip)\n"
    assert preflight._parse_manifest_claims(text) is None


def test_returns_none_when_the_tests_line_is_missing() -> None:
    text = "- Tracked files: **199**\n"
    assert preflight._parse_manifest_claims(text) is None


def test_real_manifest_file_is_parseable() -> None:
    """Regardless of whether the numbers are currently stale, the manifest
    committed in this repo must always be in the parseable shape this check
    depends on."""
    manifest = preflight.ROOT / "PUBLICATION_MANIFEST.md"
    claimed = preflight._parse_manifest_claims(manifest.read_text(encoding="utf-8"))
    assert claimed is not None
    files, tests = claimed
    assert files > 0
    assert tests > 0


def test_parses_the_claimed_commit() -> None:
    text = "- Commit: `823c5e4` (round-5 cross-review findings addressed, **not yet pushed**)\n"
    assert preflight._parse_manifest_commit(text) == "823c5e4"


def test_returns_none_when_the_commit_line_is_missing() -> None:
    assert preflight._parse_manifest_commit("- Tracked files: **199**\n") is None


def test_parses_the_claimed_component_count() -> None:
    """Regression for Codex#9 (round 8, 2026-09-12), reproduced exactly as
    reported: the tracked sbom.json had 62 components while the manifest's
    own "Dependencies" section said 29 - only the tracked-files/tests
    counts were kept in sync by an automated check, not this one."""
    text = "## Dependencies (`sbom.json`)\n\n29 components — every distribution actually\n"
    assert preflight._parse_manifest_component_count(text) == 29


def test_disagreeing_component_count_statements_are_treated_as_unparseable() -> None:
    """Regression for Codex#13 (round 9, 2026-09-12), reproduced exactly as
    reported: the manifest states the component count TWICE ("62
    components — ..." and, later, "None of the 29 components conflict
    with ...") - matching only the FIRST occurrence missed that the
    second one had drifted independently. Every occurrence must agree."""
    text = (
        "62 components — the project's actual dependency closure.\n"
        "...\n"
        "None of the 29 components conflict with Apache-2.0.\n"
    )
    assert preflight._parse_manifest_component_count(text) is None


def test_returns_none_when_the_component_count_line_is_missing() -> None:
    assert preflight._parse_manifest_component_count("- Tracked files: **199**\n") is None


def test_real_manifest_component_count_line_is_parseable() -> None:
    manifest = preflight.ROOT / "PUBLICATION_MANIFEST.md"
    count = preflight._parse_manifest_component_count(manifest.read_text(encoding="utf-8"))
    assert count is not None and count > 0


def test_constraints_file_is_present_and_non_empty() -> None:
    """Regression for Codex#15 (round 8, 2026-09-12), reproduced exactly as
    reported: pyproject.toml declares only lower bounds - two clean
    installations can resolve different dependency graphs, and nothing
    audited a specific, reviewed one. constraints.txt is that reviewed
    baseline; this checks preflight actually looks for it."""
    assert preflight._constraints_file_present() is True


def test_constraints_check_fails_when_the_file_is_only_comments(
    tmp_path, monkeypatch
) -> None:
    (tmp_path / "constraints.txt").write_text("# nothing pinned yet\n", encoding="utf-8")
    monkeypatch.setattr(preflight, "ROOT", tmp_path)
    assert preflight._constraints_file_present() is False


def test_head_itself_is_a_known_ancestor_of_head() -> None:
    import subprocess

    head = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=preflight.ROOT,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert preflight._commit_is_known_ancestor_of_head(preflight.ROOT, head)


def test_an_unknown_commit_hash_is_rejected() -> None:
    """Regression for Codex#10 (round 6, 2026-09-12): the manifest's commit
    line was never checked against the actual repository history at all -
    a typo'd or stale hash from an unrelated line of work went unnoticed."""
    assert not preflight._commit_is_known_ancestor_of_head(
        preflight.ROOT, "0000000000000000000000000000000000000000"
    )


def test_real_manifest_commit_is_a_known_ancestor_of_head() -> None:
    manifest = preflight.ROOT / "PUBLICATION_MANIFEST.md"
    commit = preflight._parse_manifest_commit(manifest.read_text(encoding="utf-8"))
    assert commit is not None
    assert preflight._commit_is_known_ancestor_of_head(preflight.ROOT, commit)
