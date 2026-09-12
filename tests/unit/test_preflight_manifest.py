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


def test_parses_name_equals_version_pins_ignoring_comments_and_markers() -> None:
    text = (
        "# a header comment\n"
        "\n"
        "pydantic==2.13.5\n"
        "Some_Weird.Name==1.0  # trailing comment\n"
        "typing-extensions==4.16.0; python_version < '3.13'\n"
    )
    assert preflight._parse_constraints(text) == {
        "pydantic": "2.13.5",
        "some-weird-name": "1.0",
        "typing-extensions": "4.16.0",
    }


def test_constraints_check_fails_on_a_version_mismatch_with_the_installed_environment(
    tmp_path, monkeypatch
) -> None:
    """Regression for Codex#8 (round 9, 2026-09-12), reproduced exactly as
    reported: preflight only checked that constraints.txt exists and is
    non-empty - a stale or even fabricated constraints file still passed,
    since nothing compared it against what is actually installed."""
    import importlib.metadata as importlib_metadata

    real_pydantic_version = importlib_metadata.version("pydantic")
    fake_version = f"{real_pydantic_version}.does-not-exist"
    (tmp_path / "constraints.txt").write_text(f"pydantic=={fake_version}\n", encoding="utf-8")
    monkeypatch.setattr(preflight, "ROOT", tmp_path)

    assert preflight._constraints_file_present() is False


def test_constraints_check_ignores_a_pin_for_something_not_installed(
    tmp_path, monkeypatch
) -> None:
    (tmp_path / "constraints.txt").write_text(
        "definitely-not-installed-anywhere==1.0\n", encoding="utf-8"
    )
    monkeypatch.setattr(preflight, "ROOT", tmp_path)
    assert preflight._constraints_file_present() is True


def test_constraints_pins_are_complete_for_the_real_project() -> None:
    """Sanity: the committed constraints.txt is currently complete (see
    _constraints_pins_are_complete()'s own comment) - this checks preflight
    actually looks for completeness, not just consistency."""
    assert preflight._constraints_pins_are_complete() is True


def test_constraints_completeness_catches_an_incomplete_file(tmp_path, monkeypatch) -> None:
    """Regression for Codex#9 (round 10, 2026-09-13), reproduced exactly as
    reported: a temporary constraints file containing only ONE correctly-
    versioned installed package caused the old, single
    _constraints_file_present() check to report success despite omitting
    the remainder of the project's dependency closure -
    _constraints_file_present() only ever compares PINNED-and-installed
    pairs for a version MISMATCH, it never required every installed
    closure member to have a pin at all.
    _constraints_pins_are_complete() is the new, separate check that
    closes that gap; splitting it out (rather than folding completeness
    into _constraints_file_present() itself) keeps that function's
    existing, narrower mismatch-only tests
    (test_constraints_check_ignores_a_pin_for_something_not_installed
    above) intact, since a partial-but-internally-consistent
    constraints.txt is still valid input for THAT check."""
    import importlib.metadata as importlib_metadata

    real_pydantic_version = importlib_metadata.version("pydantic")
    (tmp_path / "constraints.txt").write_text(
        f"pydantic=={real_pydantic_version}\n", encoding="utf-8"
    )
    monkeypatch.setattr(preflight, "ROOT", tmp_path)

    # the existing, narrower check still passes - this one pin is correct
    assert preflight._constraints_file_present() is True
    # but the fuller dependency closure is not pinned at all
    assert preflight._constraints_pins_are_complete() is False


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


def test_parses_the_area_count_table() -> None:
    text = (
        "| `app/` | 58 (.py) | engine, ... |\n"
        "| `tests/` | 76 | 45 test modules + fixtures |\n"
        "| root | 11 | `README.md`, ... |\n"
    )
    assert preflight._parse_manifest_area_counts(text) == {
        "app_py": 58,
        "tests_total": 76,
        "tests_modules": 45,
        "root": 11,
    }


def test_returns_none_when_an_area_count_row_is_missing() -> None:
    assert preflight._parse_manifest_area_counts("| `app/` | 58 (.py) | ... |\n") is None


def test_real_manifest_area_counts_match_reality() -> None:
    """Regression for Codex#10 (round 10, 2026-09-13), reproduced exactly as
    reported: the "Tracked files by area" table said 56 `app/` files (actual
    58), 74/41 `tests/` files/modules (actual 76/45), and 10 root files
    (actual 11) - all hand-maintained and drifted independently of the
    header's own tracked-file total, which a different, existing check
    already keeps honest."""
    assert preflight._manifest_area_counts_match_reality() is True


def test_no_stale_license_undecided_text_in_the_real_docs() -> None:
    """Regression for Codex#10 (round 10, 2026-09-13), reproduced exactly as
    reported: docs/threat-model.md said "Project licence not yet chosen"
    despite Apache-2.0 having already been selected and LICENSE/NOTICE
    already committed."""
    assert preflight._no_stale_license_undecided_text() is True


def test_stale_license_undecided_text_is_detected(tmp_path, monkeypatch) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "threat-model.md").write_text(
        "Project licence not yet chosen.\n", encoding="utf-8"
    )
    monkeypatch.setattr(preflight, "ROOT", tmp_path)
    assert preflight._no_stale_license_undecided_text() is False
