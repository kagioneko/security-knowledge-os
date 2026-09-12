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
