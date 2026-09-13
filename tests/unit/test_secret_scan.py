"""scripts/secret_scan.py: exact-value allowlist, not whole-file/word-based.

Fake secret-shaped test values are built via string concatenation
(_fake_aws_key()) rather than as a single literal, so this file's own
SOURCE never contains a contiguous match secret_scan.py itself would flag
when it scans the real repository.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from secret_scan import _PATTERNS, _SAFE_VALUES  # noqa: E402


def _fake_aws_key(suffix: str = "ABCDEFGHIJKLMNOP") -> str:
    return "AKIA" + suffix


def test_the_one_known_safe_value_is_exempted() -> None:
    text = "access_key = 'AKIA" + "IOSFODNN7EXAMPLE'"
    match = _PATTERNS["aws-access-key"].search(text)
    assert match is not None
    assert match.group(0) in _SAFE_VALUES


def test_a_real_shaped_credential_near_a_broad_safe_word_is_still_flagged() -> None:
    """Regression for Codex#10 (round 7, 2026-09-12), reproduced exactly as
    reported: a match used to be suppressed whenever nearby text contained
    a broad word such as "example" or "dummy" - a real credential that
    merely sits near either word was suppressed too. Only the exact known
    dummy VALUE is exempted now, not the word next to it."""
    text = "# this is just an example config\napi_key = '" + _fake_aws_key() + "'"
    match = _PATTERNS["aws-access-key"].search(text)
    assert match is not None
    assert match.group(0) not in _SAFE_VALUES


def test_a_shell_script_is_scanned_not_skipped_by_the_suffix_allowlist(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """Regression for Codex#11 (round 8, 2026-09-12), reproduced exactly as
    reported: the old suffix ALLOWLIST omitted .sh (and extensionless
    files, and other config filename forms) outright - never even opened,
    let alone scanned."""
    import subprocess

    import secret_scan

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    target = tmp_path / "deploy.sh"
    target.write_text(f"export API_KEY='{_fake_aws_key()}'\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)

    monkeypatch.chdir(tmp_path)
    exit_code = secret_scan.main()
    assert exit_code == 1
    assert "deploy.sh" in capsys.readouterr().out


def test_an_undecodable_file_fails_the_scan_instead_of_being_silently_skipped(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """Regression for Codex#11 (round 8, 2026-09-12), reproduced exactly as
    reported: a tracked file with invalid UTF-8 (before or after a
    secret-like assignment) was silently SKIPPED after UnicodeDecodeError,
    and the scan still exited 0 - a file this scanner cannot read is a
    file it cannot vouch for, which must fail the check rather than pass
    it silently."""
    import subprocess

    import secret_scan

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    target = tmp_path / "notes.txt"
    target.write_bytes(b"\xff\xfe some notes, definitely not a secret\n")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)

    monkeypatch.chdir(tmp_path)
    exit_code = secret_scan.main()
    assert exit_code == 1
    assert "notes.txt" in capsys.readouterr().out


def test_a_real_shaped_credential_in_a_formerly_allow_listed_file_is_flagged(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """Regression for Codex#10 (round 7, 2026-09-12), reproduced exactly as
    reported: a whole-FILE allowlist (app/policy/safe_test.py,
    docs/attribution.md, ...) meant a real credential accidentally added to
    any of those files was never inspected at all. There is no per-file
    exemption left - main() runs the patterns against every tracked file's
    content unconditionally."""
    import subprocess

    import secret_scan

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    target = tmp_path / "app" / "policy" / "safe_test.py"
    target.parent.mkdir(parents=True)
    target.write_text(_fake_aws_key(), encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)

    monkeypatch.chdir(tmp_path)
    exit_code = secret_scan.main()
    assert exit_code == 1
    assert "safe_test.py" in capsys.readouterr().out


def test_patterns_share_the_runtime_credential_shape_source() -> None:
    """Regression for Codex#8 (round 12, 2026-09-13), reproduced exactly as
    reported: this script kept its own separate pattern dict, never
    updated when app/models/_credential_shapes.py gained Stripe/JWT
    detection in round 11 - a Stripe key or JWT committed to a tracked
    file passed this scan even though the runtime model already rejected
    the same value. Building _PATTERNS from the shared dict means every
    name added there (present or future) is automatically present here
    too; this test would fail if that import were ever reverted to a
    separately hand-maintained copy."""
    from app.models._credential_shapes import CREDENTIAL_SHAPE_PATTERNS

    for name in CREDENTIAL_SHAPE_PATTERNS:
        assert name in _PATTERNS


def test_stripe_key_shaped_value_is_flagged() -> None:
    text = "sk_live_" + "A" * 32
    assert _PATTERNS["stripe-key"].search(text) is not None


def test_jwt_shaped_value_is_flagged() -> None:
    text = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )
    assert _PATTERNS["jwt"].search(text) is not None


def test_google_api_key_shaped_value_is_flagged() -> None:
    """Regression for Codex#1 (round 12, 2026-09-13): a Google-API-key-
    shaped value was not in any pattern list, runtime or scanner."""
    text = "AIza" + "B" * 35
    assert _PATTERNS["google-api-key"].search(text) is not None


def test_gitlab_pat_shaped_value_is_flagged() -> None:
    text = "glpat-" + "C" * 20
    assert _PATTERNS["gitlab-pat"].search(text) is not None


def test_discord_bot_token_shaped_value_is_flagged() -> None:
    text = "M" + "D" * 24 + "." + "E" * 6 + "." + "F" * 27
    assert _PATTERNS["discord-bot-token"].search(text) is not None


def test_db_connection_string_with_credentials_is_flagged() -> None:
    text = "postgres://" + "dbuser" + ":" + "hunter2" + "@" + "db.internal:5432/prod"
    assert _PATTERNS["db-connection-string"].search(text) is not None


def test_an_ordinary_url_without_credentials_is_not_flagged_as_a_db_string() -> None:
    assert _PATTERNS["db-connection-string"].search("https://example.com/docs") is None
