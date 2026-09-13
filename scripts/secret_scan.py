#!/usr/bin/env python3
"""Scan tracked text files for hard-coded secrets / credential shapes.

  python scripts/secret_scan.py

Exit 0 if clean, 1 if a candidate is found. A known-safe dummy value is
exempted by its exact matched text (never a whole file or a nearby word -
see _SAFE_VALUES).

Scope (Codex#10, round 7, 2026-09-12): this scans the current working tree
via `git ls-files`, not full repository history - a credential removed from
HEAD but present in an earlier commit would still be published with the
repository's history. Closing that requires walking every blob in every
commit (`git rev-list --all` + `git cat-file`) with a maintained scanner
(gitleaks/trufflehog), which this lightweight regex-based script does not
attempt; treat a real credential ever having been committed as requiring
that separate, dedicated scan before any push, not just this check.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.models._credential_shapes import CREDENTIAL_SHAPE_PATTERNS  # noqa: E402

# Codex#8 (round 12, 2026-09-13), reproduced exactly as reported: this
# script kept its own separate, hand-maintained pattern dict - Stripe and
# JWT detection were added to app/models/_credential_shapes.py (round 11)
# without this script's copy ever being updated, so a Stripe key or JWT
# committed to a tracked file passed this pre-publication scan even though
# the runtime model already rejected the same value. Building on the
# SAME shared dict (imported above) means the two can no longer drift
# apart - "generic-assignment" is this script's own addition (a scan
# concern with no equivalent in the runtime model, which validates typed
# field VALUES, not `key = "..."`-shaped source text).
_PATTERNS: dict[str, re.Pattern[str]] = {
    **CREDENTIAL_SHAPE_PATTERNS,
    "generic-assignment": re.compile(
        r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][0-9A-Za-z/+_-]{16,}['\"]"
    ),
}

# Codex#10 (round 7, 2026-09-12), reproduced exactly as reported: a
# whole-FILE allowlist means a real credential accidentally added to any of
# these files is never inspected at all, and suppressing a match whenever
# *nearby text* contains a broad word ("example"/"dummy") suppresses a real
# credential that merely sits near either word too - re-scanning the tree
# with both removed found exactly one match in the entire repo (below).
# Exempting the exact matched VALUE (never a whole file, never a
# free-floating word) is the only form of allowlisting that cannot mask
# something else: a real secret never happens to equal a known-safe value
# byte-for-byte.
_SAFE_VALUES = {
    "AKIAIOSFODNN7EXAMPLE",  # AWS's own published example access key (docs.aws.amazon.com)
}


# Codex#11 (round 8, 2026-09-12), reproduced exactly as reported: the
# previous suffix ALLOWLIST (.py/.md/.yaml/.yml/.toml/.json/.txt/.cfg/.ini)
# omitted .sh, extensionless files (LICENSE, NOTICE, Makefile, ...), and
# other common config filename forms outright - never even opened, let
# alone scanned. Scanning every tracked file EXCEPT a known-binary
# denylist (the inverse policy) means a new text file type is scanned by
# default instead of silently falling through a gap in the list.
_BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
    ".pdf", ".sqlite", ".sqlite3", ".db",
    ".pyc", ".so", ".dylib", ".dll", ".exe", ".bin",
    ".mp3", ".mp4", ".wav", ".ogg", ".webm",
}  # fmt: skip


def _tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, check=True
    ).stdout.splitlines()
    return [Path(p) for p in out if Path(p).suffix.lower() not in _BINARY_EXTENSIONS]


def main() -> int:
    findings: list[str] = []
    unreadable: list[str] = []
    tracked = _tracked_files()
    for path in tracked:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            # Codex#11 (round 8, 2026-09-12), reproduced exactly as
            # reported: a tracked file with invalid UTF-8 was silently
            # SKIPPED (fail-open) - a secret-like assignment right after
            # the invalid byte(s) was never inspected, and the scan still
            # exited 0. A file this scanner cannot read is a scan it
            # cannot vouch for; that must fail the check, not pass it
            # silently.
            unreadable.append(f"{path}: could not decode as UTF-8 ({exc})")
            continue
        except OSError as exc:
            unreadable.append(f"{path}: could not read ({exc})")
            continue
        for name, pattern in _PATTERNS.items():
            for match in pattern.finditer(text):
                if match.group(0) in _SAFE_VALUES:
                    continue
                line = text[: match.start()].count("\n") + 1
                findings.append(f"{path}:{line}  [{name}]")

    if unreadable:
        print("COULD NOT SCAN (treat as a possible secret until verified by hand):")
        for u in unreadable:
            print(f"  {u}")
    if findings:
        print("POSSIBLE SECRETS:")
        for f in findings:
            print(f"  {f}")
    if findings or unreadable:
        return 1
    print(f"secret scan clean ({len(tracked)} tracked text files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
