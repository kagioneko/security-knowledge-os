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

_PATTERNS = {
    "aws-access-key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private-key-block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "slack-token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{12,}"),
    "github-pat": re.compile(r"gh[pousr]_[0-9A-Za-z]{30,}"),
    "anthropic-key": re.compile(r"sk-ant-[0-9A-Za-z_-]{20,}"),
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


def _tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, check=True
    ).stdout.splitlines()
    keep = (".py", ".md", ".yaml", ".yml", ".toml", ".json", ".txt", ".cfg", ".ini")
    return [Path(p) for p in out if p.endswith(keep)]


def main() -> int:
    findings: list[str] = []
    for path in _tracked_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for name, pattern in _PATTERNS.items():
            for match in pattern.finditer(text):
                if match.group(0) in _SAFE_VALUES:
                    continue
                line = text[: match.start()].count("\n") + 1
                findings.append(f"{path}:{line}  [{name}]")

    if findings:
        print("POSSIBLE SECRETS:")
        for f in findings:
            print(f"  {f}")
        return 1
    print(f"secret scan clean ({len(_tracked_files())} tracked text files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
