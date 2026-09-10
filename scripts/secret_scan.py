#!/usr/bin/env python3
"""Scan tracked text files for hard-coded secrets / credential shapes.

  python scripts/secret_scan.py

Exit 0 if clean, 1 if a candidate is found. Known safe fixtures (dummy values,
detector patterns) are on an allow-list.
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

# Files whose "hits" are deliberate: detector patterns, dummy fixture values.
_ALLOW = {
    "scripts/secret_scan.py",
    "app/policy/safe_test.py",
    "tests/unit/test_safe_test.py",
    "tests/unit/test_fail_closed.py",
    "docs/safe-test-schema.md",
    "docs/attribution.md",
}
# Substrings that mark a match as a known-safe example.
_SAFE_TOKENS = ("EXAMPLE", "SECRET_TEST_123", "CANARY", "example", "dummy", "<api-key>")


def _tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, check=True
    ).stdout.splitlines()
    keep = (".py", ".md", ".yaml", ".yml", ".toml", ".json", ".txt", ".cfg", ".ini")
    return [Path(p) for p in out if p.endswith(keep)]


def main() -> int:
    findings: list[str] = []
    for path in _tracked_files():
        if path.as_posix() in _ALLOW:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for name, pattern in _PATTERNS.items():
            for match in pattern.finditer(text):
                context = text[max(0, match.start() - 40) : match.end() + 20]
                if any(tok in context for tok in _SAFE_TOKENS):
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
