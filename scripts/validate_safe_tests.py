#!/usr/bin/env python3
"""Load and validate the safe-test template library.

Exit codes:
  0  every template is valid and passes the safety validator
  1  a template is invalid or unsafe
  2  the safe-tests root does not exist
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import Settings  # noqa: E402
from app.policy.safe_test import SafeTestLoadError, load_safe_test_templates  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    settings = Settings.from_env()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=settings.safe_tests_root, type=Path)
    args = parser.parse_args(argv)

    if not args.root.exists():
        print(f"safe-tests root not found: {args.root}", file=sys.stderr)
        return 2

    try:
        templates = load_safe_test_templates(args.root)
    except SafeTestLoadError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1

    for test in templates.values():
        envs = "+".join(e.value for e in test.environment)
        print(f"  {test.id:14} {test.risk_id:10} [{envs}] approval={test.requires_human_approval}")
    print(f"\n{len(templates)} safe-test template(s), all valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
