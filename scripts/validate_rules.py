#!/usr/bin/env python3
"""Load and validate the risk-rule catalogue.

Exit codes:
  0  every rule is valid
  1  the catalogue is invalid (message on stderr)
  2  the rules root does not exist
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import Settings  # noqa: E402
from app.reviewer.rule_loader import RuleLoadError, load_rules  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    settings = Settings.from_env()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=settings.rules_root, type=Path)
    args = parser.parse_args(argv)

    if not args.root.exists():
        print(f"rules root not found: {args.root}", file=sys.stderr)
        return 2

    try:
        catalogue = load_rules(args.root)
    except RuleLoadError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1

    for rule in catalogue.rules:
        print(
            f"  {rule.id:10} {rule.severity.value:8} {rule.category.value:20} {rule.title}"
        )
    print(f"\n{len(catalogue.rules)} rule(s), all valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
