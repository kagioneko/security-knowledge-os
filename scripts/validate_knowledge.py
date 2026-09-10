#!/usr/bin/env python3
"""Validate every Knowledge Unit under a knowledge root.

Exit codes:
  0  no issues (or only warnings without --strict)
  1  at least one ERROR (or a warning with --strict)
  2  the knowledge root does not exist
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.ingestion.validator import (  # noqa: E402
    Level,
    iter_knowledge_files,
    validate_tree,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "root", nargs="?", default="knowledge", type=Path, help="knowledge root directory"
    )
    parser.add_argument(
        "--strict", action="store_true", help="treat warnings as failures"
    )
    args = parser.parse_args(argv)

    if not args.root.exists():
        print(f"knowledge root not found: {args.root}", file=sys.stderr)
        return 2

    issues = validate_tree(args.root)
    errors = [i for i in issues if i.level is Level.ERROR]
    warnings = [i for i in issues if i.level is Level.WARNING]

    for issue in issues:
        print(issue)

    file_count = len(iter_knowledge_files(args.root))
    print(f"\n{len(errors)} error(s), {len(warnings)} warning(s) across {file_count} file(s)")

    if errors or (args.strict and warnings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
