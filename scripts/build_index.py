#!/usr/bin/env python3
"""Build the knowledge index from a knowledge root.

Exit codes:
  0  index built
  2  the knowledge root does not exist
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import Settings  # noqa: E402
from app.retrieval.index import IndexBuildError, build_index  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    settings = Settings.from_env()
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("root", nargs="?", default=settings.knowledge_root, type=Path)
    parser.add_argument("--db", default=settings.db_path, type=Path, help="index database path")
    args = parser.parse_args(argv)

    # Codex cross-review finding #5 (round 2, 2026-09-11): exists() accepts a
    # plain FILE as "root" too (e.g. a typo'd --root pointing at README.md);
    # is_dir() is the actual requirement.
    if not args.root.is_dir():
        print(f"knowledge root does not exist or is not a directory: {args.root}", file=sys.stderr)
        return 2

    try:
        report = build_index(args.root, args.db)
    except IndexBuildError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"knowledge_root : {report.knowledge_root}")
    print(f"db_path        : {report.db_path}")
    print(f"units_indexed  : {report.units_indexed}")
    print(f"chunks_indexed : {report.chunks_indexed}")
    print(f"classifications: {', '.join(report.classifications) or '(none)'}")
    print(f"revision       : {report.knowledge_revision}")
    print(f"warnings       : {report.warnings}")
    if report.skipped:
        print(f"skipped        : {len(report.skipped)}")
        for path, reason in report.skipped:
            print(f"  - {path}\n      {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
