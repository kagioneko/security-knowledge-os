#!/usr/bin/env python3
"""Load and validate a knowledge root without touching the index.

Reports which units would be ingested and which are skipped (and why).
Use scripts/build_index.py to actually (re)build the FTS index.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import Settings  # noqa: E402
from app.ingestion.loader import compute_knowledge_revision, load_corpus  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    settings = Settings.from_env()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=settings.knowledge_root, type=Path)
    args = parser.parse_args(argv)

    if not args.root.exists():
        print(f"knowledge root not found: {args.root}", file=sys.stderr)
        return 2

    report = load_corpus(args.root)
    print(f"loadable units : {len(report.units)}")
    print(f"revision       : {compute_knowledge_revision(report.units)}")
    print(f"warnings       : {report.warning_count}")
    for unit in report.units:
        fm = unit.front_matter
        print(f"  + {fm.id} [{fm.classification.value}] {fm.title}")
    if report.skipped:
        print(f"skipped        : {len(report.skipped)}")
        for path, reason in report.skipped:
            print(f"  - {path}\n      {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
