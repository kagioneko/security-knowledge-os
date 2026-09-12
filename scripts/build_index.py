#!/usr/bin/env python3
"""Build the knowledge index from a knowledge root.

Codex#7 (round 5, 2026-09-12): this used to call build_index() directly -
the same low-level function reindex_atomic() uses to build into a STAGING
file - straight against --db. Unlike reindex_atomic(), that path is neither
clean-tree-only nor atomic: it accepts a corpus with validation errors or
skipped units (even zero units, e.g. an empty --db target directory) and
writes the result straight into the live database in place, so a bad or
half-migrated corpus published a self-consistent but wrong (or empty) index
over whatever --db was already serving.

By default this now goes through reindex_atomic() instead - the same
clean-tree-only, atomic, staging+swap path the API's /v1/knowledge/reindex
endpoint uses, which refuses validation errors or skipped units and never
touches --db until a fully-verified replacement is ready. --allow-partial
opts back into the old direct/partial build_index() behavior, for a
deliberate incremental/debugging build only - never point it at a database
an API instance is currently serving from.

Exit codes:
  0  index built and published
  2  the knowledge root does not exist (--allow-partial), or the build was
     refused (validation errors / skipped units / any POLICY_BLOCKED reason)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import Settings  # noqa: E402
from app.ingestion.validator import iter_knowledge_files  # noqa: E402
from app.retrieval.index import IndexBuildError, build_index, reindex_atomic  # noqa: E402


def _run_safe(root: Path, db: Path) -> int:
    # Codex#7 (round 5, 2026-09-12): reindex_atomic() itself does not refuse
    # a genuinely empty (but validly-structured, zero validation errors)
    # knowledge root - a 0-file directory is "internally consistent" by its
    # own rules and still gets published, replacing a real, populated
    # existing index with an empty one. That is exactly the review's repro
    # (`build_index.py empty-directory --db existing-index.sqlite`), so it
    # is refused here, before reindex_atomic() ever runs (once it has run,
    # the swap has already happened - there is nothing left to "refuse").
    if root.is_dir() and not iter_knowledge_files(root):
        print(
            f"refusing to publish a zero-unit index from an empty knowledge "
            f"root ({root}); pass --allow-partial to override",
            file=sys.stderr,
        )
        return 2

    report = reindex_atomic(root, db)
    print(f"knowledge_root : {root}")
    print(f"db_path        : {db}")
    print(f"old_revision   : {report.old_revision or '(none)'}")
    print(f"new_revision   : {report.new_revision or '(none)'}")
    print(f"units_indexed  : {report.units_indexed}")
    print(f"chunks_indexed : {report.chunks_indexed}")
    print(f"outcome        : {report.decision.outcome.value}")
    if not report.ok:
        for reason in report.decision.reasons:
            print(f"  - {reason}", file=sys.stderr)
        return 2
    return 0


def _run_allow_partial(root: Path, db: Path) -> int:
    # Codex cross-review finding #5 (round 2, 2026-09-11): exists() accepts a
    # plain FILE as "root" too (e.g. a typo'd --root pointing at README.md);
    # is_dir() is the actual requirement.
    if not root.is_dir():
        print(f"knowledge root does not exist or is not a directory: {root}", file=sys.stderr)
        return 2

    try:
        report = build_index(root, db)
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


def main(argv: list[str] | None = None) -> int:
    settings = Settings.from_env()
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("root", nargs="?", default=settings.knowledge_root, type=Path)
    parser.add_argument("--db", default=settings.db_path, type=Path, help="index database path")
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help=(
            "bypass reindex_atomic() and write directly into --db via "
            "build_index(), accepting a corpus with validation errors or "
            "skipped units (even zero units). Not atomic, not "
            "clean-tree-only - never point this at a database an API "
            "instance is currently serving from."
        ),
    )
    args = parser.parse_args(argv)

    if args.allow_partial:
        return _run_allow_partial(args.root, args.db)
    return _run_safe(args.root, args.db)


if __name__ == "__main__":
    raise SystemExit(main())
