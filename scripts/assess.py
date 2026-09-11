#!/usr/bin/env python3
"""Run an assessment from a YAML input file and print the result as JSON.

  python scripts/assess.py examples/sample.yaml [--db var/index.sqlite]

The LLM provider comes from SKOS_LLM_PROVIDER (default: none). With provider=none
the assessment still completes - the deterministic engine does all the work.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import Settings  # noqa: E402
from app.llm.factory import get_client  # noqa: E402
from app.models.assessment import AssessmentInput  # noqa: E402
from app.reviewer.assess import assess  # noqa: E402
from app.reviewer.rule_loader import load_rules  # noqa: E402
from app.storage.db import connect  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    settings = Settings.from_env()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--db", type=Path, default=None, help="FTS index for knowledge citations")
    parser.add_argument("--rules", type=Path, default=Path(settings.rules_root))
    args = parser.parse_args(argv)

    if not args.input.exists():
        print(f"input not found: {args.input}", file=sys.stderr)
        return 2

    inp = AssessmentInput.model_validate(yaml.safe_load(args.input.read_text(encoding="utf-8")))
    catalogue = load_rules(args.rules)
    client = get_client(settings)

    # Codex cross-review finding #5 (2026-09-11): the assessment path must never
    # write to the knowledge index (every other caller - app/main.py, app/cli.py,
    # scripts/evaluate.py, reindex_atomic's own verification reads - opens it
    # read_only=True). This one didn't, and would silently create+write an empty
    # schema into a not-yet-built --db path instead of treating it as absent.
    conn = connect(args.db, read_only=True) if args.db and args.db.exists() else None
    try:
        result = assess(inp, catalogue, settings=settings, client=client, index_conn=conn)
    finally:
        if conn is not None:
            conn.close()

    print(result.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
