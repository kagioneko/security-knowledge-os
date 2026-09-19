#!/usr/bin/env python3
"""Run an assessment from a YAML input file and print the result as JSON.

  python scripts/assess.py examples/sample.yaml [--db var/index.sqlite]

The LLM provider comes from SKOS_LLM_PROVIDER (default: none). With provider=none
the assessment still completes - the deterministic engine does all the work.

Exit codes: 0 ok, 2 usage/input error, 3 POLICY_BLOCKED (matches app/cli.py's
`skos assess`).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import Settings  # noqa: E402
from app.ingestion.parser import (  # noqa: E402
    FrontMatterError,
    read_text_bounded,
    safe_load_bounded,
)
from app.llm.factory import get_client  # noqa: E402
from app.models.assessment import AssessmentInput  # noqa: E402
from app.models.report import ReportStatus  # noqa: E402
from app.reviewer.report import build_report  # noqa: E402
from app.reviewer.rule_loader import load_rules  # noqa: E402
from app.safe_errors import format_validation_error  # noqa: E402
from app.storage.db import connect  # noqa: E402

# Codex#8 (round 11, 2026-09-13): see cli.py's own comment on the identical
# fix there - a hand-authored assessment YAML file is at most a few KB in
# real use (AssessmentInput's own post-parse total-size validator caps the
# parsed result at 300,000 bytes).
_MAX_ASSESSMENT_YAML_BYTES = 500_000


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

    # Codex#8 (round 11, 2026-09-13), reproduced exactly as reported: a bare
    # `yaml.safe_load()` here read the complete file before AssessmentInput's
    # own post-parse total-size validator ever ran, and nothing caught
    # yaml.YAMLError/RecursionError/ValidationError - a malformed or
    # hostile file escaped as a raw traceback.
    #
    # Codex#10 (round 12, 2026-09-13), reproduced exactly as reported: this
    # try block did not cover `args.input.read_text()` itself either - a
    # directory (`IsADirectoryError`, an `OSError` subclass, since
    # `args.input.exists()` above is true for directories too) or invalid
    # UTF-8 (`UnicodeDecodeError`) both escaped as a raw traceback.
    try:
        raw = safe_load_bounded(
            read_text_bounded(
                args.input, max_bytes=_MAX_ASSESSMENT_YAML_BYTES, what="assessment file"
            ),
            max_bytes=_MAX_ASSESSMENT_YAML_BYTES,
            what="assessment file",
        )
        if not isinstance(raw, dict):
            raise FrontMatterError(f"assessment file must be a mapping, got {type(raw).__name__}")
        inp = AssessmentInput.model_validate(raw)
    except FrontMatterError as exc:
        print(f"invalid assessment file: {exc}", file=sys.stderr)
        return 2
    except ValidationError as exc:  # Codex#1 (round 22): never echo the rejected value
        print(f"invalid assessment file: {format_validation_error(exc)}", file=sys.stderr)
        return 2
    except (OSError, UnicodeDecodeError) as exc:
        print(f"could not read input file: {exc}", file=sys.stderr)
        return 2
    catalogue = load_rules(args.rules)
    client = get_client(settings)

    # Codex cross-review finding #5 (2026-09-11): the assessment path must never
    # write to the knowledge index (every other caller - app/main.py, app/cli.py,
    # scripts/evaluate.py, reindex_atomic's own verification reads - opens it
    # read_only=True). This one didn't, and would silently create+write an empty
    # schema into a not-yet-built --db path instead of treating it as absent.
    conn = connect(args.db, read_only=True) if args.db and args.db.exists() else None
    try:
        # Codex#10 (round 12, 2026-09-13), reproduced exactly as reported:
        # this called assess() (the bare library entry point) directly -
        # every OTHER caller (app/main.py, app/cli.py) goes through
        # build_report(), which catches PolicyStop and turns it into a
        # typed, POLICY_BLOCKED AssessmentReport. A corrupt/foreign index
        # (or any other PolicyStop-raising condition) here instead escaped
        # as a raw, uncaught exception - never the documented exit code 3.
        report = build_report(inp, catalogue, settings=settings, client=client, index_conn=conn)
    finally:
        if conn is not None:
            conn.close()

    if report.status is ReportStatus.POLICY_BLOCKED:
        print(report.model_dump_json(indent=2))
        return 3

    assert report.result is not None
    print(report.result.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
