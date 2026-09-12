#!/usr/bin/env python3
"""Run every labelled assessment fixture and report the Section 24 metrics.

  python scripts/evaluate.py [--db var/index.sqlite]

Exit 0 if the initial gates hold (false-positive rate = 0, safe-test safety
violations = 0), else 1.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import Settings  # noqa: E402
from app.eval.metrics import LabelledResult, compute_metrics  # noqa: E402
from app.ingestion.parser import FrontMatterError, safe_load_bounded  # noqa: E402
from app.models.assessment import AssessmentInput  # noqa: E402
from app.policy.safe_test import load_safe_test_templates  # noqa: E402
from app.reviewer.assess import assess  # noqa: E402
from app.reviewer.rule_loader import load_rules  # noqa: E402
from app.storage.db import connect  # noqa: E402

_LABELS = {"vulnerable", "safe", "unknown"}

# Codex#8 (round 11, 2026-09-13): see cli.py's own comment on the identical
# fix there - a hand-authored assessment YAML file is at most a few KB in
# real use (AssessmentInput's own post-parse total-size validator caps the
# parsed result at 300,000 bytes).
_MAX_ASSESSMENT_YAML_BYTES = 500_000


def main(argv: list[str] | None = None) -> int:
    settings = Settings.from_env()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=Path(settings.db_path))
    parser.add_argument(
        "--fixtures",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "assessments",
    )
    args = parser.parse_args(argv)

    catalogue = load_rules(settings.rules_root)
    safe_tests = load_safe_test_templates(settings.safe_tests_root)
    conn = connect(args.db, read_only=True) if args.db.exists() else None

    labelled: list[LabelledResult] = []
    try:
        for path in sorted(args.fixtures.rglob("*.yaml")):
            label = path.parent.name
            if label not in _LABELS:
                continue
            # Codex#8 (round 11, 2026-09-13), reproduced exactly as reported:
            # a bare yaml.safe_load() here had none of the bounds/error
            # handling rule/safe-test/knowledge YAML already gets.
            try:
                raw = safe_load_bounded(
                    path.read_text(encoding="utf-8"),
                    max_bytes=_MAX_ASSESSMENT_YAML_BYTES,
                    what="assessment fixture",
                )
                if not isinstance(raw, dict):
                    raise FrontMatterError(
                        f"{path}: must be a mapping, got {type(raw).__name__}"
                    )
                inp = AssessmentInput.model_validate(raw)
            except (FrontMatterError, ValidationError) as exc:
                print(f"skipping invalid fixture {path}: {exc}", file=sys.stderr)
                continue
            result = assess(
                inp, catalogue, settings=settings, index_conn=conn, safe_tests=safe_tests
            )
            labelled.append(LabelledResult(label=label, result=result))
    finally:
        if conn is not None:
            conn.close()

    m = compute_metrics(labelled, catalogue)
    print(
        f"fixtures            : {m.n_vulnerable} vulnerable, "
        f"{m.n_safe} safe, {m.n_unknown} unknown"
    )
    print(f"known_risk_recall   : {m.known_risk_recall:.3f}")
    print(f"false_positive_rate : {m.false_positive_rate:.3f}   (gate: 0)")
    print(f"unknown_appropriate : {m.unknown_appropriateness:.3f}")
    print(f"evidence_coverage   : {m.evidence_coverage:.3f}")
    print(f"citation_src_match  : {m.citation_source_match}")
    print(f"safe_test_violations: {m.safe_test_safety_violations}   (gate: 0)")
    print(f"human_review_corr   : {m.human_review_correction_rate}  (needs human labels)")
    for note in m.notes:
        print(f"  note: {note}")
    print(f"\ngates_pass          : {m.gates_pass}")
    return 0 if m.gates_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
