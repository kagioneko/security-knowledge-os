"""``skos`` command-line interface (spec Section 19).

    skos validate-knowledge [ROOT] [--strict]
    skos validate-rules [ROOT]
    skos validate-safe-tests [ROOT]
    skos ingest [ROOT]
    skos reindex [ROOT] [--db PATH]
    skos assess FILE [--db PATH] [--json] [--strict]
    skos report FILE                 # pretty-print a saved report JSON
    skos test [--db PATH]            # run the assessment fixtures as a smoke test

Exit codes: 0 ok, 1 findings failure with --strict, 2 usage/input error,
3 POLICY_BLOCKED (an assessment or reindex was stopped by policy).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from app.config import Settings
from app.ingestion.validator import Level, iter_knowledge_files, validate_tree
from app.llm.factory import get_client
from app.models.assessment import AssessmentInput
from app.models.report import AssessmentReport, ReportStatus
from app.policy.safe_test import SafeTestLoadError, load_safe_test_templates
from app.retrieval.index import reindex_atomic
from app.reviewer.report import build_report, render_text
from app.reviewer.rule_loader import RuleLoadError, load_rules
from app.storage.db import connect

_FIXTURES = [
    "V-001-indirect-injection-auto-email",
    "V-002-rag-delete-tool-no-approval",
    "V-003-persistent-memory-untrusted",
    "V-004-env-secret-readable",
    "S-001-prompt-only",
    "S-002-rag-trusted-no-actions",
    "S-003-readonly-tool-with-approval",
    "S-004-credential-proxy",
    "U-001-tool-permissions-missing",
    "U-002-memory-persistence-unspecified",
    "U-003-outbound-destination-unspecified",
    "U-004-credential-handling-unspecified",
]


def _load_input(path: Path) -> AssessmentInput:
    return AssessmentInput.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def _cmd_validate_knowledge(args: argparse.Namespace, s: Settings) -> int:
    root = args.root or Path(s.knowledge_root)
    if not root.exists():
        print(f"knowledge root not found: {root}", file=sys.stderr)
        return 2
    issues = validate_tree(root)
    for issue in issues:
        print(issue)
    errors = sum(1 for i in issues if i.level is Level.ERROR)
    warnings = sum(1 for i in issues if i.level is Level.WARNING)
    files = len(iter_knowledge_files(root))
    print(f"\n{errors} error(s), {warnings} warning(s) across {files} file(s)")
    return 1 if errors or (args.strict and warnings) else 0


def _cmd_validate_rules(args: argparse.Namespace, s: Settings) -> int:
    root = args.root or Path(s.rules_root)
    try:
        catalogue = load_rules(root)
    except RuleLoadError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    for rule in catalogue.rules:
        print(f"  {rule.id:10} {rule.severity.value:8} {rule.category.value:20} {rule.title}")
    print(f"\n{len(catalogue.rules)} rule(s), all valid")
    return 0


def _cmd_validate_safe_tests(args: argparse.Namespace, s: Settings) -> int:
    root = args.root or Path(s.safe_tests_root)
    try:
        templates = load_safe_test_templates(root)
    except SafeTestLoadError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    for test in templates.values():
        envs = "+".join(e.value for e in test.environment)
        print(f"  {test.id:14} {test.risk_id:10} [{envs}] approval={test.requires_human_approval}")
    print(f"\n{len(templates)} safe-test template(s), all valid")
    return 0


def _cmd_ingest(args: argparse.Namespace, s: Settings) -> int:
    from app.ingestion.loader import compute_knowledge_revision, load_corpus

    root = args.root or Path(s.knowledge_root)
    if not root.exists():
        print(f"knowledge root not found: {root}", file=sys.stderr)
        return 2
    report = load_corpus(root)
    print(f"loadable units : {len(report.units)}")
    print(f"revision       : {compute_knowledge_revision(report.units)}")
    for unit in report.units:
        fm = unit.front_matter
        print(f"  + {fm.id} [{fm.classification.value}] {fm.title}")
    for path, reason in report.skipped:
        print(f"  - {path}\n      {reason}")
    return 0


def _cmd_reindex(args: argparse.Namespace, s: Settings) -> int:
    root = args.root or Path(s.knowledge_root)
    db = args.db or Path(s.db_path)
    report = reindex_atomic(root, db)
    print(f"outcome     : {report.decision.outcome.value}")
    print(f"old_revision: {report.old_revision}")
    print(f"new_revision: {report.new_revision}")
    if report.ok:
        print(f"units       : {report.units_indexed}")
        print(f"chunks      : {report.chunks_indexed}")
        return 0
    for reason in report.decision.reasons:
        print(f"  - {reason}", file=sys.stderr)
    return 3


def _run(inp: AssessmentInput, s: Settings, db: Path | None) -> AssessmentReport:
    catalogue = load_rules(s.rules_root)
    safe_tests = load_safe_test_templates(s.safe_tests_root)
    client = get_client(s)
    conn = connect(db, read_only=True) if db else None
    try:
        return build_report(
            inp, catalogue, settings=s, client=client, index_conn=conn, safe_tests=safe_tests
        )
    finally:
        if conn is not None:
            conn.close()


def _cmd_assess(args: argparse.Namespace, s: Settings) -> int:
    if not args.file.exists():
        print(f"input not found: {args.file}", file=sys.stderr)
        return 2
    report = _run(_load_input(args.file), s, args.db)
    if args.json:
        print(report.model_dump_json(indent=2))
    else:
        print(render_text(report))
    if report.status is ReportStatus.POLICY_BLOCKED:
        return 3
    flagged = {"FAIL", "CONDITIONAL", "UNKNOWN"}
    if args.strict and report.result is not None and report.result.overall_status.value in flagged:
        return 1
    return 0


def _cmd_report(args: argparse.Namespace, s: Settings) -> int:
    if not args.file.exists():
        print(f"report not found: {args.file}", file=sys.stderr)
        return 2
    report = AssessmentReport.model_validate_json(args.file.read_text(encoding="utf-8"))
    print(render_text(report))
    return 3 if report.status is ReportStatus.POLICY_BLOCKED else 0


def _cmd_test(args: argparse.Namespace, s: Settings) -> int:
    fixtures_dir = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "assessments"
    if not fixtures_dir.exists():
        print("fixtures not available in this install", file=sys.stderr)
        return 2
    failures = 0
    for name in _FIXTURES:
        report = _run(_load_input(fixtures_dir / f"{name}.yaml"), s, args.db)
        if report.status is ReportStatus.POLICY_BLOCKED:
            print(f"  {name:44} POLICY_BLOCKED")
            failures += 1
            continue
        assert report.result is not None
        r = report.result
        print(f"  {name:44} {r.overall_status.value:11} hr={int(r.human_review_required)}")
    print(f"\n{len(_FIXTURES) - failures}/{len(_FIXTURES)} fixtures completed")
    return 1 if failures else 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="skos", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate-knowledge")
    p.add_argument("root", nargs="?", type=Path)
    p.add_argument("--strict", action="store_true")
    p.set_defaults(func=_cmd_validate_knowledge)

    p = sub.add_parser("validate-rules")
    p.add_argument("root", nargs="?", type=Path)
    p.set_defaults(func=_cmd_validate_rules)

    p = sub.add_parser("validate-safe-tests")
    p.add_argument("root", nargs="?", type=Path)
    p.set_defaults(func=_cmd_validate_safe_tests)

    p = sub.add_parser("ingest")
    p.add_argument("root", nargs="?", type=Path)
    p.set_defaults(func=_cmd_ingest)

    p = sub.add_parser("reindex")
    p.add_argument("root", nargs="?", type=Path)
    p.add_argument("--db", type=Path)
    p.set_defaults(func=_cmd_reindex)

    p = sub.add_parser("assess")
    p.add_argument("file", type=Path)
    p.add_argument("--db", type=Path)
    p.add_argument("--json", action="store_true")
    p.add_argument("--strict", action="store_true")
    p.set_defaults(func=_cmd_assess)

    p = sub.add_parser("report")
    p.add_argument("file", type=Path)
    p.set_defaults(func=_cmd_report)

    p = sub.add_parser("test")
    p.add_argument("--db", type=Path)
    p.set_defaults(func=_cmd_test)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    settings = Settings.from_env()
    try:
        return int(args.func(args, settings))
    except (RuleLoadError, SafeTestLoadError) as exc:
        print(f"catalogue error: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"invalid JSON: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
