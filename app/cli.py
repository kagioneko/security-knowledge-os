"""``skos`` command-line interface (spec Section 19).

    skos validate-knowledge [ROOT] [--strict]
    skos validate-rules [ROOT]
    skos validate-safe-tests [ROOT]
    skos ingest [ROOT]
    skos reindex [ROOT] [--db PATH]
    skos assess FILE [--db PATH] [--json] [--strict]
    skos assess FILE --no-packs      # core rules only; extensions blocks are ignored
    skos report FILE                 # pretty-print a saved report JSON
    skos test [--db PATH]            # run the assessment fixtures as a smoke test
    skos pack build|inspect|verify|diff|install|list|rollback|remove ...
                                     # Update Packs (see app/pack_cli.py)
    skos scan mcp CONFIG [--out DIR] [--assess] [--client NAME]
                                     # one assessment input per MCP server in a
                                     # .mcp.json / claude_desktop_config.json

Exit codes: 0 ok, 1 findings failure with --strict, 2 usage/input error,
3 POLICY_BLOCKED (an assessment or reindex was stopped by policy).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from pydantic import ValidationError

from app.adapters.capgraph import (
    AGENT_FILE_STEM,
    CLIENTS,
    agent_labels,
    agent_yaml,
    labels_json,
)
from app.adapters.mcp_config import ConfigError, assessment_yaml, scan_config
from app.config import Settings
from app.ingestion.parser import FrontMatterError, read_text_bounded, safe_load_bounded
from app.ingestion.validator import Level, iter_knowledge_files, validate_tree
from app.llm.factory import get_client
from app.models.assessment import AssessmentInput, OverallStatus
from app.models.report import AssessmentReport, ReportStatus
from app.pack_cli import PACK_ERRORS
from app.pack_cli import register as register_pack_commands
from app.packs.loader import PackLoadError, load_with_packs, only_pack
from app.packs.store import verify_active
from app.policy.safe_test import (
    SafeTestLoadError,
    load_safe_test_templates,
    unresolved_safe_test_references,
)
from app.retrieval.index import reindex_atomic
from app.reviewer.report import build_report, render_text
from app.reviewer.rule_loader import RuleLoadError, load_rules
from app.safe_errors import format_validation_error
from app.storage.db import INDEX_OPEN_ERRORS, connect, describe_db_error

# Codex#8 (round 11, 2026-09-13): a hand-authored assessment YAML file is at
# most a few KB in real use (AssessmentInput's own post-parse total-size
# validator caps the parsed result at 300,000 bytes); bounds the raw text
# handed to the YAML parser regardless of how it would blow up.
_MAX_ASSESSMENT_YAML_BYTES = 500_000
# Codex#2 (round 25, 2026-09-20): a saved report is machine-written JSON (findings,
# evidence excerpts); 10 MB is far above any real one, and bounds the READ.
_MAX_REPORT_JSON_BYTES = 10_000_000

# Codex#6 (round 12, 2026-09-13), reproduced exactly as reported: this
# hand-maintained list had drifted to 12 names while
# tests/fixtures/assessments/ actually held 14 files - U-005 and V-005
# (each added for a specific past regression) were silently never run by
# `skos test`, with no error or warning either way. _cmd_test() below now
# derives the fixture list from the directory itself (the same way
# scripts/evaluate.py already does), which cannot drift the same way:
# every *.yaml file under a recognized label folder is always included.
_FIXTURE_LABELS = {"vulnerable", "safe", "unknown"}


def _fixture_result_matches_label(label: str, status: OverallStatus) -> bool:
    """Codex#6 (round 12, 2026-09-13), reproduced exactly as reported:
    `skos test` only ever checked that an assessment COMPLETED (was not
    POLICY_BLOCKED) - an engine that returned e.g. PASS for every single
    fixture, vulnerable ones included, still printed "N/N fixtures
    completed" and exited 0, never checking the result against what the
    fixture's own label (folder name) says it should be. Mirrors the same
    per-label expectation app/eval/metrics.py's compute_metrics() already
    encodes (known_risk_recall / false_positive_rate /
    unknown_appropriateness)."""
    if label == "vulnerable":
        return status in (OverallStatus.FAIL, OverallStatus.CONDITIONAL)
    if label == "safe":
        return status is not OverallStatus.FAIL
    if label == "unknown":
        return status is OverallStatus.UNKNOWN
    return True  # an unrecognized label folder is not this check's concern


def _load_input(path: Path) -> AssessmentInput:
    # Codex#8 (round 11, 2026-09-13), reproduced exactly as reported: a bare
    # `yaml.safe_load()` here read the complete file before
    # AssessmentInput's own post-parse total-size validator ever ran -
    # SafeLoader prevents Python object construction but not parser
    # resource exhaustion (deeply nested flow collections, a large merge/
    # alias expansion), and nothing here caught yaml.YAMLError/
    # RecursionError/pydantic ValidationError, so a malformed or hostile
    # file escaped as a raw traceback instead of a clean exit code.
    # safe_load_bounded() (already used for rule/safe-test/knowledge front
    # matter) converts every way PyYAML can blow up into FrontMatterError;
    # main() below converts that and ValidationError into exit code 2.
    raw = safe_load_bounded(
        read_text_bounded(path, max_bytes=_MAX_ASSESSMENT_YAML_BYTES, what="assessment file"),
        max_bytes=_MAX_ASSESSMENT_YAML_BYTES,
        what="assessment file",
    )
    if not isinstance(raw, dict):
        raise FrontMatterError(f"assessment file must be a mapping, got {type(raw).__name__}")
    return AssessmentInput.model_validate(raw)


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

    # Codex#8 (round 5, 2026-09-12): a syntactically valid (even empty)
    # template catalogue can still be USELESS if the configured rules
    # reference safe_test_template ids it does not contain - a typo, or the
    # whole catalogue silently emptied by a SKOS_SAFE_TESTS_ROOT
    # misconfiguration. assess.py itself does not raise on that (a rule
    # still fires; it just loses its attached safe-test recommendation), so
    # this is the loud, load-time check operators get from running this
    # command before deploying.
    try:
        catalogue = load_rules(s.rules_root)
    except RuleLoadError as exc:
        print(
            f"INVALID: could not load {s.rules_root} to check safe-test coverage: {exc}",
            file=sys.stderr,
        )
        return 1
    unresolved = unresolved_safe_test_references(catalogue.rules, templates)
    if unresolved:
        print(
            "\nINVALID: rule(s) reference a safe-test template that does not exist:",
            file=sys.stderr,
        )
        for ref in unresolved:
            print(f"  {ref}", file=sys.stderr)
        return 1
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
    # Codex#5 (round 13, 2026-09-13), reproduced exactly as reported: this
    # always returned 0 - a root that could not even be safely snapshotted
    # (missing, not a directory, an unsafe ancestor) reported "loadable
    # units: 0" and exited success, with the actual ERROR-level issue
    # (recorded in report.issues, separate from the per-file report.skipped
    # printed above) never printed or checked anywhere.
    if report.error_count:
        print("\nERROR(S):", file=sys.stderr)
        for issue in report.issues:
            if issue.level is Level.ERROR:
                print(f"  {issue}", file=sys.stderr)
        return 1
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


def _run(
    inp: AssessmentInput,
    s: Settings,
    db: Path | None,
    *,
    packs: bool | None = None,
    pack_scope: str | None = None,
) -> AssessmentReport:
    """``packs``: True = core + installed packs (``skos assess``), False =
    core only with extensions ignored (``--no-packs``), None = core only
    (``skos test``; an extensions block is then rejected)."""
    catalogue = load_rules(s.rules_root)
    if packs:
        catalogue, _ = load_with_packs(catalogue)
        if pack_scope:
            catalogue = only_pack(catalogue, pack_scope)
    elif packs is False:
        catalogue.ignore_extensions = True
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
    if args.no_packs and args.only_pack:
        print("--no-packs and --only-pack cannot be combined", file=sys.stderr)
        return 2
    report = _run(
        _load_input(args.file), s, args.db, packs=not args.no_packs, pack_scope=args.only_pack
    )
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
    # Codex#2 (round 25, 2026-09-20), reproduced exactly as reported: unlike
    # assessment loading, this read the whole file (`truncate -s 1G` -> ~1 GiB
    # materialised) before pydantic ever looked at it. FrontMatterError /
    # OSError / UnicodeDecodeError / ValidationError are handled by main().
    report = AssessmentReport.model_validate_json(
        read_text_bounded(args.file, max_bytes=_MAX_REPORT_JSON_BYTES, what="report file")
    )
    print(render_text(report))
    return 3 if report.status is ReportStatus.POLICY_BLOCKED else 0


def _cmd_test(args: argparse.Namespace, s: Settings) -> int:
    fixtures_dir = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "assessments"
    if not fixtures_dir.exists():
        print("fixtures not available in this install", file=sys.stderr)
        return 2
    fixtures = sorted(
        (p.parent.name, p) for p in fixtures_dir.rglob("*.yaml") if p.parent.name in _FIXTURE_LABELS
    )
    failures = 0
    for label, path in fixtures:
        name = path.stem
        report = _run(_load_input(path), s, args.db)
        if report.status is ReportStatus.POLICY_BLOCKED:
            print(f"  {name:44} POLICY_BLOCKED")
            failures += 1
            continue
        assert report.result is not None
        r = report.result
        # Codex#6 (round 12, 2026-09-13), reproduced exactly as reported:
        # "completed without POLICY_BLOCKED" used to be the only bar - the
        # result is now also checked against what a fixture with this
        # LABEL is supposed to produce, so a deterministically-wrong
        # engine (e.g. one that always returns PASS) fails this smoke test
        # instead of silently reporting "N/N fixtures completed".
        ok = _fixture_result_matches_label(label, r.overall_status)
        flag = "" if ok else f"  <-- unexpected for a {label!r} fixture"
        print(f"  {name:44} {r.overall_status.value:11} hr={int(r.human_review_required)}{flag}")
        if not ok:
            failures += 1
    print(f"\n{len(fixtures) - failures}/{len(fixtures)} fixtures completed")
    return 1 if failures else 0


def _write_private(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def _assess_generated(text: str, s: Settings, pack_scope: str | None) -> tuple[str, int]:
    """(summary for the scan listing, 1 if it FAILed or did not complete)."""
    report = _run(
        AssessmentInput.model_validate(safe_load_bounded(
            text, max_bytes=_MAX_ASSESSMENT_YAML_BYTES, what="generated input"
        )),
        s, None, packs=True, pack_scope=pack_scope,
    )
    if report.result is None:
        return f"  -> {report.status.value}", 1
    groups = ", ".join(
        f"{g.group}={g.worst_status.value if g.worst_status else '-'}"
        for g in report.result.group_summaries
    )
    failed = report.result.overall_status is OverallStatus.FAIL
    return f"  -> {report.result.overall_status.value}  [{groups}]", int(failed)


def _pack_active(pack_id: str) -> bool:
    return any(
        a.pack_id == pack_id and a.verified is not None for a in verify_active()
    )


def _cmd_scan_mcp(args: argparse.Namespace, s: Settings) -> int:
    scans = scan_config(args.config)
    args.out.mkdir(mode=0o700, parents=True, exist_ok=True)
    worst = 0
    for scan in scans:
        text = assessment_yaml(scan, args.config.name)
        path = args.out / f"{scan.name}.yaml"
        _write_private(path, text)
        line = f"  {scan.name:28} {path}  ({len(scan.unknown())} unknown)"
        if args.assess:
            summary, failed = _assess_generated(text, s, None if args.full else "mcp")
            line += summary
            worst = max(worst, failed)
        print(line)

    # The whole agent: capability labels of every server (+ the client's own
    # tools), for the capgraph pack and for runtime enforcement.
    agent = agent_labels(scans, args.client)
    _write_private(args.out / "capability-labels.json", labels_json(agent, args.config.name))
    text = agent_yaml(agent, args.config.name)
    path = args.out / f"{AGENT_FILE_STEM}.yaml"
    _write_private(path, text)
    unknown = sum(1 for v in agent.facts().values() if v is None)
    line = f"  {'(agent)':28} {path}  ({unknown} unknown)"
    if args.assess:
        if _pack_active("capgraph"):
            summary, failed = _assess_generated(text, s, "capgraph")
            line += summary
            worst = max(worst, failed)
        else:
            line += "  -> not assessed (the capgraph pack is not installed)"
    print(line)
    if args.client is None:
        print("  note: --client not given; the client's built-in tools are not counted")
    return worst if args.strict else 0


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
    p.add_argument(
        "--no-packs", action="store_true",
        help="assess with the core rules only; extensions blocks are ignored",
    )
    p.add_argument(
        "--only-pack", metavar="PACK_ID",
        help="evaluate only this installed pack's rules (the report says so)",
    )
    p.set_defaults(func=_cmd_assess)

    p = sub.add_parser("report")
    p.add_argument("file", type=Path)
    p.set_defaults(func=_cmd_report)

    p = sub.add_parser("test")
    p.add_argument("--db", type=Path)
    p.set_defaults(func=_cmd_test)

    register_pack_commands(sub)

    p = sub.add_parser("scan", help="derive assessment inputs from real configuration")
    scan_sub = p.add_subparsers(dest="scan_kind", required=True)
    p = scan_sub.add_parser("mcp", help="MCP client config (.mcp.json etc.)")
    p.add_argument("config", type=Path)
    p.add_argument("--out", type=Path, default=Path("mcp-assessments"))
    p.add_argument(
        "--assess", action="store_true", help="also assess each server (needs the mcp pack)"
    )
    p.add_argument("--strict", action="store_true", help="exit 1 if any server FAILs")
    p.add_argument(
        "--full", action="store_true",
        help="with --assess: also evaluate the core rules (default: the mcp pack's rules only,"
        " since one server's config does not describe the whole agent system)",
    )
    p.add_argument(
        "--client", choices=CLIENTS,
        help="the agent client whose built-in tools count toward the agent's capabilities"
        " (none = no built-in tools); without it no capability is claimed absent",
    )
    p.set_defaults(func=_cmd_scan_mcp)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    settings = Settings.from_env()
    try:
        return int(args.func(args, settings))
    except PackLoadError as exc:
        print(f"pack error: {exc}", file=sys.stderr)
        return 2
    except PACK_ERRORS as exc:
        print(f"pack error: {exc}", file=sys.stderr)
        return 1
    except ConfigError as exc:
        print(f"invalid MCP config: {exc}", file=sys.stderr)
        return 2
    except (RuleLoadError, SafeTestLoadError) as exc:
        print(f"catalogue error: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"invalid JSON: {exc}", file=sys.stderr)
        return 2
    # Codex#8 (round 11, 2026-09-13): a malformed/hostile assessment YAML
    # file (via _load_input()) used to escape as a raw traceback instead of
    # this CLI's normal exit-code-2 usage-error path.
    except FrontMatterError as exc:
        print(f"invalid assessment file: {exc}", file=sys.stderr)
        return 2
    # Codex#1 (round 22, 2026-09-19): `str(ValidationError)` embeds the
    # rejected value (`input_value=...`), so a credential that the
    # validators just refused was printed back to the terminal / CI log.
    except ValidationError as exc:
        print(f"invalid assessment file: {format_validation_error(exc)}", file=sys.stderr)
        return 2
    # Codex#10 (round 12, 2026-09-13), reproduced exactly as reported:
    # `_load_input()`'s / `_cmd_report()`'s `path.read_text()` is not
    # covered by any of the catches above - a FILE that merely EXISTS
    # (the only thing `_cmd_assess()`/`_cmd_report()` check) can still be
    # a directory (`IsADirectoryError`, an `OSError` subclass), unreadable
    # (`PermissionError`), or not valid UTF-8 (`UnicodeDecodeError`), and
    # each escaped as a raw traceback instead of this CLI's normal
    # exit-code-2 usage-error path.
    except (OSError, UnicodeDecodeError) as exc:
        print(f"could not read input file: {exc}", file=sys.stderr)
        return 2
    # Codex round-34 (2026-09-26), reproduced exactly as reported: a corrupt
    # `--db` index raised sqlite3.DatabaseError (lazily, inside connect()'s
    # FTS5 probe) straight out of `skos assess` as a raw traceback, whose
    # message quotes content from the file. Same exit code as a
    # POLICY_BLOCKED report; only describe_db_error()'s category is printed.
    except INDEX_OPEN_ERRORS as exc:
        print(f"knowledge index unusable: {describe_db_error(exc)}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
