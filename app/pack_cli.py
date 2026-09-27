"""``skos pack ...`` - the Pack Manager CLI (Update Pack spec sections 7, 20).

    skos pack build SRC [--out DIR] [--version V] [--sign --key-id ID]   (key on stdin)
    skos pack inspect ZIP        manifest, contents, trust - changes nothing
    skos pack verify ZIP         every check install would run - changes nothing
    skos pack diff OLD.zip NEW.zip
    skos pack install ZIP [--allow-unsigned] [--approve-sensitive]
    skos pack list               installed packs, re-verified
    skos pack rollback PACK_ID VERSION [--approve-sensitive]
    skos pack remove PACK_ID

Exit codes: 0 ok, 1 verification failed / needs approval, 2 usage error.
"""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from app.config import Settings
from app.packs.archive import PackArchiveError, read_pack_zip, read_zip_bytes
from app.packs.build import BuildError, build_pack, private_key_from_b64
from app.packs.diff import diff_rules
from app.packs.store import (
    PackStoreError,
    install,
    load_state,
    plan_install,
    remove,
    rollback,
    skos_home,
    verify_active,
)
from app.packs.trusted_keys import TRUSTED_KEYS
from app.packs.verify import PackVerifyError, parse_manifest, verify_pack
from app.reviewer.report import _safe_line
from app.reviewer.rule_loader import load_rules

PACK_ERRORS = (PackArchiveError, PackVerifyError, PackStoreError, BuildError)


def _engine() -> str:
    from app import __version__

    return __version__


def _cmd_build(args: argparse.Namespace, s: Settings) -> int:
    key = None
    if args.sign:
        if not args.key_id:
            print("--sign needs --key-id", file=sys.stderr)
            return 2
        if sys.stdin.isatty():
            print("refusing to read a private key from a terminal; pipe it in", file=sys.stderr)
            return 2
        key = private_key_from_b64(sys.stdin.read())
    out = build_pack(args.src, args.out, version=args.version, key=key, key_id=args.key_id)
    print(f"built {out}{' (signed)' if key else ' (UNSIGNED)'}")
    return 0


def _cmd_inspect(args: argparse.Namespace, s: Settings) -> int:
    files = read_pack_zip(read_zip_bytes(args.zip))
    m, sha = parse_manifest(files)
    rules = sorted(p for p in files if p.startswith("rules/"))
    print(f"pack_id       : {m.pack_id}")
    print(f"name          : {_safe_line(m.name)}")
    print(f"version       : {m.version}  (released {m.release_date.isoformat()})")
    print(f"classification: {m.classification.value}")
    print(f"publisher     : {m.publisher}")
    print(f"license       : {m.license}")
    print(f"engine        : >= {m.min_engine_version}"
          + (f", <= {m.max_engine_version}" if m.max_engine_version else ""))
    # Presence only - inspect verifies nothing (`skos pack verify` does).
    print("signature     : "
          + ("present (NOT verified here - run `skos pack verify`)"
             if "signature.sig" in files else "none"))
    print(f"manifest sha256: {sha}")
    print(f"rules ({len(rules)}):")
    for rule in rules:
        print(f"  - {rule}")
    return 0


def _cmd_verify(args: argparse.Namespace, s: Settings) -> int:
    files = read_pack_zip(read_zip_bytes(args.zip))
    verified = verify_pack(
        files, trusted=TRUSTED_KEYS, engine_version=_engine(), today=date.today(),
        allow_unsigned=args.allow_unsigned,
    )
    m = verified.manifest
    print(f"OK {m.pack_id} {m.version} [{m.classification.value}] trust={verified.trust.value}"
          f" rules={len(verified.catalogue.rules)}")
    return 0


def _cmd_diff(args: argparse.Namespace, s: Settings) -> int:
    def rules(path: Path):  # type: ignore[no-untyped-def]
        return verify_pack(
            read_pack_zip(read_zip_bytes(path)), trusted=TRUSTED_KEYS, engine_version=_engine(),
            today=date.today(), allow_unsigned=True, require_license=False,
        ).catalogue.rules

    diff = diff_rules(rules(args.old), rules(args.new))
    print("\n".join(diff.lines()))
    return 1 if diff.sensitive else 0


def _cmd_install(args: argparse.Namespace, s: Settings) -> int:
    plan = plan_install(args.zip, allow_unsigned=args.allow_unsigned)
    m = plan.verified.manifest
    old = plan.previous.version if plan.previous else "not installed"
    print(f"{m.pack_id}: {old} -> {m.version} [{m.classification.value}, "
          f"{plan.verified.trust.value}]")
    print("\n".join(plan.diff.lines()))
    if plan.needs_approval and not args.approve_sensitive:
        print("\nNOT installed: review the changes above, then re-run with --approve-sensitive",
              file=sys.stderr)
        return 1
    install(
        args.zip, load_rules(s.rules_root),
        allow_unsigned=args.allow_unsigned, approve_sensitive=args.approve_sensitive,
    )
    print(f"installed and activated {m.pack_id} {m.version} ({skos_home()})")
    return 0


def _cmd_list(args: argparse.Namespace, s: Settings) -> int:
    state = load_state()
    active = verify_active()  # also reconciles active/ against the registry
    if not active:
        print("no packs installed")
        return 0
    failed = 0
    for a in active:
        info = state.packs.get(a.pack_id)
        version = info.version if info else "?"
        if a.verified is not None and info is not None:
            v = a.verified
            note = f" ({v.license_note})" if v.license_note else ""
            print(f"  {a.pack_id:12} {version:11} [{info.classification.value}] "
                  f"{v.trust.value}  rules={len(v.catalogue.rules)}{note}")
        else:
            failed += 1
            print(f"  {a.pack_id:12} {version:11} ERROR: {a.problem}")
        if info is not None and info.history:
            print(f"      previous versions: {', '.join(info.history)}")
    return 1 if failed else 0


def _cmd_rollback(args: argparse.Namespace, s: Settings) -> int:
    diff = rollback(
        args.pack_id, args.version, load_rules(s.rules_root),
        approve_sensitive=args.approve_sensitive,
    )
    print("\n".join(diff.lines()))
    print(f"rolled back {args.pack_id} to {args.version}")
    return 0


def _cmd_remove(args: argparse.Namespace, s: Settings) -> int:
    remove(args.pack_id)
    print(f"removed {args.pack_id} (archives and versions kept for rollback history)")
    return 0


def register(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    pack = sub.add_parser("pack", help="Update Pack manager (build/verify/install/rollback)")
    ps = pack.add_subparsers(dest="pack_command", required=True)

    p = ps.add_parser("build")
    p.add_argument("src", type=Path)
    p.add_argument("--out", type=Path, default=Path("dist"))
    p.add_argument("--version")
    p.add_argument("--sign", action="store_true", help="sign; private key read from stdin")
    p.add_argument("--key-id")
    p.set_defaults(func=_cmd_build)

    p = ps.add_parser("inspect")
    p.add_argument("zip", type=Path)
    p.set_defaults(func=_cmd_inspect)

    p = ps.add_parser("verify")
    p.add_argument("zip", type=Path)
    p.add_argument("--allow-unsigned", action="store_true")
    p.set_defaults(func=_cmd_verify)

    p = ps.add_parser("diff")
    p.add_argument("old", type=Path)
    p.add_argument("new", type=Path)
    p.set_defaults(func=_cmd_diff)

    p = ps.add_parser("install")
    p.add_argument("zip", type=Path)
    p.add_argument("--allow-unsigned", action="store_true",
                   help="accept a pack without a trusted signature (after reviewing it)")
    p.add_argument("--approve-sensitive", action="store_true",
                   help="apply sensitive changes (severity lowered, human gate removed, ...)")
    p.set_defaults(func=_cmd_install)

    p = ps.add_parser("list")
    p.set_defaults(func=_cmd_list)

    p = ps.add_parser("rollback")
    p.add_argument("pack_id")
    p.add_argument("version")
    p.add_argument("--approve-sensitive", action="store_true")
    p.set_defaults(func=_cmd_rollback)

    p = ps.add_parser("remove")
    p.add_argument("pack_id")
    p.set_defaults(func=_cmd_remove)
