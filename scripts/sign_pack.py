#!/usr/bin/env python3
"""Hash a pack's files into its manifest and (optionally) sign it.

    # hashes only (an unsigned pack the operator enables with `skos packs enable`)
    python scripts/sign_pack.py path/to/skos_pack_x --hashes-only

    # hash + sign; the private key (base64 Ed25519 seed) is read from stdin
    vault kv get -field=ed25519_private_key secret/skos/pack-signing \\
      | python scripts/sign_pack.py path/to/skos_pack_x --key-id kagioneko-2026-01

The key is never echoed, written to disk, or accepted as an argument.

Exit codes: 0 ok, 1 build error, 2 usage error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.packs.build import (  # noqa: E402
    BuildError,
    private_key_from_b64,
    sign_manifest,
    update_manifest_files,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pack_dir", type=Path)
    parser.add_argument("--key-id")
    parser.add_argument("--hashes-only", action="store_true")
    args = parser.parse_args(argv)

    if not (args.pack_dir / "pack.yaml").is_file():
        print(f"no pack.yaml in {args.pack_dir}", file=sys.stderr)
        return 2
    if not args.hashes_only and not args.key_id:
        print("--key-id is required unless --hashes-only", file=sys.stderr)
        return 2
    try:
        update_manifest_files(args.pack_dir)
        if args.hashes_only:
            print(f"updated file hashes in {args.pack_dir / 'pack.yaml'}")
            return 0
        if sys.stdin.isatty():
            print("refusing to read a private key from a terminal; pipe it in", file=sys.stderr)
            return 2
        key = private_key_from_b64(sys.stdin.read())
        sign_manifest(args.pack_dir, key, args.key_id)
    except BuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"signed {args.pack_dir / 'pack.yaml'} with {args.key_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
