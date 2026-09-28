#!/usr/bin/env python3
"""Issue a signed license file for a commercial pack.

    <print the Ed25519 private key (raw 32 bytes, base64) from your secret store> \\
      | python scripts/issue_license.py --pack mcppro --license-id L-0001 \\
          --licensee "Example Corp" --expires 2027-09-30 \\
          --key-id kagioneko-2026-01 --out ./out

Writes ``<out>/<pack>.lic`` and ``<out>/<pack>.lic.sig``; the customer copies
both to ``~/.config/skos/licenses/``. The key is read from stdin only.

Exit codes: 0 ok, 1 build error, 2 usage error.
"""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.packs.build import BuildError, issue_license, private_key_from_b64  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", required=True)
    parser.add_argument("--license-id", required=True)
    parser.add_argument("--licensee", required=True)
    parser.add_argument("--issued", type=date.fromisoformat, default=date.today())
    parser.add_argument("--expires", type=date.fromisoformat, required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    if sys.stdin.isatty():
        print("refusing to read a private key from a terminal; pipe it in", file=sys.stderr)
        return 2
    try:
        path = issue_license(
            args.out,
            pack=args.pack,
            license_id=args.license_id,
            licensee=args.licensee,
            issued=args.issued,
            expires=args.expires,
            key=private_key_from_b64(sys.stdin.read()),
            key_id=args.key_id,
        )
    except BuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {path} and {path.name}.sig")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
