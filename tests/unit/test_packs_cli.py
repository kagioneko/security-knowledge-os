"""`skos packs`, `skos assess` with packs / --no-packs, and `skos <pack> <cmd>`."""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.cli import BUILTIN_COMMANDS, _build_parser, main
from app.packs.build import update_manifest_files

_MANIFEST = """\
pack_api: 1
name: demo
version: 0.1.0
tier: free
publisher: tester
license: Apache-2.0
description: demo pack for CLI tests
facts:
  demo_transport: {type: str, values: [stdio, http]}
  demo_auth_required: {type: bool}
commands:
  hello: skos_pack_demo.cli:main
"""

_RULE = """\
id: DEMO-001
title: HTTP transport without authentication
category: agent-security
severity: high
conditions:
  all:
    - demo_transport: http
checks:
  - demo_auth_required: true
"""

_CLI = """\
def main(argv):
    print("hello from demo", *argv)
    return 0
"""


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    pack = tmp_path / "skos_pack_demo"
    (pack / "rules").mkdir(parents=True)
    (pack / "__init__.py").write_text("")
    (pack / "cli.py").write_text(_CLI)
    (pack / "rules" / "DEMO-001.yaml").write_text(_RULE)
    (pack / "pack.yaml").write_text(_MANIFEST)
    update_manifest_files(pack)
    monkeypatch.setenv("SKOS_PACK_DIRS", str(pack))
    monkeypatch.setenv("SKOS_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setattr("app.packs.discovery._from_entry_points", lambda: [])
    yield tmp_path
    for name in [m for m in sys.modules if m.startswith("skos_pack_demo")]:
        del sys.modules[name]


def _assessment(tmp_path: Path) -> Path:
    path = tmp_path / "in.yaml"
    path.write_text(
        "name: t\nextensions:\n  demo:\n    transport: http\n    auth_required: false\n"
    )
    return path


def test_builtin_command_list_matches_the_parser() -> None:
    parser = _build_parser()
    sub = next(a for a in parser._actions if a.dest == "command")
    assert set(sub.choices) == BUILTIN_COMMANDS  # type: ignore[arg-type]


def test_list_enable_verify_disable(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["packs"]) == 0
    assert "not trusted" in capsys.readouterr().out

    assert main(["packs", "enable", "demo"]) == 0
    out = capsys.readouterr().out
    assert "pinned manifest sha256" in out and "ships code for commands: hello" in out
    assert (env / "cfg" / "packs.yaml").stat().st_mode & 0o777 == 0o600

    assert main(["packs", "verify", "demo"]) == 0
    assert "active" in capsys.readouterr().out

    assert main(["packs", "disable", "demo"]) == 0
    assert main(["packs", "verify", "demo"]) == 1


def test_assess_uses_enabled_pack(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    src = _assessment(env)
    assert main(["assess", str(src)]) == 3  # pack not enabled -> POLICY_BLOCKED
    assert "no enabled pack named 'demo'" in capsys.readouterr().out

    main(["packs", "enable", "demo"])
    capsys.readouterr()
    assert main(["assess", str(src)]) == 0
    out = capsys.readouterr().out
    assert "DEMO-001" in out and "packs: demo 0.1.0 [free, user-enabled]" in out

    assert main(["assess", str(src), "--no-packs"]) == 0
    out = capsys.readouterr().out
    assert "DEMO-001" not in out and "extensions: IGNORED" in out


def test_tampered_enabled_pack_stops_assess(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    main(["packs", "enable", "demo"])
    (env / "skos_pack_demo" / "cli.py").write_text("print('changed')\n")
    capsys.readouterr()
    assert main(["assess", str(_assessment(env))]) == 2
    assert "pack error" in capsys.readouterr().err


def test_pack_command_dispatch(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["demo", "hello", "x"]) == 2  # not enabled yet
    main(["packs", "enable", "demo"])
    capsys.readouterr()
    assert main(["demo", "hello", "x"]) == 0
    assert "hello from demo x" in capsys.readouterr().out
    assert main(["demo", "nope"]) == 2
    assert "has no command 'nope'" in capsys.readouterr().err
