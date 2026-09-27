"""`skos pack ...` end to end, and `skos assess` with / without packs."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.cli import main

_MANIFEST = {
    "pack_api": 1,
    "pack_id": "demo",
    "name": "Demo Pack",
    "version": "2026.10.0",
    "release_date": "2026-10-01",
    "min_engine_version": "0.2.0",
    "classification": "public",
    "publisher": "tester",
    "license": "Apache-2.0",
    "description": "demo pack for CLI tests",
    "facts": {
        "demo_transport": {"type": "str", "values": ["stdio", "http"]},
        "demo_auth_required": {"type": "bool"},
    },
}

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


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    src = tmp_path / "src"
    (src / "rules").mkdir(parents=True)
    (src / "manifest.json").write_text(json.dumps(_MANIFEST))
    (src / "rules" / "DEMO-001.yaml").write_text(_RULE)
    monkeypatch.setenv("SKOS_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("SKOS_CONFIG_DIR", str(tmp_path / "cfg"))
    yield tmp_path


def _assessment(tmp_path: Path) -> Path:
    path = tmp_path / "in.yaml"
    path.write_text(
        "name: t\nextensions:\n  demo:\n    transport: http\n    auth_required: false\n"
    )
    return path


def test_pack_lifecycle(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    src, dist = env / "src", env / "dist"
    assert main(["pack", "build", str(src), "--out", str(dist)]) == 0
    zip_v1 = dist / "demo-2026.10.0.zip"
    assert "UNSIGNED" in capsys.readouterr().out

    assert main(["pack", "inspect", str(zip_v1)]) == 0
    out = capsys.readouterr().out
    assert "pack_id       : demo" in out and "rules/DEMO-001.yaml" in out

    assert main(["pack", "verify", str(zip_v1)]) == 1  # unsigned
    assert "unsigned" in capsys.readouterr().err
    assert main(["pack", "verify", str(zip_v1), "--allow-unsigned"]) == 0

    src_in = _assessment(env)
    assert main(["assess", str(src_in)]) == 3  # not installed -> POLICY_BLOCKED
    capsys.readouterr()

    assert main(["pack", "install", str(zip_v1), "--allow-unsigned"]) == 0
    assert "Added:\n  - DEMO-001" in capsys.readouterr().out
    assert main(["pack", "list"]) == 0
    assert "operator-approved" in capsys.readouterr().out

    assert main(["assess", str(src_in)]) == 0
    out = capsys.readouterr().out
    assert "DEMO-001" in out and "packs: demo 2026.10.0 [public, operator-approved]" in out
    assert main(["assess", str(src_in), "--no-packs"]) == 0
    out = capsys.readouterr().out
    assert "DEMO-001" not in out and "extensions: IGNORED" in out
    assert main(["assess", str(src_in), "--only-pack", "demo"]) == 0
    out = capsys.readouterr().out
    assert "rule scope: pack:demo only" in out and "OUT-001" not in out
    assert main(["assess", str(src_in), "--only-pack", "demo", "--no-packs"]) == 2
    capsys.readouterr()

    # v2 lowers severity: diff flags it, install refuses without approval
    (src / "rules" / "DEMO-001.yaml").write_text(_RULE.replace("high", "low"))
    assert main(["pack", "build", str(src), "--out", str(dist), "--version", "2026.11.0"]) == 0
    zip_v2 = dist / "demo-2026.11.0.zip"
    capsys.readouterr()
    assert main(["pack", "diff", str(zip_v1), str(zip_v2)]) == 1
    assert "severity lowered high -> low" in capsys.readouterr().out
    assert main(["pack", "install", str(zip_v2), "--allow-unsigned"]) == 1
    assert "NOT installed" in capsys.readouterr().err
    assert main(["pack", "install", str(zip_v2), "--allow-unsigned", "--approve-sensitive"]) == 0

    assert main(["pack", "rollback", "demo", "2026.10.0"]) == 0
    assert "rolled back demo to 2026.10.0" in capsys.readouterr().out
    assert main(["pack", "remove", "demo"]) == 0
    assert main(["pack", "list"]) == 0
    assert "no packs installed" in capsys.readouterr().out

    audit = (env / "home" / "audit.jsonl").read_text().splitlines()
    assert [json.loads(line)["action"] for line in audit][-2:] == ["rollback", "remove"]


def test_tampered_install_stops_assess(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    main(["pack", "build", str(env / "src"), "--out", str(env / "dist")])
    main(["pack", "install", str(env / "dist" / "demo-2026.10.0.zip"), "--allow-unsigned"])
    rule = env / "home" / "versions" / "demo" / "2026.10.0" / "rules" / "DEMO-001.yaml"
    rule.write_text(_RULE.replace("high", "low"))
    capsys.readouterr()
    assert main(["assess", str(_assessment(env))]) == 2
    assert "pack error" in capsys.readouterr().err
    assert main(["pack", "list"]) == 1
