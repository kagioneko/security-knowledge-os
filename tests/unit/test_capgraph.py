"""Capability labels for the whole agent (`skos scan mcp` -> capgraph)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from app.adapters.capgraph import (
    AGENT_FILE_STEM,
    FACT_KEYS,
    LABELS,
    agent_labels,
)
from app.adapters.mcp_config import RESERVED_NAMES, scan_config

FAKE_SECRET = "ghp_" + "Z" * 36

FETCH = {"command": "uvx", "args": ["mcp-server-fetch==2025.4.7"]}
GITHUB = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github@2025.4.8"]}
TIME = {"command": "uvx", "args": ["mcp-server-time==2025.1.1"]}
SEARCH = {"command": "npx", "args": ["@modelcontextprotocol/server-brave-search@0.6.2"]}


def _scans(tmp_path: Path, servers: dict[str, Any]):  # type: ignore[no-untyped-def]
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps({"mcpServers": servers}))
    return scan_config(path)


def test_trifecta_across_servers(tmp_path: Path) -> None:
    home = str(Path.home())
    fs = {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem@1.0.0", home]}
    agent = agent_labels(
        _scans(tmp_path, {"fetch": FETCH, "files": fs, "github": GITHUB}), "none"
    )
    assert agent.labels["untrusted_input"] is True
    assert agent.labels["sensitive_read"] is True
    assert agent.labels["egress"] is True
    assert agent.labels["persistence"] is True
    assert agent.labels["exec"] is False  # every server is known to have no shell
    assert agent.contributors["sensitive_read"] == ["files", "github"]
    assert agent.contributors["untrusted_input"] == ["fetch", "github"]
    assert "sensitive_read <- files, github" in agent.notes()


def test_labels_of_known_servers(tmp_path: Path) -> None:
    agent = agent_labels(_scans(tmp_path, {
        "time": TIME, "search": SEARCH, "fetch": FETCH, "github": GITHUB,
        "project": {"command": "npx",
                    "args": ["@modelcontextprotocol/server-filesystem@1.0.0", "/srv/app"]},
        "mem": {"command": "npx", "args": ["@modelcontextprotocol/server-memory@1.0.0"]},
    }), "none")
    by = {s.name: s for s in agent.servers}
    assert by["time"].labels == dict.fromkeys(LABELS, False)
    assert by["search"].labels["untrusted_input"] is True
    assert by["search"].labels["sensitive_read"] is False
    # fetch can reach localhost and intranet URLs: not claimed either way
    assert by["fetch"].labels["sensitive_read"] is None
    assert by["fetch"].labels["persistence"] is False
    assert by["github"].labels["persistence"] is True
    assert by["github"].write_scope == "remote"
    # a project directory may hold secrets, but that is not visible
    assert by["project"].labels["sensitive_read"] is None
    assert by["project"].labels["persistence"] is True  # CI config, hooks, CLAUDE.md
    assert by["project"].write_scope == "project"
    assert by["mem"].labels["persistence"] is True  # loaded into later sessions


def test_unknown_servers_claim_nothing(tmp_path: Path) -> None:
    agent = agent_labels(_scans(tmp_path, {
        "local": {"command": "python", "args": ["./server.py"]},
        "remote": {"url": "https://mcp.example.com/sse", "type": "sse"},
        "impostor": {"command": "npx", "args": ["@unrelated/mcp-server-time@1.2.3"]},
    }), "none")
    for s in agent.servers:
        assert s.labels == dict.fromkeys(LABELS), s.name


def test_unsandboxed_shell_reads_and_persists(tmp_path: Path) -> None:
    dc = {"command": "npx", "args": ["@wonderwhy-er/desktop-commander@0.2.3"]}
    agent = agent_labels(_scans(tmp_path, {"dc": dc}), "none")
    labels = agent.servers[0].labels
    assert labels["exec"] is True
    assert labels["sensitive_read"] is labels["write"] is labels["persistence"] is True


def test_absence_needs_a_declared_client(tmp_path: Path) -> None:
    """Without --client the client's own tools are unknown: all-False servers
    must not add up to 'the agent cannot do this'."""
    scans = _scans(tmp_path, {"time": TIME})
    assert agent_labels(scans, "none").labels == dict.fromkeys(LABELS, False)
    assert agent_labels(scans, None).labels == dict.fromkeys(LABELS)
    assert any("--client" in n for n in agent_labels(scans, None).notes())


def test_claude_code_client_brings_every_capability(tmp_path: Path) -> None:
    agent = agent_labels(_scans(tmp_path, {"time": TIME}), "claude-code")
    assert agent.labels == dict.fromkeys(LABELS, True)
    assert agent.contributors["exec"] == ["client:claude-code"]
    assert agent.facts()["flow_gated"] is None  # never visible in a config
    assert set(agent.facts()) == set(FACT_KEYS)


def test_unknown_client_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown client"):
        agent_labels(_scans(tmp_path, {"time": TIME}), "cursor")


def test_server_cannot_take_the_agent_file_name(tmp_path: Path) -> None:
    assert AGENT_FILE_STEM in RESERVED_NAMES
    scans = _scans(tmp_path, {"_agent": TIME})
    assert scans[0].name != AGENT_FILE_STEM


def test_cli_writes_agent_outputs_without_config_values(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.cli import main

    monkeypatch.setenv("SKOS_HOME", str(tmp_path / "home"))  # no packs installed
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "fetch": FETCH,
        "github": {**GITHUB, "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": FAKE_SECRET}},
    }}))
    out = tmp_path / "out"
    assert main(["scan", "mcp", str(cfg), "--out", str(out), "--client", "claude-code"]) == 0
    printed = capsys.readouterr()
    agent_file = out / f"{AGENT_FILE_STEM}.yaml"
    labels_file = out / "capability-labels.json"
    for blob in (printed.out, printed.err, agent_file.read_text(), labels_file.read_text()):
        assert FAKE_SECRET not in blob
    for f in (agent_file, labels_file):
        assert f.stat().st_mode & 0o777 == 0o600
    doc = yaml.safe_load(agent_file.read_text())
    assert doc["extensions"]["capgraph"]["untrusted_input"] is True
    assert doc["extensions"]["capgraph"]["flow_gated"] is None
    labels = json.loads(labels_file.read_text())
    assert labels["schema"] == "capgraph/v0" and labels["client"] == "claude-code"
    assert set(labels["servers"]) == {"fetch", "github"}
    assert labels["contributors"]["egress"][0] == "client:claude-code"


def test_cli_assess_without_capgraph_pack_says_so(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from app import cli

    monkeypatch.setenv("SKOS_HOME", str(tmp_path / "home"))
    # the per-server assessment needs the mcp pack; stub it out here
    monkeypatch.setattr(cli, "_assess_generated", lambda text, s, scope: ("  -> stub", 0))
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"time": TIME}}))
    assert cli.main(["scan", "mcp", str(cfg), "--out", str(tmp_path / "o"), "--assess"]) == 0
    out = capsys.readouterr().out
    assert "not assessed (the capgraph pack is not installed)" in out
    assert "--client not given" in out
