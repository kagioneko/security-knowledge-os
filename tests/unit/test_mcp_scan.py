"""`skos scan mcp`: facts derived from MCP client configs, and secrets never
leave the config."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from app.adapters.mcp_config import ConfigError, scan_config

# Assembled at runtime so no credential-shaped literal sits in the source.
FAKE_SECRET = "ghp_" + "Z" * 36
FAKE_KEY = "sk-" + "q" * 40


def _scan(tmp_path: Path, config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps(config))
    return {s.name: s.facts for s in scan_config(path)}


def test_stdio_servers(tmp_path: Path) -> None:
    home = str(Path.home())
    facts = _scan(tmp_path, {"mcpServers": {
        "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", home]},
        "fs-pinned": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem@2026.1.14", "/srv/app"],
        },
        "gh": {"command": "npx", "args": ["-y", "@example/server-github"],
               "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": FAKE_SECRET}},
        "fetch": {"command": "uvx", "args": ["mcp-server-fetch==2025.4.7"]},
        "ref": {"command": "npx", "args": ["some-tool"], "env": {"API_KEY": "${API_KEY}"}},
        "box": {"command": "docker", "args": ["run", "-i", "--rm", "img@sha256:" + "a" * 64]},
        "local": {"command": "python", "args": ["./server.py"]},
    }})
    assert facts["fs"]["transport"] == "stdio"
    assert facts["fs"]["version_pinned"] is False
    assert facts["fs"]["third_party"] is False
    assert facts["fs"]["fs_scope"] == "home"
    assert facts["fs"]["can_write"] is True and facts["fs"]["shell_exec"] is False
    assert facts["fs-pinned"]["version_pinned"] is True
    assert facts["fs-pinned"]["fs_scope"] == "project"

    assert facts["gh"]["secrets_in_config"] is True
    assert facts["gh"]["token_scope"] is None  # a token exists; its scope must be asked
    assert facts["gh"]["third_party"] is True
    assert facts["gh"]["ingests_untrusted_content"] is True

    assert facts["fetch"]["version_pinned"] is True
    assert facts["fetch"]["third_party"] is False
    assert facts["fetch"]["can_send"] is True

    assert facts["ref"]["secrets_in_config"] is False  # an env reference, not a literal
    assert facts["ref"]["token_scope"] is None

    assert facts["box"]["sandboxed"] is True and facts["box"]["version_pinned"] is True
    assert facts["local"]["version_pinned"] is None and facts["local"]["token_scope"] == "none"


def test_remote_servers(tmp_path: Path) -> None:
    facts = _scan(tmp_path, {"mcpServers": {
        "loop": {"type": "http", "url": "http://127.0.0.1:8080/mcp"},
        "lan": {"type": "sse", "url": "http://192.168.1.5:9000/sse"},
        "cloud": {"type": "http", "url": "https://mcp.example.com/",
                  "headers": {"Authorization": "Bearer " + FAKE_KEY}},
    }})
    assert facts["loop"]["bind_scope"] == "loopback"
    assert facts["lan"]["transport"] == "sse" and facts["lan"]["bind_scope"] == "private"
    assert facts["cloud"]["bind_scope"] == "public"
    assert facts["cloud"]["auth_required"] is True
    assert facts["cloud"]["secrets_in_config"] is True


def test_claude_json_projects_are_included(tmp_path: Path) -> None:
    facts = _scan(tmp_path, {"projects": {"/home/u/work/app": {"mcpServers": {
        "db": {"command": "node", "args": ["db.js"]}}}}})
    assert list(facts) == ["app.db"]


def test_secret_arguments_are_detected(tmp_path: Path) -> None:
    facts = _scan(tmp_path, {"mcpServers": {
        "x": {"command": "npx", "args": ["tool", "--api-key=" + FAKE_KEY]}}})
    assert facts["x"]["secrets_in_config"] is True


@pytest.mark.parametrize(
    "config",
    [{"mcpServers": {}}, {"other": 1}, {"mcpServers": {"bad": {"foo": 1}}}],
)
def test_invalid_configs(tmp_path: Path, config: dict[str, Any]) -> None:
    with pytest.raises(ConfigError):
        _scan(tmp_path, config)


def test_cli_output_never_contains_secret_values(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from app.cli import main

    cfg = tmp_path / "claude_desktop_config.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "gh": {"command": "npx", "args": ["-y", "@example/server-github", "--token", FAKE_SECRET],
               "env": {"GITHUB_TOKEN": FAKE_SECRET, "OPENAI_API_KEY": FAKE_KEY}},
    }}))
    out = tmp_path / "out"
    assert main(["scan", "mcp", str(cfg), "--out", str(out)]) == 0
    printed = capsys.readouterr()
    written = (out / "gh.yaml").read_text()
    for blob in (printed.out, printed.err, written):
        assert FAKE_SECRET not in blob and FAKE_KEY not in blob
    assert "secrets_in_config: true" in written
    assert (out / "gh.yaml").stat().st_mode & 0o777 == 0o600
