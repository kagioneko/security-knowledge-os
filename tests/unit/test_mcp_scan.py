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
        "gh": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
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
    assert facts["gh"]["third_party"] is False
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
    # Client-side facts are not server properties (Codex review F04):
    # connecting via loopback does not prove a loopback-only bind, and
    # sending a credential does not prove the server requires one.
    assert facts["loop"]["bind_scope"] is None
    assert facts["lan"]["transport"] == "sse" and facts["lan"]["bind_scope"] == "private"
    assert facts["cloud"]["bind_scope"] == "public"
    assert facts["cloud"]["auth_required"] is None
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



def test_package_identity_is_exact(tmp_path: Path) -> None:
    """Codex review F08: a same-named package under another scope is not the
    known server, and the PyPI first-party list does not apply to npm."""
    facts = _scan(tmp_path, {"mcpServers": {
        "impostor": {"command": "npx", "args": ["@unrelated/mcp-server-time@1.2.3"]},
        "npm-fetch": {"command": "npx", "args": ["mcp-server-fetch@1.0.0"]},
    }})
    for name in ("impostor", "npm-fetch"):
        assert facts[name]["third_party"] is True
        assert facts[name]["shell_exec"] is None and facts[name]["fs_scope"] is None


@pytest.mark.parametrize(
    ("args", "sandboxed", "pinned"),
    [
        (["run", "-v", "/:/host", "img:latest"], False, False),
        (["run", "img:latest", "--arg", "@sha256:" + "a" * 64], True, False),
        (["run", "--privileged", "img@sha256:" + "b" * 64], False, True),
        (["run", "--network=host", "img"], False, False),
        (["run", "-v", "/srv/data:/data", "img"], None, False),
        (["compose", "up"], None, None),
    ],
)
def test_container_arguments(tmp_path: Path, args: list[str], sandboxed: bool | None,
                             pinned: bool | None) -> None:
    """Codex review F09: the image is the first positional argument after the
    options, and unsafe options/mounts are not reported as sandboxed."""
    facts = _scan(tmp_path, {"mcpServers": {"c": {"command": "docker", "args": args}}})
    assert facts["c"]["sandboxed"] is sandboxed
    assert facts["c"]["version_pinned"] is pinned


@pytest.mark.parametrize(
    ("path", "scope"),
    [
        ("/srv/app/../..", "root"),
        ("/srv/app", "project"),
        ("~/", "home"),
        ("$HOME/work", "project"),
        ("/home", "home"),
        ("./data", None),
        ("$DATA_DIR", None),
    ],
)
def test_fs_scope_normalizes_paths(tmp_path: Path, path: str, scope: str | None) -> None:
    """Codex review F10: '..' is resolved; unresolvable paths are unknown."""
    facts = _scan(tmp_path, {"mcpServers": {"fs": {
        "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", path]}}})
    assert facts["fs"]["fs_scope"] == scope


def test_url_credentials_are_detected(tmp_path: Path) -> None:
    """Codex review F11: userinfo and credential query parameters count."""
    facts = _scan(tmp_path, {"mcpServers": {
        "a": {"type": "http", "url": "https://user:" + FAKE_KEY + "@mcp.example.com/"},
        "b": {"type": "http", "url": "https://mcp.example.com/?api_key=" + FAKE_KEY},
    }})
    for name in ("a", "b"):
        assert facts[name]["secrets_in_config"] is True
        assert facts[name]["token_scope"] is None


def test_malformed_url_does_not_leak(tmp_path: Path) -> None:
    """Codex review F03: urlsplit's error quotes the URL; ours must not."""
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps({"mcpServers": {"s": {
        "url": "https://user:" + FAKE_KEY + "@example\uff0fhost.com/mcp"}}}))
    with pytest.raises(ConfigError) as err:
        scan_config(path)
    assert FAKE_KEY not in str(err.value)


def test_same_project_basename_keeps_both_servers(tmp_path: Path) -> None:
    """Codex review F12: servers under /work/a/app and /work/b/app both survive."""
    facts = _scan(tmp_path, {"projects": {
        "/work/a/app": {"mcpServers": {"s": {"command": "node", "args": ["a.js"]}}},
        "/work/b/app": {"mcpServers": {"s": {"command": "node", "args": ["b.js"]}}},
    }})
    assert sorted(facts) == ["app.s", "app.s-2"]


@pytest.mark.parametrize(
    "server",
    [{"command": "npx", "args": None}, {"command": "npx", "args": "x"},
     {"command": "npx", "env": ["A"]}, {"url": 5}],
)
def test_malformed_server_shapes_are_config_errors(tmp_path: Path,
                                                  server: dict[str, Any]) -> None:
    """Codex review F15: wrong field shapes are ConfigError, not TypeError."""
    if server.get("args", 0) is None:
        # args: null is simply "no arguments"
        _scan(tmp_path, {"mcpServers": {"s": server}})
        return
    with pytest.raises(ConfigError):
        _scan(tmp_path, {"mcpServers": {"s": server}})


def test_huge_integer_json_is_a_config_error(tmp_path: Path) -> None:
    path = tmp_path / ".mcp.json"
    path.write_text('{"mcpServers": {"s": {"command": "x", "n": ' + "9" * 5000 + "}}}")
    with pytest.raises(ConfigError):
        scan_config(path)
