"""Derive MCP-pack assessment inputs from an MCP client configuration
(``.mcp.json``, ``claude_desktop_config.json``, ``~/.claude.json``).

One input per configured server, carrying ``extensions.mcp`` facts for the
``mcp`` Update Pack. Only what the configuration actually shows is filled in;
everything else stays ``null`` (= not stated) so the assessment asks for it
instead of guessing.

Secrets: environment values, header values and arguments are inspected only
to decide ``secrets_in_config`` (true/false). No value from the configuration
- secret or not, other than the server name and the package name - is ever
written to the output.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

MAX_CONFIG_BYTES = 20_000_000

FACT_KEYS = (
    "transport",
    "bind_scope",
    "auth_required",
    "shell_exec",
    "per_call_approval",
    "fs_scope",
    "sandboxed",
    "ingests_untrusted_content",
    "can_write",
    "can_send",
    "third_party",
    "tool_descriptions_reviewed",
    "secrets_in_config",
    "token_scope",
    "version_pinned",
)

_SECRET_NAME = r"(?i)(key|token|secret|passw|pat\b|credential|auth|cookie|session)"
_ENV_REFERENCE = r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$"
_SECRET_ARG = (
    r"(?i)^--?(api[-_]?key|token|secret|password|auth)(=|$)"
    r"|^(sk-|ghp_|gho_|github_pat_|xox[bpas]-|AKIA|AIza)"
)
_PINNED_NPM = r"^(@[a-z0-9._-]+/)?[a-z0-9._-]+@\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$"
_PINNED_PY = r"^[A-Za-z0-9._-]+(\[[A-Za-z0-9,._-]+\])?==\d+(\.\d+)*$"

# Reference servers published by the MCP project itself.
_FIRST_PARTY_PREFIXES = ("@modelcontextprotocol/",)
_FIRST_PARTY_PY = {"mcp-server-fetch", "mcp-server-git", "mcp-server-time"}


@dataclass(frozen=True)
class _Profile:
    shell_exec: bool | None = None
    can_write: bool | None = None
    can_send: bool | None = None
    ingests_untrusted_content: bool | None = None
    touches_fs: bool = False  # derive fs_scope from path arguments


# Capabilities of well-known servers, by package name without scope/version.
_KNOWN: dict[str, _Profile] = {
    "server-filesystem": _Profile(False, True, False, None, touches_fs=True),
    "server-fetch": _Profile(False, False, True, True),
    "mcp-server-fetch": _Profile(False, False, True, True),
    "server-github": _Profile(False, True, True, True),
    "github-mcp-server": _Profile(False, True, True, True),
    "server-gitlab": _Profile(False, True, True, True),
    "server-slack": _Profile(False, True, True, True),
    "server-puppeteer": _Profile(False, False, True, True),
    "mcp": _Profile(False, False, True, True),  # @playwright/mcp
    "server-brave-search": _Profile(False, False, True, True),
    "server-git": _Profile(False, True, False, None, touches_fs=True),
    "mcp-server-git": _Profile(False, True, False, None, touches_fs=True),
    "server-memory": _Profile(False, True, False, False),
    "mcp-server-time": _Profile(False, False, False, False),
    "desktop-commander": _Profile(True, True, True, None, touches_fs=True),
}


class ConfigError(ValueError):
    """The file is not a readable MCP client configuration."""


@dataclass
class ServerScan:
    name: str
    package: str | None
    facts: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def unknown(self) -> list[str]:
        return [k for k in FACT_KEYS if self.facts.get(k) is None]


def _safe_name(raw: str, taken: set[str]) -> str:
    base = re.sub(r"[^A-Za-z0-9_.-]", "-", raw)[:48].strip("-.") or "server"
    name, n = base, 2
    while name in taken:
        name, n = f"{base}-{n}", n + 1
    taken.add(name)
    return name


def _host_scope(host: str | None) -> str | None:
    if not host:
        return None
    if host == "localhost":
        return "loopback"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "public"  # a DNS name: assume reachable unless shown otherwise
    if ip.is_loopback:
        return "loopback"
    if ip.is_private or ip in ipaddress.ip_network("100.64.0.0/10"):
        return "private"
    return "public"


def _is_literal_secret(name: str, value: object) -> bool:
    return (
        isinstance(value, str)
        and value.strip() != ""
        and re.search(_SECRET_NAME, name) is not None
        and re.fullmatch(_ENV_REFERENCE, value.strip()) is None
    )


def _package_arg(command: str, args: list[str]) -> tuple[str | None, str]:
    """(package spec, ecosystem) for launcher commands, else (None, "")."""
    base = PurePosixPath(command).name
    rest = list(args)
    if base in ("pnpm", "yarn", "npm") and rest[:1] in (["dlx"], ["exec"]):
        rest = rest[1:]
        base = "npx"
    if base in ("npx", "bunx"):
        skip_next = False
        for arg in rest:
            if skip_next:
                skip_next = False
                continue
            if arg in ("-p", "--package"):
                skip_next = True
                continue
            if not arg.startswith("-"):
                return arg, "npm"
        return None, "npm"
    if base in ("uvx", "pipx"):
        if base == "pipx" and rest[:1] == ["run"]:
            rest = rest[1:]
        for i, arg in enumerate(rest):
            if arg == "--from" and i + 1 < len(rest):
                return rest[i + 1], "pypi"
            if not arg.startswith("-"):
                return arg, "pypi"
        return None, "pypi"
    if base in ("docker", "podman"):
        return None, "container"
    return None, ""


def _package_base(spec: str, ecosystem: str) -> str:
    if ecosystem == "npm":
        name = spec[1:].split("@", 1)[0] if spec.startswith("@") else spec.split("@", 1)[0]
        if spec.startswith("@"):
            name = "@" + name
        return name.rsplit("/", 1)[-1]
    return re.split(r"[=<>\[@ ]", spec, maxsplit=1)[0]


def _fs_scope(args: list[str], package: str | None) -> str | None:
    home = str(Path.home())
    paths = [a for a in args if a.startswith(("/", "~", "$HOME")) and a != package]
    if not paths:
        return None
    scopes = []
    for p in paths:
        norm = p.rstrip("/") or "/"
        if norm == "/":
            scopes.append("root")
        elif norm in ("~", "$HOME", "${HOME}", home) or re.fullmatch(r"/(home|Users)/[^/]+", norm):
            scopes.append("home")
        else:
            scopes.append("project")
    for scope in ("root", "home", "project"):
        if scope in scopes:
            return scope
    return None  # pragma: no cover


def scan_server(raw_name: str, cfg: dict[str, Any], taken: set[str]) -> ServerScan:
    facts: dict[str, Any] = {k: None for k in FACT_KEYS}
    notes: list[str] = []
    url = cfg.get("url")
    kind = str(cfg.get("type", "")).lower()
    package: str | None = None
    secret_seen = False
    token_seen = False

    if isinstance(url, str) or kind in ("http", "sse", "streamable-http"):
        facts["transport"] = "sse" if kind == "sse" else "http"
        host = urlsplit(url).hostname if isinstance(url, str) else None
        facts["bind_scope"] = _host_scope(host)
        raw_headers = cfg.get("headers")
        headers: dict[str, Any] = raw_headers if isinstance(raw_headers, dict) else {}
        for hname, hval in headers.items():
            if re.search(_SECRET_NAME, str(hname)):
                token_seen = True
                facts["auth_required"] = True
                if _is_literal_secret(str(hname), hval):
                    secret_seen = True
        if isinstance(url, str) and url.startswith("http://") and facts["bind_scope"] != "loopback":
            notes.append("remote server over plain http (no TLS)")
    elif isinstance(cfg.get("command"), str):
        facts["transport"] = "stdio"
        command = cfg["command"]
        args = [str(a) for a in cfg.get("args", []) if isinstance(a, (str, int, float))]
        spec, ecosystem = _package_arg(command, args)
        if ecosystem == "container":
            facts["sandboxed"] = not any(
                a in ("--privileged", "--network=host") or a.startswith("-v/:") for a in args
            )
            facts["version_pinned"] = any("@sha256:" in a for a in args)
        elif spec is not None:
            package = _package_base(spec, ecosystem)
            pattern = _PINNED_NPM if ecosystem == "npm" else _PINNED_PY
            facts["version_pinned"] = re.fullmatch(pattern, spec) is not None
            facts["third_party"] = not (
                spec.startswith(_FIRST_PARTY_PREFIXES) or package in _FIRST_PARTY_PY
            )
            profile = _KNOWN.get(package)
            if profile is not None:
                for key in ("shell_exec", "can_write", "can_send", "ingests_untrusted_content"):
                    facts[key] = getattr(profile, key)
                facts["fs_scope"] = _fs_scope(args, spec) if profile.touches_fs else "none"
        else:
            facts["third_party"] = None  # a local script: who wrote it is not visible here
        for arg in args:
            if re.search(_SECRET_ARG, arg):
                secret_seen = token_seen = True
    else:
        raise ConfigError(f"server {raw_name!r} has neither 'command' nor 'url'")

    raw_env = cfg.get("env")
    env: dict[str, Any] = raw_env if isinstance(raw_env, dict) else {}
    for ename, evalue in env.items():
        if re.search(_SECRET_NAME, str(ename)):
            token_seen = True
            if _is_literal_secret(str(ename), evalue):
                secret_seen = True
    facts["secrets_in_config"] = secret_seen
    facts["token_scope"] = None if token_seen else "none"
    return ServerScan(_safe_name(raw_name, taken), package, facts, notes)


def load_config(path: Path) -> dict[str, dict[str, Any]]:
    """``{server name: server config}`` from the top-level ``mcpServers`` and,
    for ``~/.claude.json``, every ``projects.<path>.mcpServers``."""
    try:
        with path.open("rb") as fh:
            raw = fh.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise ConfigError(f"cannot read config ({type(exc).__name__})") from None
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError("config file is too large")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ConfigError("config is not valid UTF-8 JSON") from None
    if not isinstance(data, dict):
        raise ConfigError("config must be a JSON object")
    servers: dict[str, dict[str, Any]] = {}
    top = data.get("mcpServers")
    if isinstance(top, dict):
        servers.update({str(k): v for k, v in top.items() if isinstance(v, dict)})
    projects = data.get("projects")
    if isinstance(projects, dict):
        for project, pdata in projects.items():
            inner = pdata.get("mcpServers") if isinstance(pdata, dict) else None
            if isinstance(inner, dict):
                label = PurePosixPath(str(project)).name or "project"
                for k, v in inner.items():
                    if isinstance(v, dict):
                        servers[f"{label}.{k}"] = v
    if not servers:
        raise ConfigError("no MCP servers found (expected 'mcpServers')")
    return servers


def scan_config(path: Path) -> list[ServerScan]:
    taken: set[str] = set()
    return [scan_server(name, cfg, taken) for name, cfg in load_config(path).items()]


def assessment_yaml(scan: ServerScan, source_name: str) -> str:
    import yaml

    body = yaml.safe_dump(
        {"name": f"mcp:{scan.name}", "extensions": {"mcp": scan.facts}},
        sort_keys=False,
        allow_unicode=True,
    )
    header = [
        f"# generated by `skos scan mcp` from {source_name} (server: {scan.name})",
        "# null = not visible in the config. Answer what you can, then `skos assess` this file.",
    ]
    header += [f"# note: {n}" for n in scan.notes]
    return "\n".join(header) + "\n" + body
