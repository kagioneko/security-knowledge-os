"""Derive MCP-pack assessment inputs from an MCP client configuration
(``.mcp.json``, ``claude_desktop_config.json``, ``~/.claude.json``).

One input per configured server, carrying ``extensions.mcp`` facts for the
``mcp`` Update Pack. A fact is filled in only when the configuration
establishes it; everything else stays ``null`` (= not stated) so the
assessment asks for it instead of guessing. In particular, what the CLIENT
sends or connects to is not taken as a property of the SERVER: an
Authorization header does not prove the server requires authentication, and
connecting via 127.0.0.1 does not prove the server listens only there.

Secrets: environment values, header values, URL userinfo/query and
arguments are inspected only to decide ``secrets_in_config`` (true/false).
No value from the configuration - secret or not, other than server names -
is ever written, printed, or placed in an error message.
"""

from __future__ import annotations

import ipaddress
import json
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import parse_qsl, urlsplit

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

_SECRET_NAME = r"(?i)(key|token|secret|passw|pat\b|credential|auth|cookie|session|sig)"
_ENV_REFERENCE = r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$"
_SECRET_ARG = (
    r"(?i)^--?(api[-_]?key|token|secret|password|auth)(=|$)"
    r"|^(sk-|ghp_|gho_|github_pat_|xox[bpas]-|AKIA|AIza)"
)
_NPM_SPEC = r"^(?P<name>(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*)(@(?P<version>.+))?$"
_EXACT_SEMVER = r"^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$"
_PY_SPEC = r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(\[[A-Za-z0-9,._-]+\])?(?P<rest>.*)$"
_EXACT_PY = r"^==\d+(\.\d+)*$"
_DIGEST_IMAGE = r"^[^@\s]+@sha256:[0-9a-f]{64}$"


@dataclass(frozen=True)
class _Profile:
    shell_exec: bool | None = None
    can_write: bool | None = None
    can_send: bool | None = None
    ingests_untrusted_content: bool | None = None
    touches_fs: bool = False  # positional arguments are the allowed paths


# Capabilities of well-known servers, by exact (ecosystem, package) identity.
# Anything else keeps its capabilities unknown.
_KNOWN: dict[tuple[str, str], _Profile] = {
    ("npm", "@modelcontextprotocol/server-filesystem"): _Profile(False, True, False, None, True),
    ("npm", "@modelcontextprotocol/server-github"): _Profile(False, True, True, True),
    ("npm", "@modelcontextprotocol/server-gitlab"): _Profile(False, True, True, True),
    ("npm", "@modelcontextprotocol/server-slack"): _Profile(False, True, True, True),
    ("npm", "@modelcontextprotocol/server-puppeteer"): _Profile(False, False, True, True),
    ("npm", "@modelcontextprotocol/server-brave-search"): _Profile(False, False, True, True),
    ("npm", "@modelcontextprotocol/server-memory"): _Profile(False, True, False, False),
    ("npm", "@playwright/mcp"): _Profile(False, False, True, True),
    ("npm", "@wonderwhy-er/desktop-commander"): _Profile(True, True, True, None, True),
    ("pypi", "mcp-server-fetch"): _Profile(False, False, True, True),
    ("pypi", "mcp-server-git"): _Profile(False, True, False, None, True),
    ("pypi", "mcp-server-time"): _Profile(False, False, False, False),
}
# Reference servers published by the MCP project itself.
_FIRST_PARTY_NPM_SCOPE = "@modelcontextprotocol/"
_FIRST_PARTY_PYPI = {"mcp-server-fetch", "mcp-server-git", "mcp-server-time"}

# docker/podman `run` options that take a separate value argument.
_VALUE_FLAGS = {
    "-v", "--volume", "-e", "--env", "--env-file", "--name", "--network", "--net", "-p",
    "--publish", "--mount", "-w", "--workdir", "-u", "--user", "--entrypoint", "-h",
    "--hostname", "--add-host", "--cap-add", "--cap-drop", "--security-opt", "--device",
    "-l", "--label", "--pid", "--ipc", "--uts", "--userns", "-m", "--memory", "--cpus",
    "--platform", "--pull", "--restart", "--log-driver", "--tmpfs", "--ulimit",
    "--group-add", "--dns", "--runtime", "--volumes-from", "--cgroupns",
}


_HOST_NAMESPACE_FLAGS = ("--network", "--net", "--pid", "--ipc", "--uts", "--userns")


class ConfigError(ValueError):
    """The file is not a readable MCP client configuration. Messages never
    contain configuration values."""


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
    """Where the server is reachable FROM, as far as the URL proves it."""
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


def _str_list(value: object, what: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, (str, int, float)) for v in value):
        raise ConfigError(f"{what} must be a list of strings")
    return [str(v) for v in value]


def _str_dict(value: object, what: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{what} must be an object")
    return {str(k): v for k, v in value.items()}


def _launcher(command: str, args: list[str]) -> tuple[str, str | None, list[str]]:
    """(ecosystem, package spec, arguments after the spec).

    ecosystem: "npm" / "pypi" / "container" / "" (a plain command)."""
    base = PurePosixPath(command).name
    rest = list(args)
    if base in ("pnpm", "yarn", "npm") and rest[:1] in (["dlx"], ["exec"]):
        base, rest = "npx", rest[1:]
    if base in ("npx", "bunx"):
        i = 0
        while i < len(rest):
            arg = rest[i]
            if arg in ("-p", "--package"):
                i += 2
                continue
            if not arg.startswith("-"):
                return "npm", arg, rest[i + 1 :]
            i += 1
        return "npm", None, []
    if base in ("uvx", "pipx"):
        if base == "pipx" and rest[:1] == ["run"]:
            rest = rest[1:]
        for i, arg in enumerate(rest):
            if arg == "--from" and i + 1 < len(rest):
                return "pypi", rest[i + 1], rest[i + 2 :]
            if not arg.startswith("-"):
                return "pypi", arg, rest[i + 1 :]
        return "pypi", None, []
    if base in ("docker", "podman"):
        return "container", None, rest
    return "", None, rest


def _identity(ecosystem: str, spec: str) -> tuple[str | None, bool | None]:
    """(exact package name, pinned?) or (None, None) if the spec is not understood."""
    if ecosystem == "npm":
        m = re.fullmatch(_NPM_SPEC, spec)
        if m is None:
            return None, None
        version = m.group("version")
        return m.group("name"), bool(version) and re.fullmatch(_EXACT_SEMVER, version) is not None
    m = re.fullmatch(_PY_SPEC, spec)
    if m is None:
        return None, None
    return m.group("name").lower(), re.fullmatch(_EXACT_PY, m.group("rest")) is not None


def _container(args: list[str]) -> tuple[bool | None, bool | None, list[str]]:
    """(sandboxed, version_pinned, notes) for `docker|podman run ...`."""
    if args[:1] != ["run"]:
        return None, None, ["container command other than `run`: not analysed"]
    opts: list[tuple[str, str | None]] = []
    image: str | None = None
    i = 1
    while i < len(args):
        arg = args[i]
        if arg.startswith("-"):
            if "=" in arg:
                flag, value = arg.split("=", 1)
                opts.append((flag, value))
            elif arg in _VALUE_FLAGS:
                opts.append((arg, args[i + 1] if i + 1 < len(args) else None))
                i += 1
            else:
                opts.append((arg, None))
            i += 1
            continue
        image = arg
        break
    pinned = None if image is None else re.fullmatch(_DIGEST_IMAGE, image) is not None

    home = str(Path.home())
    dangerous = False
    mounts = False
    for flag, optval in opts:
        v = (optval or "").strip()
        if (
            flag == "--privileged"
            or (flag in _HOST_NAMESPACE_FLAGS and v == "host")
            or (flag == "--cap-add" and v.upper() in ("ALL", "SYS_ADMIN", "SYS_PTRACE"))
            or (flag == "--security-opt" and "unconfined" in v)
        ):
            dangerous = True
        elif flag in ("-v", "--volume", "--mount", "--device", "--volumes-from"):
            mounts = True
            src = v.split(":", 1)[0] if flag != "--mount" else ""
            if flag == "--mount":
                for part in v.split(","):
                    if part.startswith(("source=", "src=")):
                        src = part.split("=", 1)[1]
            norm = posixpath.normpath(src) if src.startswith("/") else src
            if norm in ("/", home, "/home", "/Users", "/root") or "docker.sock" in norm:
                dangerous = True
    if dangerous:
        sandboxed: bool | None = False
    elif mounts:
        sandboxed = None  # isolation depends on what is mounted
    else:
        sandboxed = True
    return sandboxed, pinned, []


def _fs_scope(paths: list[str]) -> str | None:
    """Scope of the positional path arguments of a filesystem-style server;
    None if any path cannot be resolved from the config alone."""
    if not paths:
        return None
    home = str(Path.home())
    scopes: list[str] = []
    for raw in paths:
        p = raw
        for prefix in ("${HOME}", "$HOME", "~"):
            if p == prefix or p.startswith(prefix + "/"):
                p = home + p[len(prefix) :]
                break
        if "$" in p or not p.startswith("/"):
            return None  # relative or unexpanded: depends on the client's cwd/env
        norm = posixpath.normpath(p)
        if norm == "/":
            scopes.append("root")
        elif (
            norm == home
            or home.startswith(norm + "/")  # an ancestor of the home dir
            or re.fullmatch(r"/(home|Users)/[^/]+", norm)
            or norm == "/root"
        ):
            scopes.append("home")
        else:
            scopes.append("project")
    for scope in ("root", "home", "project"):
        if scope in scopes:
            return scope
    return None  # pragma: no cover


def scan_server(label: str, cfg: object, taken: set[str]) -> ServerScan:
    name = _safe_name(label, taken)
    if not isinstance(cfg, dict):
        raise ConfigError(f"server {name!r}: entry must be an object")
    facts: dict[str, Any] = {k: None for k in FACT_KEYS}
    notes: list[str] = []
    package: str | None = None
    secret_seen = False
    token_seen = False
    url = cfg.get("url")
    kind = str(cfg.get("type", "")).lower()

    if url is not None or kind in ("http", "sse", "streamable-http"):
        if not isinstance(url, str):
            raise ConfigError(f"server {name!r}: 'url' must be a string")
        facts["transport"] = "sse" if kind == "sse" else "http"
        try:
            parts = urlsplit(url)
            host = parts.hostname
            has_userinfo = parts.username is not None or parts.password is not None
            query_keys = [k for k, _ in parse_qsl(parts.query, keep_blank_values=True)]
        except ValueError:
            # The exception text can quote the URL (and credentials in it).
            raise ConfigError(f"server {name!r}: 'url' is not a valid URL") from None
        scope = _host_scope(host)
        if scope == "loopback":
            notes.append("reached via loopback; the server's own listen address is not visible")
        else:
            facts["bind_scope"] = scope  # reachable at least from there
        if has_userinfo:
            secret_seen = token_seen = True
        if any(re.search(_SECRET_NAME, k) for k in query_keys):
            secret_seen = token_seen = True
        headers = _str_dict(cfg.get("headers"), f"server {name!r}: 'headers'")
        for hname, hval in headers.items():
            if re.search(_SECRET_NAME, hname):
                token_seen = True
                if _is_literal_secret(hname, hval):
                    secret_seen = True
        if token_seen:
            notes.append(
                "the client sends credentials; whether the server REQUIRES them is not visible"
            )
        if url.startswith("http://") and scope not in (None, "loopback"):
            notes.append("remote server over plain http (no TLS)")
    elif isinstance(cfg.get("command"), str):
        facts["transport"] = "stdio"
        args = _str_list(cfg.get("args"), f"server {name!r}: 'args'")
        ecosystem, spec, rest = _launcher(cfg["command"], args)
        if ecosystem == "container":
            facts["sandboxed"], facts["version_pinned"], extra = _container(rest)
            notes += extra
        elif spec is not None:
            package, pinned = _identity(ecosystem, spec)
            if package is not None:
                facts["version_pinned"] = pinned
                facts["third_party"] = not (
                    (ecosystem == "npm" and package.startswith(_FIRST_PARTY_NPM_SCOPE))
                    or (ecosystem == "pypi" and package in _FIRST_PARTY_PYPI)
                )
                profile = _KNOWN.get((ecosystem, package))
                if profile is not None:
                    for key in ("shell_exec", "can_write", "can_send",
                                "ingests_untrusted_content"):
                        facts[key] = getattr(profile, key)
                    positional = [a for a in rest if not a.startswith("-")]
                    facts["fs_scope"] = _fs_scope(positional) if profile.touches_fs else "none"
        for arg in args:
            if re.search(_SECRET_ARG, arg):
                secret_seen = token_seen = True
    else:
        raise ConfigError(f"server {name!r} has neither 'command' nor 'url'")

    env = _str_dict(cfg.get("env"), f"server {name!r}: 'env'")
    for ename, evalue in env.items():
        if re.search(_SECRET_NAME, ename):
            token_seen = True
            if _is_literal_secret(ename, evalue):
                secret_seen = True
    facts["secrets_in_config"] = secret_seen
    facts["token_scope"] = None if token_seen else "none"
    return ServerScan(name, package, facts, notes)


def load_config(path: Path) -> list[tuple[str, object]]:
    """``[(label, server config)]`` from the top-level ``mcpServers`` and, for
    ``~/.claude.json``, every ``projects.<path>.mcpServers``. Labels may
    repeat; scan_config() makes them unique, so no server is ever dropped."""
    try:
        with path.open("rb") as fh:
            raw = fh.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise ConfigError(f"cannot read config ({type(exc).__name__})") from None
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError("config file is too large")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):  # incl. huge ints
        raise ConfigError("config is not valid UTF-8 JSON") from None
    if not isinstance(data, dict):
        raise ConfigError("config must be a JSON object")
    servers: list[tuple[str, object]] = []
    top = data.get("mcpServers")
    if isinstance(top, dict):
        servers += [(str(k), v) for k, v in top.items()]
    projects = data.get("projects")
    if isinstance(projects, dict):
        for project, pdata in projects.items():
            inner = pdata.get("mcpServers") if isinstance(pdata, dict) else None
            if isinstance(inner, dict):
                label = PurePosixPath(str(project)).name or "project"
                servers += [(f"{label}.{k}", v) for k, v in inner.items()]
    if not servers:
        raise ConfigError("no MCP servers found (expected 'mcpServers')")
    return servers


def scan_config(path: Path) -> list[ServerScan]:
    taken: set[str] = set()
    return [scan_server(label, cfg, taken) for label, cfg in load_config(path)]


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
