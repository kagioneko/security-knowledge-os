"""Capability labels for one agent, derived from its MCP client config.

Each server gets six labels - ``untrusted_input``, ``sensitive_read``,
``egress``, ``exec``, ``write``, ``persistence`` - valued ``True`` /
``False`` / ``None`` (unknown). A label is ``True`` only when the config
(package identity, launch options) establishes it, and ``False`` only when
the absence is established the same way; a server the scanner does not know
keeps every label ``None``. Tool descriptions are never used: they can lie.

The agent is the union of its servers and the client's own built-in tools,
combined with a three-valued OR (any ``True`` -> ``True``; all ``False`` ->
``False``; otherwise ``None``). When the client is not declared, nothing is
known about its built-in tools, so an aggregate ``False`` becomes ``None``.

The result feeds the ``capgraph`` Update Pack (``extensions.capgraph``) and
is also written as ``capability-labels.json`` for runtime enforcement (for
example a gateway that decides trust from the same labels). Only server
names from the config appear in either output, never configuration values.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from app.adapters.mcp_config import ServerScan

LABELS = ("untrusted_input", "sensitive_read", "egress", "exec", "write", "persistence")
# Written to extensions.capgraph; every key becomes a ``capgraph_<key>`` fact.
FACT_KEYS = (*LABELS, "flow_gated")
SCHEMA = "capgraph/v0"
AGENT_FILE_STEM = "_agent"  # reserved: no server may be written under this name
CLIENTS = ("claude-code", "none")

Label = bool | None


@dataclass(frozen=True)
class _Caps:
    """What a known package can do beyond the MCP scanner's own facts."""

    sensitive_read: Label = None
    persistence: Label = None
    write_scope: str | None = None  # "fs" = the scanner's fs_scope


# By exact (ecosystem, package) identity, like the scanner's own profiles.
_KNOWN: dict[tuple[str, str], _Caps] = {
    # scope-dependent: see _labels()
    ("npm", "@modelcontextprotocol/server-filesystem"): _Caps(None, True, "fs"),
    # private repositories/messages behind the token; pushes can change CI
    ("npm", "@modelcontextprotocol/server-github"): _Caps(True, True, "remote"),
    ("npm", "@modelcontextprotocol/server-gitlab"): _Caps(True, True, "remote"),
    ("npm", "@modelcontextprotocol/server-slack"): _Caps(True, None, "remote"),
    # a browser can reach intranet pages and the host's services
    ("npm", "@modelcontextprotocol/server-puppeteer"): _Caps(None, False, "none"),
    ("npm", "@playwright/mcp"): _Caps(None, False, "none"),
    ("npm", "@modelcontextprotocol/server-brave-search"): _Caps(False, False, "none"),
    # what it stores is loaded into later sessions
    ("npm", "@modelcontextprotocol/server-memory"): _Caps(False, True, "sandbox"),
    ("npm", "@wonderwhy-er/desktop-commander"): _Caps(True, True, "root"),
    # fetch can reach localhost and intranet URLs
    ("pypi", "mcp-server-fetch"): _Caps(None, False, "none"),
    ("pypi", "mcp-server-git"): _Caps(None, None, "project"),
    ("pypi", "mcp-server-time"): _Caps(False, False, "none"),
}

# Built-in tools of an agent client, by --client name. "none" declares a
# client without built-in tools (e.g. a custom agent that only uses MCP).
_CLIENTS: dict[str, dict[str, Label]] = {
    # Bash, Read/Edit/Write, WebFetch/WebSearch
    "claude-code": {
        "untrusted_input": True, "sensitive_read": True, "egress": True,
        "exec": True, "write": True, "persistence": True,
    },
}


@dataclass
class ServerLabels:
    name: str
    labels: dict[str, Label]
    write_scope: str | None


@dataclass
class AgentLabels:
    client: str | None
    servers: list[ServerLabels]
    labels: dict[str, Label] = field(default_factory=dict)
    contributors: dict[str, list[str]] = field(default_factory=dict)

    def facts(self) -> dict[str, Label]:
        """The ``extensions.capgraph`` block. ``flow_gated`` is not visible in
        a config, so it is always left for the operator to answer."""
        return {**self.labels, "flow_gated": None}

    def notes(self) -> list[str]:
        out = []
        if self.client is None:
            out.append(
                "client not declared (--client): its built-in tools are unknown, so no label "
                "is claimed absent"
            )
        for label in LABELS:
            if self.contributors.get(label):
                out.append(f"{label} <- {', '.join(self.contributors[label])}")
        return out


def _labels(scan: ServerScan) -> ServerLabels:
    f = scan.facts
    labels: dict[str, Label] = {
        "untrusted_input": f.get("ingests_untrusted_content"),
        "sensitive_read": None,
        "egress": f.get("can_send"),
        "exec": f.get("shell_exec"),
        "write": f.get("can_write"),
        "persistence": None,
    }
    write_scope: str | None = None
    caps = None
    if scan.package is not None and scan.ecosystem is not None:
        caps = _KNOWN.get((scan.ecosystem, scan.package))
    if caps is not None:
        labels["sensitive_read"] = caps.sensitive_read
        labels["persistence"] = caps.persistence
        write_scope = caps.write_scope
        if caps.write_scope == "fs":
            scope = f.get("fs_scope")
            write_scope = scope if scope in ("project", "home", "root") else None
            # the whole home directory or / holds credentials and private files;
            # a project directory may (.env) but that is not visible here
            labels["sensitive_read"] = True if scope in ("home", "root") else None
    if labels["exec"] is True and f.get("sandboxed") is not True:
        # an unsandboxed shell reads and writes anything the user can
        labels["sensitive_read"] = labels["write"] = labels["persistence"] = True
        write_scope = write_scope or "root"
    if labels["write"] is False and labels["exec"] is False and labels["persistence"] is None:
        labels["persistence"] = False
    return ServerLabels(scan.name, labels, write_scope)


def _or(values: list[Label]) -> Label:
    if any(v is True for v in values):
        return True
    if values and all(v is False for v in values):
        return False
    return None


def agent_labels(scans: list[ServerScan], client: str | None) -> AgentLabels:
    if client is not None and client not in CLIENTS:
        raise ValueError(f"unknown client {client!r} (known: {', '.join(CLIENTS)})")
    servers = [_labels(s) for s in scans]
    builtin = _CLIENTS.get(client) if client else None
    agent = AgentLabels(client, servers)
    for label in LABELS:
        values = [s.labels[label] for s in servers]
        sources = [s.name for s in servers if s.labels[label] is True]
        if builtin is not None:
            values.append(builtin[label])
            if builtin[label] is True:
                sources.insert(0, f"client:{client}")
        value = _or(values)
        if value is False and client is None:
            value = None
        agent.labels[label] = value
        agent.contributors[label] = sources
    return agent


def labels_json(agent: AgentLabels, source_name: str) -> str:
    doc = {
        "schema": SCHEMA,
        "source": source_name,
        "client": agent.client,
        "agent": agent.labels,
        "contributors": agent.contributors,
        "servers": {
            s.name: {**s.labels, "write_scope": s.write_scope} for s in agent.servers
        },
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def agent_yaml(agent: AgentLabels, source_name: str) -> str:
    import yaml

    body = yaml.safe_dump(
        {"name": f"agent:{source_name}", "extensions": {"capgraph": agent.facts()}},
        sort_keys=False,
        allow_unicode=True,
    )
    header = [
        f"# generated by `skos scan mcp` from {source_name} (the whole agent: every server"
        + (f" + client {agent.client}" if agent.client else "") + ")",
        "# null = not established by the config. Answer what you can, then `skos assess` this"
        " file.",
    ]
    header += [f"# note: {n}" for n in agent.notes()]
    return "\n".join(header) + "\n" + body
