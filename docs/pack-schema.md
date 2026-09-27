# Pack Schema (draft, pack API 1)

A **pack** is a separately distributed Python package that extends the skos rule
catalogue for one domain (for example `skos-pack-mcp` for MCP server connection
risk). Installing a pack is meant to feel like applying an update: once it is
installed and trusted, `skos assess` evaluates its rules with no extra flags.

Status: implemented in core 0.2.0 (`app/packs/`, tests in `tests/unit/test_packs*.py`).

## Design principles

1. **Assessment stays data-only.** A pack contributes facts, evidence keys,
   rules, questions and report groups as YAML. No pack code runs during
   `skos assess` (or the HTTP API's assessment path).
2. **Verify before execute.** A pack may ship code only for its own CLI
   subcommands (for example `skos mcp scan`). That code is imported only after
   the pack's manifest signature and every file hash have been verified and the
   pack is trusted.
3. **Additive only.** A pack can never override or disable a core fact, rule,
   evidence key, knowledge unit or question, or another pack's.
4. **Fail closed.** A malformed, tampered or incompatible pack is a hard error
   for that pack; it is never partially loaded.
5. **Always visible.** Every report lists the packs that were applied, with
   version, tier and manifest hash, so a changed verdict can be traced to a
   changed rule set.

## Package layout

```
skos_pack_mcp/            # import package: always skos_pack_<name>
  __init__.py             # required only if the pack ships commands
  pack.yaml               # manifest (below)
  pack.sig                # detached Ed25519 signature over pack.yaml's exact bytes
  rules/MCP-001.yaml ...  # rule files, same schema as docs/rule-schema.md (required)
  scan.py                 # optional code for CLI subcommands
```

Knowledge Units are not part of pack API 1; a pack's rules may cite core KUs
in `knowledge_refs`.

The distribution advertises the pack with an entry point:

```toml
[project.entry-points."skos.packs"]
mcp = "skos_pack_mcp"
```

Discovery reads the entry point's **metadata only** (`importlib.metadata`): the
value is resolved to a directory via the distribution's recorded file list,
and the module is **not imported** at discovery time. An editable install has
no such file list; during development point `$SKOS_PACK_DIRS`
(`os.pathsep`-separated) at the package directory instead. Packs found either
way go through exactly the same trust checks.

## Manifest (`pack.yaml`)

```yaml
pack_api: 1                      # must equal the core's PACK_API
name: mcp                        # ^[a-z][a-z0-9]{1,15}$, unique among loaded packs
version: 0.1.0
tier: free                       # free | commercial
publisher: kagioneko             # key id prefix in the trust store
license: Apache-2.0              # SPDX id, or "LicenseRef-..." for commercial
description: MCP server connection risk (Capability / Exposure / Impact / Defense)

facts:                           # new facts, read from extensions.<name>.<key>
  mcp_transport:     {type: str, values: [stdio, http, sse, unknown]}
  mcp_auth_required: {type: bool}
  mcp_version_pinned: {type: bool}
  mcp_fs_roots:      {type: str_list}

evidence:                        # new evidence keys (docs/rule-schema.md)
  mcp_launch_command: "Provide the command/args used to launch the server."

questions:                       # prompts for undetermined facts
  mcp_auth_required: "Does the server require authentication for every client?"

report_groups:                   # optional grouping for subtotals in the report
  capability: [MCP-001, MCP-002]
  exposure:   [MCP-003, MCP-004]
  impact:     [MCP-005]
  defense:    [MCP-006, MCP-007]

commands:                        # optional; code, loaded only when trusted
  scan: "skos_pack_mcp.scan:main"   # exposed as `skos mcp scan`

files:                           # sha256 of EVERY other file in the pack dir
  rules/MCP-001.yaml: 3b1f...    # (must be the LAST key: scripts/sign_pack.py
  scan.py: 9ac0...               #  regenerates this block in place)
```

`commands` targets must live inside the pack's own package (`skos_pack_<name>`).

### Namespacing (all enforced at load time)

| Item | Rule |
|---|---|
| fact names | must start with `<name>_` |
| evidence keys | must start with `<name>_` |
| rule ids | must start with `<NAME>-` (upper-cased pack name), e.g. `MCP-001` |
| knowledge unit ids | must start with `KU-<NAME>-` |
| commands | exposed only as `skos <name> <command>` |

Pack rules may reference core facts (for example `has_shell_tool`) as well as
their own. They may not reference another pack's facts.

### Questions

As for core rules, a question is generated when a rule's trigger
`conditions` cannot be decided; `questions` supplies the text for a pack fact
(otherwise a generic "needed to evaluate <rule>" is used). An undecidable
`checks` clause yields an `UNKNOWN` finding; list the input a check needs in
`required_evidence` to also get a question for it.

### Fact types

Pack facts use the core fact types (`bool`, `str`, `str_list`). A `str` fact with
`values` is an enum; the literal `unknown` is always allowed and means "not
stated". Values are read verbatim from `extensions.<name>.<key>`; there is no
derivation logic in the manifest. Derived facts (for example "is the version
pinned?" from a launch command) are computed by the pack's adapter command,
which writes them out as plain input YAML.

## Assessment input

`AssessmentInput` gains one field:

```yaml
extensions:
  mcp:
    transport: http
    auth_required: false
    version_pinned: false
    fs_roots: ["~"]
```

- Each `extensions.<name>` block is validated against that pack's `facts`
  (unknown key, wrong type, value outside `values`: hard error). The existing
  size bound and credential-shape rejection apply to the whole input as today.
- `extensions.<name>` for a pack that is not installed or not trusted is a
  **hard error** - the input carries data the operator expected to be assessed,
  and silently ignoring it would read as a clean result.
- `--no-packs` assesses with the core catalogue only. Any `extensions` present
  are then ignored, and the report states that they were ignored.

## Trust

Before anything else the pack directory is copied to a private snapshot with
a no-follow walk (a symlink anywhere refuses the pack); every later check,
and any later import of pack code, reads that one copy.

A pack is loaded only if **one** of these holds:

1. **Signed by a trusted publisher.** `pack.sig` verifies against a key in the
   core's built-in trust store (`app/packs/trusted_keys.py`, key id + Ed25519
   public key), and every entry in `files` matches, and the pack directory
   contains no file absent from `files` (ignoring `__pycache__/`).
2. **Enabled by the operator.** `skos packs enable <name>` records the pack's
   name and manifest sha256 in `~/.config/skos/packs.yaml`. A pack whose
   manifest changes (an upgrade) must be enabled again. `files` hashes are still
   verified.

Anything else is listed by `skos packs` as `disabled` and never loaded.
`skos packs disable <name>` turns off a trusted pack locally.

A signature by a key that is not in the trust store is treated like no
signature. A signature that is present but does not verify, or a trusted pack
that then fails any check (file hashes, vocabulary, rules, report groups), is
an **error**: `skos assess` refuses to run until it is fixed or disabled.

Scope of the signature: it establishes **provenance** ("this rule set is what
the publisher released") and makes accidental or unnoticed modification
visible. It is not a defence against an attacker who can already write to the
Python environment - such an attacker can modify skos itself.

Key management: the signing key lives in Vault and never in any repository.
Key rotation ships as a core release that adds the new key id; revocation ships
as a core release that removes it.

## Commercial tier

A `tier: commercial` pack additionally requires a **license file**:

```
~/.config/skos/licenses/<name>.lic      # JSON
~/.config/skos/licenses/<name>.lic.sig  # Ed25519 by the pack's publisher
```

```json
{"license_id": "L-0001", "licensee": "Example Corp", "packs": ["mcp-pro"],
 "issued": "2026-10-01", "expires": "2027-09-30"}
```

- Verification is **offline** - skos never contacts a license server.
- The licensee name is never written into reports or `skos packs` output.
- Missing, invalid or expired license: the pack is `disabled (license: <reason>)`
  in `skos packs`; its `extensions` block is then a hard error as for any other
  unloaded pack.
- Limits, stated plainly: rules shipped as YAML (and Python code) are readable
  by whoever installs them, so the license check identifies a legitimate
  customer rather than preventing copying. The value of a commercial pack is in
  continued rule updates, support and audit-ready reporting.

Distribution of commercial packs is through a private package index with
per-customer credentials. Pricing is not yet decided.

## Report

Every report (JSON and text) gains:

```json
"packs_applied": [
  {"name": "mcp", "version": "0.1.0", "tier": "free", "publisher": "kagioneko",
   "trust": "signed", "manifest_sha256": "..."}
],
"extensions_ignored": false
```

and, for packs with `report_groups`, a per-group summary (worst verdict and
finding count per group).

## CLI

| Command | Purpose |
|---|---|
| `skos packs` | list installed packs: name, version, tier, trust state |
| `skos packs enable <name>` / `disable <name>` | operator trust decisions |
| `skos packs verify <name>` | re-run signature/hash/license checks, print the result |
| `skos assess ... [--no-packs]` | assess with (default) or without packs |
| `skos <name> <command>` | a pack's own command, trusted packs only |

## Scope of pack API 1

- `skos assess` (and `skos packs`, `skos <pack> <command>`) load packs. The
  HTTP API and `skos test` assess with the core catalogue only; an input with
  an `extensions` block is therefore rejected there (POLICY_BLOCKED), never
  silently assessed without it.
- Publisher tooling: `scripts/sign_pack.py` (hash + sign) and
  `scripts/issue_license.py`; both read the private key from stdin only.

## Compatibility

`pack_api` is a single integer. The core rejects a pack whose `pack_api` differs
from its own. It is bumped only for incompatible changes to this document.
