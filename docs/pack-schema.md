# Update Pack Schema (pack API 1)

Implements the *Security Knowledge OS - Update Pack / Distribution Specification
v0.1* for rules. An **Update Pack** is a ZIP of data - rules plus the facts they
use - distributed separately from the engine (free, commercial, or
customer-specific) and installed with `skos pack install`. Once installed,
`skos assess` evaluates the pack's rules with no extra flags, and every report
names the packs that took part.

Implementation: `app/packs/`, CLI `app/pack_cli.py`, tests
`tests/unit/test_packs*.py`.

## Principles

1. **Data only.** A pack contains no code. Only the files listed under
   *Layout* are accepted; anything else (a script, a binary, another
   directory) rejects the whole archive before a byte is written to disk.
2. **Verify before extract.** The ZIP is read into memory and every entry is
   checked (no absolute paths, `..`, backslashes, symlinks, duplicates,
   encryption; bounded sizes and entry count) before anything is verified or
   written.
3. **Additive.** A pack cannot override or shadow a core fact, rule, evidence
   key or question, nor another pack's. Its names are namespaced (below).
4. **Nothing half-applied.** Install and rollback stage, verify, smoke-test
   and only then switch atomically; a failure leaves the previous state intact.
5. **Re-verified on every load.** An installed pack is checked again (signature
   or operator approval, checksums, license, rules) each time it is loaded. A
   tampered pack stops the assessment instead of silently dropping out.
6. **Visible.** Reports list `packs_applied` (id, version, classification,
   trust, manifest sha256); `--no-packs` is shown as such.

## Layout

```
<pack_id>-<version>.zip
  manifest.json        required
  signature.sig        Ed25519 over manifest.json (see Trust)
  checksums.sha256     sha256sum-compatible list, generated from manifest.files
  rules/*.yaml         at least one; docs/rule-schema.md; ids start with <PACK_ID>-
  changelog.md         optional
  LICENSE.txt          optional
  README.md            optional
```

Knowledge Units, safe-test templates and fixtures (spec section 3) are not part
of pack API 1; rules may cite core KUs in `knowledge_refs`.

## manifest.json

```json
{
  "pack_api": 1,
  "pack_id": "mcp",
  "name": "MCP Connection Risk Pack",
  "version": "2026.10.0",
  "release_date": "2026-10-01",
  "min_engine_version": "0.2.0",
  "max_engine_version": null,
  "classification": "public",
  "publisher": "kagioneko",
  "license": "Apache-2.0",
  "description": "...",
  "changelog": "changelog.md",
  "facts":    {"mcp_transport": {"type": "str", "values": ["stdio", "http", "sse"]},
               "mcp_auth_required": {"type": "bool"}},
  "evidence": {"mcp_launch_command": "Provide the command used to launch the server."},
  "questions": {"mcp_transport": "Which transport does the server use?"},
  "report_groups": {"capability": ["MCP-001"], "exposure": ["MCP-003"]},
  "hash_algorithm": "sha256",
  "files": {"rules/MCP-001.yaml": "<sha256>", "changelog.md": "<sha256>"}
}
```

- `name`, `description`, `evidence`/`questions` text: no control, line-break or
  bidirectional-formatting characters (they are shown in terminals and reports).
- `version`: `YYYY.MM.PATCH`. A released version never changes: installing the
  same version with different content is refused.
- `classification`: `public` | `commercial` | `internal` | `confidential`.
  `secret` is refused outright - secret material is never packed.
- `files` covers every file except `manifest.json`, `signature.sig` and
  `checksums.sha256`. `skos pack build` generates it.

### Namespacing (enforced)

| item | rule |
|---|---|
| facts, evidence keys | `<pack_id>_<name>` |
| rule ids | `<PACK_ID>-NNN` (e.g. `MCP-001`) |
| questions | only for the pack's own facts |

Pack rules may use core facts (e.g. `has_shell_tool`) and their own, never
another pack's. A literal compared to an enum fact (`values`) must be one of
the declared values - a typo is a load error, not a rule that never fires.

### Questions

A question is generated for every fact a rule needed but could not read -
an undecidable trigger `condition`, or an undecidable `check` of a rule that
applies (which also makes the finding `UNKNOWN`). `questions` supplies the
text for a pack's facts; without one a generic prompt is used.

## Assessment input

`AssessmentInput.extensions.<pack_id>.<key>` carries a pack's facts
(`<pack_id>_<key>`) and evidence:

```yaml
name: my-mcp-server
extensions:
  mcp:
    transport: http
    auth_required: false
```

- Values are type-checked against the manifest (unknown key, wrong type, value
  outside `values`: POLICY_BLOCKED). The engine's size bound and credential
  shape rejection apply as for every other field.
- An `extensions` block for a pack that is not installed and active is
  POLICY_BLOCKED - data the operator expected to be assessed is never dropped.
- `skos assess --no-packs` assesses with the core rules only and reports the
  extensions as ignored.

## Trust

A pack is accepted if:

1. `signature.sig` verifies against a key in the built-in trust store
   (`app/packs/trusted_keys.py`) that belongs to the manifest's `publisher`
   → trust `signed`; or
2. it is unsigned (or signed by an unknown key) and the operator installs it
   with `--allow-unsigned` → trust `operator-approved`; the manifest sha256 is
   recorded and the pack keeps loading only while its manifest is unchanged.

A signature that is present but does not verify, or a key/publisher mismatch,
is always a rejection. The signature establishes provenance; it does not
defend against an attacker who can already write to the operator's files.

Keys: the signing key lives in Vault, never in a repository. Rotation (add a
key id) and revocation (remove it) ship as core releases.

## Commercial packs

`classification: commercial` additionally requires a license file:

```
$SKOS_CONFIG_DIR/licenses/<pack_id>.lic       (default ~/.config/skos)
$SKOS_CONFIG_DIR/licenses/<pack_id>.lic.sig   Ed25519 by the pack's publisher
```

```json
{"license_id": "L-0001", "licensee": "Example Corp", "packs": ["mcppro"],
 "issued": "2026-10-01", "expires": "2027-09-30"}
```

- Verified offline; skos never contacts a license server.
- Missing / invalid / expired: install is refused; an installed pack is
  skipped, not fatal - every report then lists it under `packs_skipped`
  ("pack NOT applied: ...") so the reduced coverage is visible, and an
  `extensions` block for it is POLICY_BLOCKED like any other inactive pack.
- The licensee name is never written to reports or listings.
- Rules are readable YAML, so this identifies a legitimate customer; it does
  not prevent copying. The value of a commercial pack is continued updates,
  support, and audit-ready reporting. Distribution is by per-customer
  download; pricing is not yet decided.
- Issue with `scripts/issue_license.py` (key on stdin).

## Install, rollback, remove

State lives under `$SKOS_HOME` (default `~/.local/share/skos`), 0700/0600:

```
packs/<classification>/<pack_id>-<version>.zip   every archive installed
versions/<pack_id>/<version>/                    verified, extracted files
active/<pack_id> -> ../versions/<pack_id>/<version>   swapped atomically
installed.json                                   versions, trust, history
audit.jsonl                                      one record per action
```

`skos pack install` (spec section 7): read ZIP once (the same bytes are
verified and stored) → entry checks → manifest → engine compatibility →
classification → signature/trust → checksums → license → vocabulary → rules →
report groups → **diff against the active version** → stop unless sensitive
changes are approved → write to a staging directory → re-verify what landed →
smoke test (an empty assessment with core + all packs must complete) →
rename into `versions/` → atomic symlink swap → state + audit record.

**Sensitive changes** (spec section 22) need `--approve-sensitive`, on install
and on rollback alike: a severity lowered, `manual_review` removed (human
gate), **any change to `required_evidence`** (fewer keys, or added keys -
missing evidence is evaluated before checks and can mask a FAIL), a rule
removed, **any change to a rule's conditions or checks** (whether a logic
change weakens detection cannot be decided in general), or a `confidential`
pack. `skos pack diff OLD NEW` shows
them.

The registry (`installed.json`) is written before the active link is switched;
if switching fails the previous registry is restored, and if the process dies
in between, registry and link disagree and the pack is refused until
`rollback`/`remove` (fail closed). On every load an active pack must match its
registry record exactly - pack id, version, directory and manifest sha256 -
checked before anything else (so an expired license cannot mask a swap);
operator approval counts only for a recorded operator-approved install, and a
signed install must keep verifying as signed - removing its signature or
revoking its key does not degrade it to "operator-approved". An active link with no registry entry
(a lost or emptied `installed.json`) is an error, not "nothing installed".

The version install/rollback diffs against (the one active now) goes through
the same strict check; if it fails, the change is refused until the
installation is repaired - a tampered baseline must never decide that a
change needs no approval. A kept version directory is replaced only after the
verified copy is in place, and restored if that fails.

`skos pack rollback PACK_ID VERSION` re-verifies the kept version, diffs,
smoke-tests and swaps back. `skos pack remove PACK_ID` deactivates the pack and
keeps its archives and versions as history.

Audit records hold timestamp, operator, action, pack id, old/new version,
manifest hash and results - never file content or secrets.

## CLI

| command | purpose |
|---|---|
| `skos pack build SRC [--version V] [--sign --key-id ID]` | reproducible ZIP; key on stdin |
| `skos pack inspect ZIP` | manifest and contents; changes nothing |
| `skos pack verify ZIP [--allow-unsigned]` | every install check; changes nothing |
| `skos pack diff OLD NEW` | added / modified / removed / sensitive (exit 1 if sensitive) |
| `skos pack install ZIP [--allow-unsigned] [--approve-sensitive]` | install and activate |
| `skos pack list` | installed packs, re-verified |
| `skos pack rollback PACK_ID VERSION` | switch back to a kept version |
| `skos pack remove PACK_ID` | deactivate (history kept) |
| `skos assess FILE [--no-packs \| --only-pack ID]` | assess with installed packs, without them, or with one pack's rules only (the report states the narrowed scope) |
| `skos scan mcp CONFIG [--assess [--full]]` | assessment inputs for the `mcp` pack from an MCP client config; `--assess` evaluates the mcp rules only unless `--full` |

## `skos scan mcp`

Reads an MCP client config and writes one input per server. A fact is filled
in only when the config establishes it: what the client sends or connects to
is not taken as a server property (an auth header does not prove the server
requires auth; a loopback URL does not prove a loopback-only bind), known
server capabilities apply only to exact registry package identities (aliases,
URLs, git and path specs, and any launcher option other than `-y`/`-q` - a
registry/index override, `-p`/`--from` - leave the package unidentified), and container options that are not
fully understood leave isolation and pinning unknown. Credential detection
proves presence, never absence: `secrets_in_config` is `true` (a literal
credential was found; `${VAR}` references, also after `Bearer `, do not count)
or `null`, and
`token_scope` is never claimed to be `none`. No config value other than
server names is written, printed, or used in an error message.

## Scope of pack API 1

- `skos assess` and `skos scan mcp --assess` load packs. The HTTP API and
  `skos test` assess with the core rules only; an input with an `extensions`
  block is POLICY_BLOCKED there.
- Not yet: Knowledge Units in packs (and the index rebuild they need),
  enterprise `overrides`, update channels, online update checks.

`pack_api` is an integer; the engine rejects any other value. It changes only
for incompatible changes to this document.
