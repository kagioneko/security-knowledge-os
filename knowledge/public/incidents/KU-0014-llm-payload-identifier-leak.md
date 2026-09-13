---
id: KU-0014
title: "Identifier-shaped secrets leak into LLM payloads even after a denylist"
category: incident
source_type: incident
source_ref: "internal: security-knowledge-os cross-AI review, rounds 9-14 (2026-09)"
classification: public
status: reviewed
risk_ids:
  - CRED-001
version: "1.0"
last_reviewed: "2026-09-13"
requires_ip_review: false
provenance:
  source_title: "security-knowledge-os pre-publication cross-AI review, rounds 9-14"
  source_url: null
  source_version: null
  source_license: "N/A - original first-party incident, no external source"
  derivation: original
  last_verified: "2026-09-13"
---

## Summary
A system that forwards user-supplied *identifiers* (source names, tool names,
destination hosts, approval-gate keys) to an LLM-assisted reviewer - while
correctly withholding fields explicitly documented as secrets - can still leak
credentials. Attackers (or careless callers) put the secret in an identifier
field instead of a secret field. A denylist of known secret *shapes* (AWS keys,
Slack tokens, JWTs, ...) catches each format only after someone thinks to add
it, and was defeated five review rounds in a row by five different formats. It
was finally defeated by a *valid-looking* format (a UUID) that matched no known
secret pattern at all. The only fix that closed the class for good was
structural: stop sending the raw identifier value to the LLM, period.

## Conditions
- An LLM (or any less-trusted downstream consumer) receives a payload built
  from user- or agent-supplied *free-form identifier* fields (names, hostnames,
  keys in a map, labels) that were never intended to hold secrets.
- The system already has a *content* boundary for fields it knows are
  sensitive (e.g. a `system_prompt` scrubber, a secrets vault), but identifier
  fields are treated as inherently safe because "that's not where secrets go."
- The identifier fields are attacker- or caller-controlled strings with no
  independent verification that they are actually what they claim to be
  (a tool name, a hostname, a source label).

## Risk
Any credential-shaped string placed in an identifier field is forwarded
verbatim to the LLM (and typically into its provider's logs, and into any
third-party API the review call itself makes), bypassing every control that
exists specifically to keep secrets out of LLM context.

## Evidence
- The payload/request object sent to the external reviewer contains raw values
  copied from identifier-typed fields (names, hosts, map keys) rather than
  stable local labels.
- A regex denylist for "credential-shaped" strings exists and is applied only
  to identifier fields, with no allowlist or anonymization layer behind it.

## Failure Mode
This was discovered as a live, repeating pattern across five consecutive
review rounds of this same project, each time with the reviewer proving the
previous round's fix incomplete:

1. **Round 9**: AWS access keys and Slack tokens placed in identifier fields
   reached the LLM payload unfiltered. Fix: add regex patterns for those two
   formats to a denylist.
2. **Round 11**: Stripe keys and JWTs reached the payload the same way. Fix:
   extend the denylist with two more patterns.
3. **Round 12**: Google API keys, GitLab tokens, Discord bot tokens, and DB
   connection strings, same gap. Fix: extend the denylist again (now covering
   many formats across many providers, requiring a shared module so the
   pattern list itself does not drift between the two enforcement points that
   used it).
4. **Round 13**: OpenAI-style keys, same gap. The team added an *allowlist*
   this time - reject any identifier segment over a fixed length, since every
   known secret format was longer than any real identifier - reasoning that
   a length bound is stronger than yet another format-specific pattern.
5. **Round 14**: A UUID-shaped secret defeated the length-based allowlist too
   - a UUID's hyphen-separated segments are all short, so the same string that
   looks exactly like a plausible resource identifier is also a perfectly
   valid credential shape in systems that mint UUID-form API keys. At this
   point the same structural recommendation had now been raised twice by the
   external reviewer: stop trying to recognize secret shapes and stop sending
   the raw value at all.

The pattern across all five rounds: **shape-based detection (deny or allow) is
a moving target because "looks like a secret" and "looks like a normal
identifier" are not disjoint sets**, and the set of secret formats in active
use is open-ended (any team can mint a new token format tomorrow).

## Detection Clues
- Any code path that serializes user- or agent-controlled identifier fields
  into a prompt, request body, or log line sent to a less-trusted consumer,
  without first checking whether the value is used *anywhere else* as a
  literal (i.e., whether identity, not content, is what actually matters to
  that consumer).
- A growing, format-specific regex list as the *only* defense for a field
  class - each addition is evidence the previous version was already proven
  insufficient by a real bypass, not a hypothetical one.
- Fields whose purpose is to *identify* something (a name, a key in a map, a
  hostname) but whose type is unconstrained free-text equal in shape to fields
  whose purpose is to *hold a secret value*.

## Mitigations
- **Ask whether the downstream consumer needs the real value or just needs to
  distinguish one identifier from another.** If only the latter, don't send
  the real value at all: replace every free-form identifier with a stable,
  locally-generated label (e.g. sort the distinct values, number them
  `item_1`, `item_2`, ...) before building the payload, and keep the mapping
  local. This closes the entire vulnerability *class* in one change, instead
  of chasing individual formats forever.
- Apply the anonymization consistently across every place the same identifier
  appears in the payload (e.g. a tool name referenced both in a tool list and
  embedded inside a separate free-text action string) - a mapping that covers
  one occurrence but not the other reopens the leak for that field.
- Keep a fail-closed fallback for anything that shows up unmapped (an
  "unlabeled" placeholder), rather than falling back to the original value,
  so a bug in the mapping logic cannot silently regress to leaking.
- Never mutate the original, non-anonymized object: only the copy built for
  the less-trusted consumer should be relabeled. Whatever performs
  authoritative decisions (a deterministic rule engine, a human-facing report)
  must keep operating on the real values.
- Treat a shape-based denylist or allowlist as a *stopgap*, not a destination:
  if the same field class gets a second real-world bypass, that is the signal
  to stop patching and do the structural fix, not evidence that "just one more
  pattern" will finally be enough.

## Safe Test
Construct an identifier-typed field (a source name, tool name, or map key)
containing a value shaped like a real secret in a format NOT already covered
by any denylist/allowlist in the system (invent a novel-looking token shape
if needed). Confirm it is absent, byte-for-byte, from whatever payload is
built for the less-trusted consumer - not merely that it fails a specific
pattern check. Also confirm the same value, if it appears in more than one
field derived from the same identifier, is anonymized consistently everywhere
it appears.

## Limitations
Anonymization protects the *external* payload only; it does nothing if the
less-trusted consumer is later given tool access to fetch the real value some
other way, and it does not protect fields whose entire purpose is to carry
free-form prose (a system prompt, a user message) where content-based secret
scanning is still required and structurally different from this fix.

## Related Knowledge
- KU-0008
- KU-0009
