---
id: KU-0009
title: "Credential broker: short-lived, least-privilege handles"
category: credential-security
source_type: standard
source_ref: "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf (NIST AI 600-1, Generative AI Profile)"
classification: public
status: reviewed
risk_ids:
  - CRED-001
version: "1.0"
last_reviewed: "2026-09-10"
requires_ip_review: false
provenance:
  source_title: "NIST AI 600-1: Artificial Intelligence Risk Management Framework - Generative AI Profile"
  source_url: "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf"
  source_version: "2024-07"
  source_license: "U.S. Government work / public domain"
  derivation: summary
  last_verified: "2026-09-10"
---

## Summary
Instead of handing the model a raw credential, a broker sits between the agent and
the secret. The agent requests a capability by name; the broker returns a
short-lived, narrowly-scoped handle (or performs the call itself) and never
reveals the underlying value.

## Conditions
- The agent needs to authenticate to an external system, and
- The design goal is that a compromised model does not equal a compromised
  credential.

## Risk
Without a broker, the model's context is a credential store; with one, the worst
case is a scoped, expiring handle.

## Evidence
- credential_storage (is it `proxy`?)
- credential_exposed_to_model (should be false)

## Failure Mode
n/a - this is a mitigating pattern; the failure is not adopting it (see KU-0008).

## Detection Clues
- `credential_storage: proxy` and `exposed_to_model: false` indicate the pattern
  is in place.

## Mitigations
- Route all credential use through the broker.
- Issue the minimum scope and the shortest lifetime that works.
- Audit every issuance; revoke on anomaly.
- Keep the broker on a separate process and trust boundary from the agent.

## Safe Test
Confirm that removing the raw secret from the agent's environment does not break
normal operation (the broker still works) and that the agent cannot enumerate or
print a credential.

## Limitations
The broker becomes a critical dependency and a target; protect and monitor it.

## Related Knowledge
- KU-0008
