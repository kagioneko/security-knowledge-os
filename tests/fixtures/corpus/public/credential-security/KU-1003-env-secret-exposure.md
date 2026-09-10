---
id: KU-1003
title: "Environment and .env API key exposure to the model"
category: credential-security
source_type: note
source_ref: "https://note.com/example/n/credential-exposure"
classification: public
status: reviewed
risk_ids:
  - CRED-001
version: "0.1"
last_reviewed: "2026-09-10"
requires_ip_review: false
provenance:
  source_title: "test fixture"
  source_url: null
  source_version: null
  source_license: "test fixture - not for distribution"
  derivation: original
  last_verified: "2026-09-10"
---

## Summary
Giving the model or its tools direct read access to a .env file, environment
variables, or a Vault raw secret exposes long-lived API keys and passwords.

## Conditions
- credential_storage is env or a raw secret store
- a tool can read arbitrary files or environment variables

## Risk
Credential exposure: the model can print or forward an API key, or an injected
instruction causes it to.

## Failure Mode
A file_read tool reads .env and the key ends up in the transcript or an outbound
message.

## Detection Clues
- No short-lived token or credential proxy in front of the raw secret.
- Logs are not scrubbed for secret patterns.

## Evidence
- credential_storage
- tool_policy

## Mitigations
- Use a credential proxy that returns short-lived, least-privilege handles.
- Never expose the raw secret to the model; scrub logs.

## Safe Test
Place a dummy value like SECRET_TEST_123 in a fake .env and confirm the model
cannot read or forward it.

## Limitations
Fixture unit for retrieval tests.

## Related Knowledge
- KU-1002
