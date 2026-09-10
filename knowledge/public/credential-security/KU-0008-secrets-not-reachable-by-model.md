---
id: KU-0008
title: "Secrets must not be reachable by the model"
category: credential-security
source_type: standard
source_ref: "https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/ (OWASP LLM02, 2025)"
classification: public
status: reviewed
risk_ids:
  - CRED-001
version: "1.0"
last_reviewed: "2026-09-10"
requires_ip_review: false
provenance:
  source_title: "OWASP Top 10 for LLM Applications 2025 - LLM02 Sensitive Information Disclosure"
  source_url: "https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/"
  source_version: "2025"
  source_license: "CC-BY-SA-4.0 (OWASP GenAI Security Project)"
  derivation: summary
  last_verified: "2026-09-10"
---

## Summary
If the model - or a tool it can call - can read a `.env` file, an environment
variable, or a raw vault secret, then a single injection or misjudgement can
disclose a long-lived credential.

## Conditions
- Credentials are stored as environment variables or raw secrets, and
- A tool can read arbitrary files or environment variables, or the credential is
  placed in the prompt.

## Risk
Credential exposure: the key ends up in the transcript, in a log, or in an
outbound message, and remains valid for a long time.

## Evidence
- credential_storage (env / vault / proxy / none)
- credential_exposed_to_model (can the model or a tool read the raw value?)
- tool_policy (file read, env read)

## Failure Mode
A `file_read` tool reads `.env` and the API key appears in the model's answer.

## Detection Clues
- Storage is `env` and a broad file/read tool exists.
- No short-lived token layer in front of the raw secret.
- Logs are not scrubbed for secret patterns.

## Mitigations
- Put a credential broker in front of the raw secret (KU-0009).
- Never expose the raw value to the model or its tools.
- Scrub logs and transcripts for known secret shapes.
- Rotate credentials and keep their lifetime short.

## Safe Test
Place a dummy value such as `SECRET_TEST_123` where a read tool could reach it and
confirm the model cannot read or forward it.

## Limitations
Not disclosing the secret does not stop misuse of the access it grants; scope the
access too.

## Related Knowledge
- KU-0009
- KU-0006
