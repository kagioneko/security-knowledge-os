---
id: KU-1099
title: "Secret unit that must never enter the index"
category: credential-security
source_type: manual
source_ref: "tests/fixture://KU-1099"
classification: secret
status: reviewed
risk_ids: []
version: "0.1"
last_reviewed: "2026-09-10"
requires_ip_review: true
provenance:
  source_title: "test fixture"
  source_url: null
  source_version: null
  source_license: "test fixture - not for distribution"
  derivation: original
  last_verified: "2026-09-10"
---

## Summary
A secret-classified unit. The loader must skip it and it must never appear in the
FTS index or in any retrieval result. Contains only fixture text, no real secret.
