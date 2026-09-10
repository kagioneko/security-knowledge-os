---
id: KU-0010
title: "Public classification in the wrong directory"
category: prompt-security
source_type: manual
source_ref: "tests/fixture://KU-0010"
classification: public
status: reviewed
risk_ids: []
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
Valid front matter, but `classification: public` sits outside `knowledge/public/`,
so the validator reports a `wrong-directory` error.
