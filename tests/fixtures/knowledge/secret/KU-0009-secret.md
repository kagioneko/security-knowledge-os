---
id: KU-0009
title: "Secret-classified unit that must never be in a repo"
category: credential-security
source_type: manual
source_ref: "tests/fixture://KU-0009"
classification: secret
status: reviewed
risk_ids: []
version: "0.1"
last_reviewed: "2026-09-10"
requires_ip_review: true
---

## Summary
Valid front matter, but `classification: secret` inside the repository is a
`secret-in-repo` error regardless of location.
