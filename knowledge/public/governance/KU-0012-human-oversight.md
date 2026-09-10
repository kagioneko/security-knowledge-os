---
id: KU-0012
title: "Human oversight for consequential decisions"
category: governance
source_type: standard
source_ref: "https://www.nist.gov/itl/ai-risk-management-framework (NIST AI RMF: Govern / Manage)"
classification: public
status: reviewed
risk_ids:
  - GOV-001
version: "1.0"
last_reviewed: "2026-09-10"
requires_ip_review: false
provenance:
  source_title: "NIST AI Risk Management Framework (AI RMF 1.0)"
  source_url: "https://www.nist.gov/itl/ai-risk-management-framework"
  source_version: "1.0 (2023-01)"
  source_license: "U.S. Government work / public domain"
  derivation: summary
  last_verified: "2026-09-10"
---

## Summary
An assessment tool supports a decision; it does not make it. Consequential
outcomes - deployment approval, risk acceptance, anything affecting money, people,
contracts, production, or external parties - stay with a named human owner.

## Conditions
- The system produces an output that could be read as a final safety, legal, or
  business decision, and
- There is no explicit step where a person owns that decision.

## Risk
An automated "PASS" is treated as a guarantee; responsibility is diffused; a wrong
call has no owner.

## Evidence
- Which decisions are automated vs. reviewed
- Who signs off on high-impact outcomes

## Failure Mode
A pipeline promotes a change to production because the assistant returned "looks
fine" and nothing required a person to confirm.

## Detection Clues
- High-impact actions are present with no approval coverage.
- Output uses definitive language ("safe", "approved") rather than scoped findings.

## Mitigations
- Return findings, evidence, unknowns, and residual risk - not a verdict.
- Require a human owner for every consequential decision.
- Record the revision, model, and knowledge version behind each result.
- State plainly that PASS is not a security guarantee and UNKNOWN is valid.

## Safe Test
Review the output wording and the workflow: confirm a human sign-off is required
before any consequential action and that the result carries its provenance.

## Limitations
Oversight only works if the reviewer has enough context; give them the evidence.

## Related Knowledge
- KU-0005
- KU-0011
