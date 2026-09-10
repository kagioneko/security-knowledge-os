# Attribution & third-party knowledge

The engine code in this repository is original work. The shipped Knowledge Units
(`knowledge/public/`) are **original prose that summarises publicly documented
security concepts**; they do not reproduce third-party text verbatim. Every unit
carries a `provenance` block (`source_title`, `source_url`, `source_version`,
`source_license`, `derivation`, `last_verified`).

`derivation` is one of: `original` (our own analysis), `summary` (our own prose
summarising a public concept - **all shipped units are this**), `adaptation`
(reworded from a specific source), `quotation` (contains verbatim quoted text -
**none of the shipped units are this**).

## Sources referenced by the Knowledge corpus

| source | used by | licence / terms |
| --- | --- | --- |
| OWASP Top 10 for LLM Applications 2025 (OWASP GenAI Security Project) | KU-0001–0008, KU-0010, KU-0011, KU-0013 | CC-BY-SA-4.0 |
| MITRE ATLAS (atlas.mitre.org) | KU-0005, KU-0013 | MITRE ATLAS / ATT&CK Terms of Use - free use with attribution |
| NIST AI 600-1 (Generative AI Profile) | KU-0009 | U.S. Government work / public domain |
| NIST AI Risk Management Framework (AI RMF 1.0) | KU-0012 | U.S. Government work / public domain |
| simonwillison.net (prompt injection writing) | KU-0002 (context only, not reproduced) | referenced, not reproduced |

## Note on CC-BY-SA-4.0

OWASP's material is CC-BY-SA-4.0. The shipped units are **not** derivative works
of the OWASP text - they are original wording describing the same, widely-known
risk categories, with the OWASP page cited as the authoritative reference. If a
future unit adapts specific OWASP wording, mark it `derivation: adaptation` and
the ShareAlike obligation must be considered for that unit and any pack that
distributes it.

## Engine dependencies

Runtime: `pydantic` (MIT), `PyYAML` (MIT). Optional: `fastapi` (MIT),
`uvicorn` (BSD-3-Clause), `anthropic` (MIT). See `sbom.json`.

## Project licence

**Not yet chosen.** `pyproject.toml` currently declares `Proprietary` as a safe
default. A licence must be selected (e.g. Apache-2.0 or MIT for the engine, with
the knowledge corpus and any commercial packs licensed separately - see the
Update Pack / Distribution spec) before public release.
