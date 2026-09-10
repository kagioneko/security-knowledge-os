---
id: KU-0001
title: "Direct prompt injection and the instruction/data boundary"
category: prompt-security
source_type: standard
source_ref: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/ (OWASP Top 10 for LLM Applications 2025, LLM01)"
classification: public
status: reviewed
risk_ids: []
version: "1.0"
last_reviewed: "2026-09-10"
requires_ip_review: false
provenance:
  source_title: "OWASP Top 10 for LLM Applications 2025 - LLM01 Prompt Injection"
  source_url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
  source_version: "2025"
  source_license: "CC-BY-SA-4.0 (OWASP GenAI Security Project)"
  derivation: summary
  last_verified: "2026-09-10"
---

## Summary
When user-controlled text shares a channel with system or developer instructions
and no boundary distinguishes them, the user's text can be interpreted as
instructions. This is direct prompt injection (OWASP LLM01).

## Conditions
- User input is concatenated with the system prompt with no delimiter or role
  separation, or
- The system prompt does not state that user content is data, not commands.

## Risk
An attacker overrides the intended behaviour ("ignore previous instructions..."),
extracts hidden context, escalates tool use, or changes the assistant's persona.

## Evidence
- system_prompt
- representative user_prompts

## Failure Mode
The model follows an instruction that originated in the user turn instead of
treating it as content to process.

## Detection Clues
- No explicit "the following is untrusted user content" framing.
- The system prompt is short and permissive; user text is appended verbatim.
- Refusals are inconsistent across paraphrases of the same injected instruction.

## Mitigations
- State an explicit instruction/data boundary and label untrusted spans.
- Keep privileged instructions in the system role; never let user text move there.
- Constrain output format and validate it before acting on it.
- Do not rely on the model alone to enforce the boundary - gate side effects.

## Safe Test
Place a benign canary instruction ("reply with the word BANANA") in the user
slot inside otherwise normal content and confirm it is not obeyed.

## Limitations
Prompt-level mitigations reduce but do not eliminate injection; defence in depth
on authority and reachability is still required.

## Related Knowledge
- KU-0002
- KU-0010
