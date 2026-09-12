"""Shared credential-shape detection for free-text assessment fields.

Codex#2 (round 9, 2026-09-12), reproduced exactly as reported: free-text
fields on AssessmentInput/AnswerPatch (system_prompt, RAG sources, tool
names, approval keys, ...) accepted arbitrary text, including a value
shaped like a real credential - that value then flowed unchanged into
AttackSurface and the ReviewPayload sent to an external LLM provider,
which does not satisfy the project's own "AnswerPatch never takes a raw
secret" boundary (README.md, app/models/answer.py's docstring).

No detector can catch every possible secret - this closes the same
concrete, unambiguous credential SHAPES this project's own
scripts/secret_scan.py and app/policy/safe_test.py's _FORBIDDEN list
already recognize, rather than leaving free text completely unfiltered.
A value that merely looks like ordinary prose is never affected.
"""

from __future__ import annotations

import re

_CREDENTIAL_SHAPE_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"xox[baprs]-[0-9A-Za-z-]{12,}"),
    re.compile(r"gh[pousr]_[0-9A-Za-z]{30,}"),
    re.compile(r"sk-ant-[0-9A-Za-z_-]{20,}"),
    # Codex#1 (round 11, 2026-09-13), reproduced exactly as reported:
    # `sk_live_` + 32 chars (a Stripe secret key shape) passed every
    # existing pattern and reached the LLM payload unfiltered. Stripe
    # secret/publishable/restricted keys are an equally concrete,
    # unambiguous shape as the ones already listed above.
    re.compile(r"(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{16,}"),
    # A JWT: three base64url segments separated by dots, the first always
    # decoding to a `{"alg":...,"typ":"JWT"}`-shaped header - `eyJ` is the
    # base64url encoding of `{"` at the start of any JSON object, so this
    # is as unambiguous a shape as the others above, not a guess.
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
)


def reject_credential_shapes(value: str) -> str:
    for pattern in _CREDENTIAL_SHAPE_PATTERNS:
        if pattern.search(value):
            raise ValueError(
                "value looks like a real credential (matches a known secret shape) - "
                "store secrets in Vault and never in an assessment field"
            )
    return value
