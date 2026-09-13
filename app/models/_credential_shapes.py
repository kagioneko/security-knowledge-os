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

This remains, by construction, an enumeration of known formats - Codex#1
(round 12, 2026-09-13) found the SAME residual gap again (a Google-API-
key-shaped value, not yet in the list, reached the LLM payload) after
round 11 closed the previous gap (Stripe/JWT). Every round narrows the
list further; none can make it exhaustive. An arbitrary OPAQUE secret
with no recognizable shape is - and will remain - indistinguishable from
ordinary free text; this module's actual, honest boundary is "known
shapes are rejected", never "no secret can pass". Do not restate that
stronger claim in docs/comments (Codex#1, round 12: a prior restatement
of it in PUBLICATION_MANIFEST.md was itself flagged as inaccurate).
"""

from __future__ import annotations

import re

# Codex#8 (round 12, 2026-09-13), reproduced exactly as reported:
# scripts/secret_scan.py kept its OWN separate pattern dict, which was
# never updated when Stripe/JWT detection was added here (round 11) - a
# Stripe key or JWT committed to a tracked file passed the pre-publication
# secret scan even though the runtime model already rejected it. A named
# dict (rather than the previous plain tuple) lets both this module's
# `reject_credential_shapes()` AND secret_scan.py's file scan iterate the
# exact same, single, maintained pattern source - the same drift cannot
# recur because there is no second list left to fall out of sync.
CREDENTIAL_SHAPE_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws-access-key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private-key-block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "slack-token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{12,}"),
    "github-pat": re.compile(r"gh[pousr]_[0-9A-Za-z]{30,}"),
    "anthropic-key": re.compile(r"sk-ant-[0-9A-Za-z_-]{20,}"),
    # Codex#1 (round 11, 2026-09-13), reproduced exactly as reported:
    # `sk_live_` + 32 chars (a Stripe secret key shape) passed every
    # existing pattern and reached the LLM payload unfiltered. Stripe
    # secret/publishable/restricted keys are an equally concrete,
    # unambiguous shape as the ones already listed above.
    "stripe-key": re.compile(r"(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{16,}"),
    # A JWT: three base64url segments separated by dots, the first always
    # decoding to a `{"alg":...,"typ":"JWT"}`-shaped header - `eyJ` is the
    # base64url encoding of `{"` at the start of any JSON object, so this
    # is as unambiguous a shape as the others above, not a guess.
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    # Codex#1 (round 12, 2026-09-13), reproduced exactly as reported: a
    # Google API key (fixed `AIza` prefix + 35 more characters, always this
    # exact length) reached the LLM payload unfiltered via
    # outbound_destinations - equally concrete and unambiguous as the
    # shapes above.
    "google-api-key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    # A GitLab personal access token: fixed `glpat-` prefix, 20+ base64url
    # characters.
    "gitlab-pat": re.compile(r"glpat-[0-9A-Za-z_-]{20,}"),
    # A Discord bot token: three dot-separated segments - a base64url
    # user-id segment (always starting with a letter in {M,N,O} for the
    # snowflake-ID ranges in use), a fixed-length timestamp segment, then a
    # longer HMAC segment.
    "discord-bot-token": re.compile(
        r"[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}"
    ),
    # A database connection URL with credentials embedded in the authority
    # component (scheme://user:password@host) - the scheme names below are
    # never used for anything BUT a database/broker connection string, so
    # this cannot mistake an ordinary URL for one.
    "db-connection-string": re.compile(
        r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://"
        r"[^\s:@/'\"]+:[^\s:@/'\"]+@[^\s/'\"]+"
    ),
}


def reject_credential_shapes(value: str) -> str:
    for pattern in CREDENTIAL_SHAPE_PATTERNS.values():
        if pattern.search(value):
            raise ValueError(
                "value looks like a real credential (matches a known secret shape) - "
                "store secrets in Vault and never in an assessment field"
            )
    return value
