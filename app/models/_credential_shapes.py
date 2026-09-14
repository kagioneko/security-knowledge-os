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

Codex#1 (round 13, 2026-09-13) found the same gap a FOURTH time (an
OpenAI `sk-proj-` key). Codex's suggested structural alternative (stop
forwarding raw free-text identifiers to the LLM at all; replace them
with local placeholders or derived booleans/enums/counts) was discussed
with the user and NOT taken - it would reshape AttackSurface/
AssessmentContext and the LLM review payload broadly. Instead
(2026-09-13), the identifier-shaped fields (RAG sources, outbound
destinations, tool names, approval keys - never system_prompt/
developer_prompt, which are free text by design) gained a SECOND,
independent check below: `reject_non_identifier_shapes()`. Where
`reject_credential_shapes()` above is a denylist (block known-bad
shapes; a new key format always needs a new entry), the new check is an
ALLOWLIST for what a legitimate identifier looks like (short, separator-
delimited words) - a real API key's random body is, by construction, a
long UNBROKEN run of characters regardless of which service issued it,
so this generalizes to key formats no one has enumerated yet, at the
cost of also rejecting a legitimate identifier that happens to contain
one unusually long unbroken word (accepted trade-off: the field is
identifier-shaped by contract, not prose).
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
    #
    # Codex#2 / Antigravity SKOS-ADV-23 (round 18, 2026-09-14), reproduced
    # exactly as reported: unlike a token's fixed-case prefix (issued by a
    # specific service, e.g. always-uppercase "AKIA", always-lowercase
    # "xox-"), a URI SCHEME is case-insensitive per RFC 3986 - a real
    # driver accepts an uppercase scheme exactly like a lowercase one.
    # This pattern matched only the lowercase spelling, so an uppercase-
    # scheme connection string (otherwise identical in shape) validated
    # and reached AssessmentResult.attack_surface.
    # scripts/secret_scan.py imports this dict directly
    # (`**CREDENTIAL_SHAPE_PATTERNS`), so the same gap applied to the
    # tracked-history secret scan too - fixed here closes both at once,
    # the same "one shared dict, not two drifting copies" property this
    # module's own docstring already establishes.
    "db-connection-string": re.compile(
        r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://"
        r"[^\s:@/'\"]+:[^\s:@/'\"]+@[^\s/'\"]+",
        re.IGNORECASE,
    ),
    # Codex#1 (round 13, 2026-09-13), reproduced exactly as reported: a
    # modern OpenAI project API key (fixed `sk-proj-` prefix) reached the
    # LLM payload unfiltered - the existing `sk-ant-`/Stripe `sk_`-prefixed
    # patterns above do not match this distinct, longer prefix.
    "openai-key": re.compile(r"sk-proj-[0-9A-Za-z_-]{20,}"),
    # A Hugging Face access token: fixed `hf_` prefix, 20+ alphanumeric
    # characters.
    "huggingface-token": re.compile(r"hf_[0-9A-Za-z]{20,}"),
    # A granular npm access token: fixed `npm_` prefix, 36 alphanumeric
    # characters (legacy npm tokens are bare UUIDs, indistinguishable from
    # ordinary identifiers, and are not covered here).
    "npm-token": re.compile(r"npm_[0-9A-Za-z]{36}"),
    # A PyPI API token: fixed `pypi-AgEIcHlwaS5vcmcC` prefix (base64 of a
    # fixed macaroon header identifying pypi.org), 50+ more characters.
    "pypi-token": re.compile(r"pypi-AgEIcHlwaS5vcmcC[0-9A-Za-z_-]{50,}"),
    # A GitHub fine-grained personal access token: fixed `github_pat_`
    # prefix - distinct from the classic `gh[pousr]_`-prefixed tokens
    # already covered above.
    "github-fine-grained-pat": re.compile(r"github_pat_[0-9A-Za-z_]{20,}"),
}


def reject_credential_shapes(value: str) -> str:
    for pattern in CREDENTIAL_SHAPE_PATTERNS.values():
        if pattern.search(value):
            raise ValueError(
                "value looks like a real credential (matches a known secret shape) - "
                "store secrets in Vault and never in an assessment field"
            )
    return value


# Codex#1 (round 13, 2026-09-13): the boundary the ALLOWLIST below draws.
# A legitimate hostname, tool name, or similar short identifier is made of
# short words joined by these separators (`api.example.com`,
# `internal_wiki`, `email_send`, `my-service-name`); a real API key's
# random body is - regardless of which service issued it, known or not -
# a single long UNBROKEN run of characters. 24 comfortably covers real
# identifier words (this project's own fixtures top out at 9-character
# words: "documents", "customer") while every credential shape already in
# CREDENTIAL_SHAPE_PATTERNS above has an unbroken random segment well
# past it.
_MAX_IDENTIFIER_SEGMENT_LENGTH = 24
_IDENTIFIER_SEPARATORS = re.compile(r"[.\-_/:@\s]+")


def reject_non_identifier_shapes(value: str) -> str:
    """Codex#1 (round 13, 2026-09-13), reproduced exactly as reported: a
    modern OpenAI project key reached the LLM payload unfiltered - the
    FOURTH round in a row this same gap was found under a new format
    (round 9, 11, 12, 13). Rather than adding a fifth entry to the
    denylist above, this is an ALLOWLIST for what a legitimate
    identifier-shaped value looks like: only for fields that are
    identifiers/hostnames BY CONTRACT (RAG source names, outbound
    destinations, tool names, approval keys) - never `system_prompt`/
    `developer_prompt`, which hold actual prose and legitimately may
    contain a long word, URL, or hash.

    Splits on the usual identifier/hostname separators and rejects any
    resulting segment over `_MAX_IDENTIFIER_SEGMENT_LENGTH` characters -
    the shape every random credential body has, independent of which
    service issued it or whether this module has ever seen that format
    before. Consulted independently of, and in addition to,
    `reject_credential_shapes()` above; both must pass.
    """
    for segment in _IDENTIFIER_SEPARATORS.split(value):
        if len(segment) > _MAX_IDENTIFIER_SEGMENT_LENGTH:
            raise ValueError(
                f"value contains a {len(segment)}-character unbroken segment "
                f"(over the {_MAX_IDENTIFIER_SEGMENT_LENGTH}-character limit for a "
                "single word of a hostname/identifier) - this looks like a "
                "credential rather than a name; store secrets in Vault and "
                "never in an assessment field"
            )
    return value
