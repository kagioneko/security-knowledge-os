"""Safe Test templates and the deterministic safety validator (spec Section 14).

Path an LLM idea cannot skip:

    UntrustedSafeTestProposal  (LLM, origin='llm')
        -> promote_proposal()   -> HUMAN_APPROVAL_REQUIRED  (always; a human vets it)
        -> becomes a vetted template (origin='template')
        -> validate_safe_test() -> ALLOWED / POLICY_BLOCKED
        -> attached to the result

The validator requires the safe attributes (sandbox/read-only/canary, scope,
expected behaviour, failure condition, cleanup) and rejects any text that looks
like a real secret, an external destination, a destructive operation, or a
production target.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import ValidationError

from app.ingestion.parser import FrontMatterError, _read_text_no_follow, safe_load_bounded
from app.ingestion.snapshot import snapshot_tree
from app.models._credential_shapes import CREDENTIAL_SHAPE_PATTERNS
from app.models.assessment import SafeTest, SafeTestEnvironment, UntrustedSafeTestProposal
from app.models.policy_outcome import PolicyDecision, PolicyOutcome, allow, stop
from app.models.risk import RiskRule
from app.safe_errors import format_validation_error

# Codex#5 (round 7, 2026-09-12): a hand-authored safe-test template file is
# at most a few KB in real use; bounds the raw text handed to the YAML
# parser regardless of how it would blow up.
_MAX_SAFE_TEST_FILE_BYTES = 50_000

# Codex#3 (round 14, 2026-09-13), reproduced exactly as reported: this list
# had its own hand-maintained AWS/private-key/Slack patterns instead of the
# shared, actively-maintained CREDENTIAL_SHAPE_PATTERNS (app/models/
# _credential_shapes.py, kept in sync with scripts/secret_scan.py since
# round 12, Codex#8) - Stripe/JWT/OpenAI/Google/GitHub/npm/PyPI shapes
# added there since round 11 were never reflected here, so a safe test
# could name any of them and still validate. Reusing the shared dict means
# this can no longer drift the same way.
_FORBIDDEN = [
    (re.compile(r"\bprod(uction)?\b", re.I), "references a production target"),
    (re.compile(r"rm\s+-rf", re.I), "contains a destructive shell command"),
    (re.compile(r"\bDROP\s+TABLE\b", re.I), "contains a destructive SQL statement"),
    (re.compile(r"\bDELETE\s+FROM\b", re.I), "contains a destructive SQL statement"),
    (re.compile(r"\bTRUNCATE\b", re.I), "contains a destructive SQL statement"),
    (re.compile(r"\bsudo\b", re.I), "escalates privileges"),
    *(
        (pattern, f"contains a {name}-shaped literal")
        for name, pattern in CREDENTIAL_SHAPE_PATTERNS.items()
    ),
]

# Hosts / addresses that are safe to name in a test.
_SAFE_HOST = re.compile(
    r"^(localhost|127\.0\.0\.1|::1|(?:[a-z0-9-]+\.)*example\.(?:com|org|net|invalid)"
    r"|[a-z0-9-]+\.invalid)$",
    re.I,
)
# Codex#3 (round 14, 2026-09-13), reproduced exactly as reported: this only
# ever matched an http(s) URL or an email-like "@host" - ftp://evil.example,
# gopher://evil.example/, and a plain hostname/IP literal with no scheme at
# all (e.g. "connect to evil.example directly") all passed unrecognized.
# The first alternative now matches ANY URI scheme's authority, not just
# http(s); the third is a conservative bare hostname/IP shape (at least two
# dot-separated labels) - the module's own established posture (mentioning
# "prod" or "sudo" ANYWHERE already blocks a test outright) already prefers
# an author having to rephrase a false positive over missing a real
# destination, so a safe test incidentally naming a file like "config.yaml"
# is deliberately traded off the same way.
_URI_AUTHORITY = re.compile(r"[a-z][a-z0-9+.-]*://[^/\s]+", re.I)
_EMAIL_LIKE_HOST = re.compile(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", re.I)
_BARE_HOST = re.compile(
    r"\b([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+)\b",
    re.I,
)
# Codex#4 (round 15, 2026-09-14), reproduced exactly as reported: neither
# `_URI_AUTHORITY`'s old `.split(":")[0]` truncation nor `_BARE_HOST`
# recognized a bare (schemeless) IPv6 literal at all -
# `curl https://localhost:443@attacker.com/x` truncated the authority at
# the first colon and checked only "localhost" (userinfo before the real
# host, which was never inspected), and "connect to 2606:4700:4700::1111"
# matched neither alternative (colon-separated hex groups, not the
# dot-separated label shape _BARE_HOST expects). The regex below is
# deliberately loose (it also matches non-address colon-separated text
# like timestamps or ratios) - `ipaddress.ip_address()` is the actual
# validator; the regex only limits how much text gets parsed as a
# candidate.
_BARE_IPV6_CANDIDATE = re.compile(r"\b[0-9A-Fa-f:]{2,}\b")


def _flag_host(host: str, seen: set[str], reasons: list[str]) -> None:
    if not host or host in seen or _SAFE_HOST.match(host):
        return
    seen.add(host)
    reasons.append(f"names an external destination '{host}'")


def _scan_text(parts: list[str]) -> list[str]:
    text = "\n".join(parts)
    reasons = [reason for pattern, reason in _FORBIDDEN if pattern.search(text)]
    seen: set[str] = set()

    # Codex#4 (round 15, 2026-09-14): parse the full scheme://authority match
    # with urlsplit() and use its .hostname, instead of naively truncating
    # the authority at the first ":" - urlsplit correctly separates
    # userinfo ("user:pass@"), a port, and bracketed IPv6 from the actual
    # host regardless of which of those are present.
    #
    # Codex#4 / Antigravity SKOS-ADV-19 (round 17, 2026-09-14), reproduced
    # exactly as reported: urlsplit(...).hostname raises ValueError for a
    # malformed bracketed IPv6 authority (e.g. "http://[:::]"), uncaught
    # here - validate_safe_test() raised instead of returning the
    # documented fail-closed PolicyDecision, surfacing as an untyped 500
    # from any API path that reaches it. A destination this module cannot
    # even PARSE is exactly the kind of thing it should refuse to pass
    # silently on - treated as its own blocking finding, not skipped.
    for match in _URI_AUTHORITY.finditer(text):
        try:
            hostname = urlsplit(match.group(0)).hostname
        except ValueError:
            # Codex round-30 (2026-09-25), reproduced exactly as reported:
            # urlsplit() rejects this authority specifically because it could
            # not be parsed apart - the raw match can still contain userinfo
            # ('user:pass@...'), i.e. exactly the credential-shaped content
            # this module exists to keep out of a safe test. Echoing it back
            # in the rejection reason defeated that. The reason states that a
            # destination was unparseable without repeating it.
            reasons.append("contains a malformed, unparseable destination authority")
            continue
        if hostname:
            _flag_host(hostname, seen, reasons)

    for match in _EMAIL_LIKE_HOST.finditer(text):
        _flag_host(match.group(1), seen, reasons)

    for match in _BARE_HOST.finditer(text):
        _flag_host(match.group(1), seen, reasons)

    for match in _BARE_IPV6_CANDIDATE.finditer(text):
        candidate = match.group(0)
        if candidate.count(":") < 2:
            continue  # too few colons to plausibly be IPv6; avoids flagging e.g. "12:30"
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        _flag_host(candidate, seen, reasons)

    return reasons


def validate_safe_test(test: SafeTest) -> PolicyDecision:
    reasons: list[str] = []

    if test.origin == "llm":  # type: ignore[comparison-overlap]
        reasons.append("origin 'llm' is never executable")
    if not test.environment:
        reasons.append("no sandbox/read-only/canary environment declared")
    if not set(test.environment) <= set(SafeTestEnvironment):
        reasons.append("unknown environment value")
    if not test.scope.strip():
        reasons.append("scope is not stated")
    if not test.cleanup:
        reasons.append("no cleanup steps")
    if SafeTestEnvironment.CANARY in test.environment and not test.uses_canary_values:
        reasons.append("declares a canary environment but uses_canary_values is false")

    # Codex#3 (round 14, 2026-09-13), reproduced exactly as reported: this
    # omitted `preconditions` entirely (operational instructions, exactly
    # as executable-looking as setup/steps/cleanup) and the two free-text
    # outcome fields `expected_secure_behavior`/`failure_condition` -
    # nothing stopped an author from putting a production target,
    # destructive command, or secret-shaped literal in any of the three.
    reasons += _scan_text(
        test.preconditions
        + test.setup
        + test.steps
        + test.cleanup
        + [test.scope, test.expected_secure_behavior, test.failure_condition]
    )

    if reasons:
        return stop(PolicyOutcome.POLICY_BLOCKED, f"safe-test:{test.id}", *reasons)
    return allow(f"safe-test:{test.id}")


def promote_proposal(proposal: UntrustedSafeTestProposal) -> PolicyDecision:
    """An LLM proposal never becomes executable automatically."""
    return stop(
        PolicyOutcome.HUMAN_APPROVAL_REQUIRED,
        f"safe-test-proposal:{proposal.title}",
        "LLM-authored safe-test ideas must be turned into a vetted template by a human",
    )


class SafeTestLoadError(Exception):
    """A safe-test template file is invalid or unsafe."""


def load_safe_test_templates(root: Path | str) -> dict[str, SafeTest]:
    root = Path(root)
    # Codex#8 (round 5, 2026-09-12): Path.rglob() on a missing or
    # non-directory root silently yields nothing - `load_safe_test_templates(
    # "/typo'd/path")` and `load_safe_test_templates("README.md")` both
    # returned `{}`, an empty-but-"valid" catalogue, exactly like the
    # pre-fix load_rules() bug (Codex cross-review finding #1, 2026-09-11).
    # A misconfigured/missing SKOS_SAFE_TESTS_ROOT must be a hard load
    # error, not a silent "every safe-test recommendation just disappeared".
    if not root.is_dir():
        raise SafeTestLoadError(
            f"safe-tests root does not exist or is not a directory: {root}"
        )
    # Codex#5 (round 8, 2026-09-12), reproduced exactly as reported: Codex#2
    # (round 7)'s O_NOFOLLOW read protects only the FINAL pathname component
    # - `rglob()`'s own directory walk and the later open both re-resolve
    # the full path from scratch, so a symlinked ANCESTOR directory under
    # `root` was silently followed straight through to a file entirely
    # outside it - the same class of gap app/ingestion/snapshot.py's
    # directory-fd walk already closes for the knowledge corpus (round 7,
    # Codex#2). Snapshotting `root` the same way removes the live,
    # externally-mutable tree from the read path entirely; snapshot_tree()
    # also already rejects any symlink anywhere in the tree, which is why
    # the old `if path.is_symlink()` check right before the read is gone
    # below.
    try:
        snapshot_root = snapshot_tree(root)
    except OSError as exc:
        raise SafeTestLoadError(f"{root}: could not safely read the safe-tests directory: {exc}") \
            from exc

    templates: dict[str, SafeTest] = {}
    try:
        for snap_path in sorted(snapshot_root.rglob("*.yaml")):
            path = root / snap_path.relative_to(snapshot_root)  # for error messages only
            try:
                text = _read_text_no_follow(snap_path)
            except (OSError, FrontMatterError) as exc:
                raise SafeTestLoadError(f"{path}: {exc}") from exc
            try:
                # Codex#5 (round 7, 2026-09-12): this yaml.safe_load() call
                # used to run OUTSIDE any try/except at all - invalid YAML
                # raised a bare yaml.YAMLError straight out of
                # load_safe_test_templates(). Also had none of the
                # merge-key ban / size cap / RecursionError handling the
                # knowledge front-matter loader already had.
                raw = safe_load_bounded(
                    text, max_bytes=_MAX_SAFE_TEST_FILE_BYTES, what="safe-test file"
                )
            except FrontMatterError as exc:
                raise SafeTestLoadError(f"{path}: {exc}") from exc
            try:
                test = SafeTest.model_validate(raw)
            except ValidationError as exc:
                raise SafeTestLoadError(f"{path}: {format_validation_error(exc)}") from exc
            decision = validate_safe_test(test)
            if not decision.is_allowed:
                raise SafeTestLoadError(f"{path}: {decision.outcome.value}: {decision.reasons}")
            if test.id in templates:
                raise SafeTestLoadError(f"duplicate safe-test id {test.id}")
            templates[test.id] = test
    finally:
        shutil.rmtree(snapshot_root, ignore_errors=True)
    return templates


def unresolved_safe_test_references(
    rules: Iterable[RiskRule], templates: dict[str, SafeTest]
) -> list[str]:
    """Codex#8 (round 5, 2026-09-12): every `RiskRule.safe_test_template`
    that does not resolve in `templates` - a typo in a rule file, or a
    `SKOS_SAFE_TESTS_ROOT` misconfiguration that emptied the whole
    catalogue. `assess.py::_safe_tests_for()` intentionally does not raise on
    a missing template mid-assessment (`test is None: continue` - a rule
    still fires, it just has no safe-test recommendation attached), so a
    broken reference previously failed SILENTLY with no error anywhere. This
    is the loud, load-time counterpart: callers that load both catalogues
    together (the CLI's `validate-safe-tests`, a startup check) can fail on
    a non-empty result instead of only ever seeing recommendations quietly
    vanish. Returns `"<rule_id> -> <safe_test_template>"` for each broken
    reference, in rule order.
    """
    return [
        f"{rule.id} -> {rule.safe_test_template}"
        for rule in rules
        if rule.safe_test_template and rule.safe_test_template not in templates
    ]
