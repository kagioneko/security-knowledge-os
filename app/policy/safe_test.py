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

import re
import shutil
from collections.abc import Iterable
from pathlib import Path

from pydantic import ValidationError

from app.ingestion.parser import FrontMatterError, _read_text_no_follow, safe_load_bounded
from app.ingestion.snapshot import snapshot_tree
from app.models.assessment import SafeTest, SafeTestEnvironment, UntrustedSafeTestProposal
from app.models.policy_outcome import PolicyDecision, PolicyOutcome, allow, stop
from app.models.risk import RiskRule

# Codex#5 (round 7, 2026-09-12): a hand-authored safe-test template file is
# at most a few KB in real use; bounds the raw text handed to the YAML
# parser regardless of how it would blow up.
_MAX_SAFE_TEST_FILE_BYTES = 50_000

_FORBIDDEN = [
    (re.compile(r"\bprod(uction)?\b", re.I), "references a production target"),
    (re.compile(r"rm\s+-rf", re.I), "contains a destructive shell command"),
    (re.compile(r"\bDROP\s+TABLE\b", re.I), "contains a destructive SQL statement"),
    (re.compile(r"\bDELETE\s+FROM\b", re.I), "contains a destructive SQL statement"),
    (re.compile(r"\bTRUNCATE\b", re.I), "contains a destructive SQL statement"),
    (re.compile(r"\bsudo\b", re.I), "escalates privileges"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "contains an AWS-key-shaped literal"),
    (re.compile(r"BEGIN (?:RSA |OPENSSH )?PRIVATE KEY"), "contains a private key"),
    (re.compile(r"\bxox[bpsar]-[0-9A-Za-z-]+"), "contains a Slack-token-shaped literal"),
]

# Hosts / addresses that are safe to name in a test.
_SAFE_HOST = re.compile(
    r"^(localhost|127\.0\.0\.1|(?:[a-z0-9-]+\.)*example\.(?:com|org|net|invalid)|[a-z0-9-]+\.invalid)$",
    re.I,
)
_HOST_LIKE = re.compile(r"https?://([^/\s]+)|@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")


def _scan_text(parts: list[str]) -> list[str]:
    text = "\n".join(parts)
    reasons = [reason for pattern, reason in _FORBIDDEN if pattern.search(text)]
    for match in _HOST_LIKE.finditer(text):
        host = (match.group(1) or match.group(2) or "").split(":")[0]
        if host and not _SAFE_HOST.match(host):
            reasons.append(f"names an external destination '{host}'")
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

    reasons += _scan_text(test.setup + test.steps + test.cleanup + [test.scope])

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
                raise SafeTestLoadError(f"{path}: {exc}") from exc
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
