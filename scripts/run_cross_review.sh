#!/usr/bin/env bash
# Cross-AI pre-publication review (AI_RULES.md).
#   Codex       -> code audit               (REVIEW_CHECKLIST.md Part A)
#   Antigravity -> adversarial design audit  (REVIEW_CHECKLIST.md Part B)
#
# Read-only: neither reviewer is allowed to modify the tree. Outputs land in
# reviews/ and must be summarised into HANDOFF.md before publishing.
#
# Usage:
#   scripts/run_cross_review.sh            # run both
#   scripts/run_cross_review.sh codex      # run one
#   scripts/run_cross_review.sh antigravity
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

COMMIT="$(git rev-parse --short HEAD)"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$REPO/reviews"
mkdir -p "$OUT"
TIMEOUT="${REVIEW_TIMEOUT:-1800}"

WHICH="${1:-both}"

CODEX_PROMPT="You are doing a PRE-PUBLICATION CODE AUDIT of this repository
(Security Knowledge OS, Apache-2.0, commit ${COMMIT}, not yet pushed).

READ FIRST, in this repo: REVIEW_PACKAGE.md, then REVIEW_CHECKLIST.md 'Part A -
Code audit', then PUBLICATION_MANIFEST.md.

Audit against Part A only: arbitrary code execution paths (rules must be data,
not code); SQL / SQLite (parameterisation, FTS5 syntax injection, read-only
enforcement); path traversal and unsafe file write/delete (reindex_atomic,
rglob, scripts); exception handling and fail-closed behaviour; type/model
soundness (extra='forbid', the Finding A8 validator, AnswerPatch never taking a
raw secret); API boundary (in-memory store, /answers cost, /history cycles,
unauthenticated reindex); test-coverage gaps; dependency / supply chain.

Do NOT modify any file. For each finding give: severity, file:line, repro,
suggested fix. End with an overall verdict: PASS / PASS-with-nits /
CHANGES-REQUIRED, and reference commit ${COMMIT}."

ANTIGRAVITY_PROMPT="You are doing a PRE-PUBLICATION ADVERSARIAL DESIGN AUDIT of
this repository (Security Knowledge OS, Apache-2.0, commit ${COMMIT}, not yet
pushed). Goal: find how to fool the system itself.

READ FIRST, in this repo: REVIEW_PACKAGE.md (Trust Boundary, Threat Model, A8
boundary, Human Gate, Fail-closed, Classification), then REVIEW_CHECKLIST.md
'Part B - Adversarial design audit'.

Audit against Part B only, from an attacker's view: prompt / indirect prompt
injection against the reviewer; knowledge poisoning (any write path into
knowledge/; can a poisoned KU misfire a rule; is /v1/knowledge/validate truly
read-only); pulling UNKNOWN toward PASS (missing required_evidence, unknown
checks, _emit_indeterminate, N/A masking, AnswerPatch); Human Gate bypass
(unknown action fail-closed; can a safe_test be 'run'); LLM override of the
verdict (any path to set a status in ReviewerObservations); index / DB tampering
(is verify_chunk_hashes always run; TOCTOU; reindex race); FUTURE Update Pack ->
RCE (path traversal / symlink / manifest mismatch / unapproved severity
downgrade when the M9-M10 Pack Manager lands); classification leakage; secret
exposure in logs.

Do NOT modify any file. For each attack give: preconditions, steps, impact,
severity, mitigation. End with an overall verdict: PASS / PASS-with-nits /
CHANGES-REQUIRED, and reference commit ${COMMIT}."

# Explicitly NOT fast mode: pin full reasoning depth for a security audit.
# 'codex exec' carries no persistent "fast" toggle (that is TUI session state),
# but we set the reasoning effort explicitly so the audit does not run light.
CODEX_MODEL_OPTS=(-c 'model_reasoning_effort="high"')

# Codex's read-only sandbox uses bubblewrap, which cannot create a user
# namespace on this host (kernel.apparmor_restrict_unprivileged_userns=1) and
# dies with "bwrap: loopback: Failed RTM_NEWADDR". Every sandbox mode hits this,
# so we run without the OS sandbox. It is still a read-only audit by intent:
# approval_policy=never, the prompt forbids edits, and the tree is git-tracked
# (any stray write is `git checkout`-recoverable). Override with
# CODEX_SANDBOX=read-only once the host allows unprivileged userns.
#
# Codex#2 (round 14, 2026-09-13), reproduced exactly as reported:
# danger-full-access gives the reviewer OS-level permission to run any
# command and write anywhere the invoking user can - a prompt-injection
# string planted in ANY file the reviewer reads (source, YAML, Markdown,
# a knowledge-base entry) could induce it to act on that instead of just
# auditing, and unlike a stray write inside this git-tracked repo (always
# `git checkout`-recoverable), a write or network call OUTSIDE the repo is
# not undoable by this script at all. A full fix (a disposable container/
# VM with the repo bind-mounted read-only, no Vault/socket access,
# restricted network, an explicit resource limit) was discussed with the
# user and deliberately deferred - it changes how the shared Codex review
# pipeline runs across every project on this host, not just this one, and
# needs the host's actual container/VM capabilities checked first, which
# a code-review round cannot verify on its own. What IS in scope here: a
# resource-limit MITIGATION that needs no new infrastructure - CPU time
# and max written-file-size caps, both scoped to this process (and its
# children) alone via the shell's own `ulimit`. Deliberately NOT
# `ulimit -u` (max processes): on Linux that limit is enforced per REAL
# UID system-wide, not per process tree - setting it here could starve
# every other service already running as this same account (nekoguard,
# discord-bot, vps-spirit, ...), a worse outcome than the risk being
# mitigated. This bounds worst-case local resource abuse; it does not
# bound network access or writes within these limits - it is a
# mitigation, not the fix Codex actually asked for.
CODEX_SANDBOX="${CODEX_SANDBOX:-danger-full-access}"
CODEX_MAX_CPU_SECONDS="${CODEX_MAX_CPU_SECONDS:-1800}"
CODEX_MAX_FILE_SIZE_BLOCKS="${CODEX_MAX_FILE_SIZE_BLOCKS:-2097152}"  # 512-byte blocks; ~1 GiB

# Codex#8 (round 15, 2026-09-14), reproduced exactly as reported:
# `REVIEW_TIMEOUT=0 scripts/run_cross_review.sh codex; echo $?` printed 0
# even though the reviewer never ran at all - the `|| { echo ...; }`
# below caught the failure into a LOG LINE but let the function itself
# (and so the whole script, and the scheduled wrapper around it) report
# success regardless. A caller has no way to tell "produced a verdict"
# apart from "silently produced nothing" without reading every log by
# hand. `_has_verdict()` requires one of the three literal tokens the
# prompt instructs the reviewer to output; a failed/timed-out/empty run
# now makes the function - and this script's own exit code - reflect
# that honestly.
_has_verdict() {
  grep -qE '\bPASS\b|\bCHANGES-REQUIRED\b' "$1"
}

run_codex() {
  local f="$OUT/codex-${STAMP}-${COMMIT}.md"
  echo ">> Codex code audit (reasoning_effort=high, not fast; sandbox=${CODEX_SANDBOX}) -> $f"
  {
    echo "# Codex code audit"
    echo "commit: ${COMMIT}   date: $(date -Iseconds)"
    echo "config: model_reasoning_effort=high (explicit; fast mode off); sandbox=${CODEX_SANDBOX}"
    echo
  } > "$f"
  # Subshell so these ulimits apply only to this invocation (and whatever
  # it spawns), never leaking into the rest of this script or the
  # Antigravity run below.
  # `if PIPELINE; then ...; else ...; fi` - not `PIPELINE || true` - is
  # required here: with `set -e` active, `|| true` runs `true` as its OWN
  # separate command to suppress errexit, and that overwrites
  # $PIPESTATUS before this function ever gets to read it (silently
  # losing codex's real exit code, the exact bug this fix is closing).
  # An `if` condition suppresses errexit for the tested command without
  # running anything else afterward, so $PIPESTATUS is still the
  # pipeline's own when the `else` branch reads it.
  local codex_exit
  if (
    ulimit -t "$CODEX_MAX_CPU_SECONDS"
    ulimit -f "$CODEX_MAX_FILE_SIZE_BLOCKS"
    exec timeout "$TIMEOUT" codex exec "${CODEX_MODEL_OPTS[@]}" \
      -C "$REPO" -s "$CODEX_SANDBOX" --skip-git-repo-check \
      "$CODEX_PROMPT"
  ) 2>&1 | tee -a "$f"; then
    codex_exit=0
  else
    codex_exit="${PIPESTATUS[0]}"
  fi
  if [ "$codex_exit" -ne 0 ]; then
    echo "!! codex exec failed or timed out (exit $codex_exit)" | tee -a "$f"
    return 1
  fi
  if ! _has_verdict "$f"; then
    echo "!! codex exec exited 0 but no PASS/PASS-with-nits/CHANGES-REQUIRED verdict was found in $f" | tee -a "$f"
    return 1
  fi
  echo "   done: $f"
}

run_antigravity() {
  local f="$OUT/antigravity-${STAMP}-${COMMIT}.md"
  echo ">> Antigravity adversarial design audit -> $f"
  {
    echo "# Antigravity adversarial design audit"
    echo "commit: ${COMMIT}   date: $(date -Iseconds)"
    echo
  } > "$f"
  # --mode plan keeps it read-only (no edits); --dangerously-skip-permissions is
  # required so headless mode does not auto-deny read tools (grep/find/cat) it
  # cannot prompt for. plan mode bounds the "dangerously": it still cannot write.
  # --print-timeout: agy's own print-mode wait defaults to 5m regardless of the
  # outer `timeout "$TIMEOUT"` wrapper - a real audit at --effort high routinely
  # runs past 5m and was observed returning a "partial output" stub instead of
  # a verdict (2026-09-11). Match it to $TIMEOUT so agy's own deadline is the
  # binding one.
  # See run_codex()'s identical comment above for why this is an `if`
  # over the pipeline, not `PIPELINE || true`.
  local agy_exit
  if timeout "$TIMEOUT" agy -p "$ANTIGRAVITY_PROMPT" \
    --add-dir "$REPO" --effort high --mode plan --dangerously-skip-permissions \
    --print-timeout "${TIMEOUT}s" --output-format text 2>&1 | tee -a "$f"; then
    agy_exit=0
  else
    agy_exit="${PIPESTATUS[0]}"
  fi
  if [ "$agy_exit" -ne 0 ]; then
    echo "!! agy failed or timed out (exit $agy_exit)" | tee -a "$f"
    return 1
  fi
  if ! _has_verdict "$f"; then
    echo "!! agy exited 0 but no PASS/PASS-with-nits/CHANGES-REQUIRED verdict was found in $f" | tee -a "$f"
    return 1
  fi
  echo "   done: $f"
}

overall_exit=0
case "$WHICH" in
  codex)        run_codex || overall_exit=1 ;;
  antigravity)  run_antigravity || overall_exit=1 ;;
  both)
    run_codex || overall_exit=1
    echo
    run_antigravity || overall_exit=1
    ;;
  *) echo "usage: $0 [codex|antigravity|both]"; exit 2 ;;
esac

cat <<EOF

------------------------------------------------------------
Reviews written to: $OUT/
Next:
  1. read the review output(s)
  2. record verdict + findings + responses in HANDOFF.md
     (reviewer, date, target commit ${COMMIT})
  3. fix -> scripts/preflight.py -> re-review if CHANGES-REQUIRED
  4. only then: publish GO -> first push
------------------------------------------------------------
EOF

exit "$overall_exit"
