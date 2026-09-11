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
CODEX_SANDBOX="${CODEX_SANDBOX:-danger-full-access}"

run_codex() {
  local f="$OUT/codex-${STAMP}-${COMMIT}.md"
  echo ">> Codex code audit (reasoning_effort=high, not fast; sandbox=${CODEX_SANDBOX}) -> $f"
  {
    echo "# Codex code audit"
    echo "commit: ${COMMIT}   date: $(date -Iseconds)"
    echo "config: model_reasoning_effort=high (explicit; fast mode off); sandbox=${CODEX_SANDBOX}"
    echo
  } > "$f"
  timeout "$TIMEOUT" codex exec "${CODEX_MODEL_OPTS[@]}" \
    -C "$REPO" -s "$CODEX_SANDBOX" --skip-git-repo-check \
    "$CODEX_PROMPT" 2>&1 | tee -a "$f" || {
      echo "!! codex exec failed or timed out (exit $?)" | tee -a "$f"; }
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
  timeout "$TIMEOUT" agy -p "$ANTIGRAVITY_PROMPT" \
    --add-dir "$REPO" --effort high --mode plan --dangerously-skip-permissions \
    --print-timeout "${TIMEOUT}s" --output-format text 2>&1 | tee -a "$f" || {
      echo "!! agy failed or timed out (exit $?)" | tee -a "$f"; }
  echo "   done: $f"
}

case "$WHICH" in
  codex)        run_codex ;;
  antigravity)  run_antigravity ;;
  both)         run_codex; echo; run_antigravity ;;
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
