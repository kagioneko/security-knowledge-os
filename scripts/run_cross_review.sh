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
FULL_COMMIT="$(git rev-parse HEAD)"

# Codex#3 (round 26, 2026-09-20), reproduced exactly as reported: the
# review names HEAD in its prompt, output filename and verdict line but reads
# the WORKING DIRECTORY - an uncommitted edit to a tracked file was reviewed
# under the unchanged commit's name, and a reviewer running with
# `danger-full-access` (or a concurrent checkout) could change the tree
# mid-review with the verdict still labelled for the original commit. So:
#   1. refuse to start unless tracked files match HEAD exactly, and
#   2. after the reviewer finishes, require HEAD and the tracked files to be
#      unchanged before a verdict is accepted (see `_assert_tree_unchanged`).
# Untracked files are deliberately ignored (reviews/ output itself is one).
_tree_is_clean() {
  [ -z "$(git status --porcelain --untracked-files=no)" ]
}

if ! _tree_is_clean; then
  echo "!! refusing to review: tracked files differ from HEAD ($COMMIT)." >&2
  echo "   commit (or stash) first, so the reviewed tree IS the commit the verdict names." >&2
  git status --short --untracked-files=no >&2
  exit 1
fi
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$REPO/reviews"
mkdir -p "$OUT"
TIMEOUT="${REVIEW_TIMEOUT:-1800}"

WHICH="${1:-both}"

# Review scope (2026-09-20, agreed with the owner after 28 rounds): the
# reviewers kept reporting attacks that need write access to the state
# directory / index / rule trees - locations docs/threat-model.md ("Deployment
# assumptions") puts INSIDE the trust boundary, where the writer can replace a
# rule directly and a recomputable hash is no defence. Those are listed once as
# out of scope instead of being reported as findings; crashes or leaks in the
# handling of a corrupt or tampered file stay in scope (corruption is also
# innocent). No double quotes, backticks or dollar signs here: it is expanded
# inside both double-quoted prompts below.
SCOPE_CLAUSE='SCOPE (docs/threat-model.md, section Deployment assumptions): the state directory, the index database and the knowledge, rules and safe_tests trees are INSIDE the trust boundary - only the service OS user (or root) can write them. Report a finding only if it is exploitable WITHOUT write access to those locations, i.e. through untrusted input (API or CLI inputs, knowledge documents submitted for validation, LLM output, assessed-system content) or by another local account that lacks write access to them. Attacks that require such write access (tampering with the index or database, swapping directories inside the trees, recomputing digests, races coordinated with a writer) are OUT OF SCOPE: do not report them as findings; list them once, briefly, under a heading Out of scope (inside trust boundary) so your coverage stays visible. A crash, fail-open behaviour or information leak in the code that handles a corrupt or tampered file is still IN scope, because corruption also happens innocently.'

CODEX_PROMPT="You are doing a PRE-PUBLICATION CODE AUDIT of this repository
(Security Knowledge OS, Apache-2.0, commit ${COMMIT}, not yet pushed).

READ FIRST, in this repo: REVIEW_PACKAGE.md, then REVIEW_CHECKLIST.md 'Part A -
Code audit', then PUBLICATION_MANIFEST.md, then docs/threat-model.md.

${SCOPE_CLAUSE}

Audit against Part A only: arbitrary code execution paths (rules must be data,
not code); SQL / SQLite (parameterisation, FTS5 syntax injection, read-only
enforcement); path traversal and unsafe file write/delete (reindex_atomic,
rglob, scripts); exception handling and fail-closed behaviour; type/model
soundness (extra='forbid', the Finding A8 validator, AnswerPatch never taking a
raw secret); API boundary (in-memory store, /answers cost, /history cycles,
unauthenticated reindex); test-coverage gaps; dependency / supply chain.

Do NOT modify any file. For each finding give: severity, file:line, repro,
suggested fix. End your ENTIRE response with exactly one line, in exactly
this format (this exact line is machine-checked to gate publication):
Overall verdict for commit ${COMMIT}: PASS
(or PASS-with-nits, or CHANGES-REQUIRED, in place of PASS - choose exactly
one). Do not print this exact line anywhere else in your response."

ANTIGRAVITY_PROMPT="You are doing a PRE-PUBLICATION ADVERSARIAL DESIGN AUDIT of
this repository (Security Knowledge OS, Apache-2.0, commit ${COMMIT}, not yet
pushed). Goal: find how to fool the system itself.

READ FIRST, in this repo: REVIEW_PACKAGE.md (Trust Boundary, Threat Model, A8
boundary, Human Gate, Fail-closed, Classification), then REVIEW_CHECKLIST.md
'Part B - Adversarial design audit', then docs/threat-model.md.

${SCOPE_CLAUSE}

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
severity, mitigation. End your ENTIRE response with exactly one line, in
exactly this format (this exact line is machine-checked to gate publication):
Overall verdict for commit ${COMMIT}: PASS
(or PASS-with-nits, or CHANGES-REQUIRED, in place of PASS - choose exactly
one). Do not print this exact line anywhere else in your response."

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
# hand.
#
# Codex#4 / Antigravity SKOS-ADV-17 (round 16, 2026-09-14), reproduced
# exactly as reported by both reviewers independently: the round-15 fix
# above matched `PASS` or `CHANGES-REQUIRED` UNANCHORED, anywhere in the
# log - a reviewer that crashed mid-run after merely printing
# `preflight: PASS` (or quoting PUBLICATION_MANIFEST.md, which itself
# contains those words throughout its own round-history narrative) would
# still satisfy this check and clear the publication gate. Both prompts
# above now require the reviewer's FINAL line to be an exact, anchored
# "Overall verdict for commit <hash>: <verdict>" declaration; this checks
# for exactly that line (anywhere in the file - a reviewer's transcript
# can be long, but the declaration format itself is what makes it
# unambiguous, not its position) rather than the bare word anywhere.
# Codex#5 / Antigravity SKOS-ADV-20 (round 17, 2026-09-14), reproduced
# exactly as reported by both reviewers independently: the round-16 fix
# above only ever asked "did a verdict line exist" - it never asked
# WHICH verdict. A reviewer ending with `CHANGES-REQUIRED` satisfies
# `_has_verdict()` exactly as well as `PASS` does, so `run_codex()`/
# `run_antigravity()` returned SUCCESS (exit 0) for a review that
# explicitly said publication must be blocked - and `_scheduled_cross_
# review.sh` then labeled that run "成功" (success) in HANDOFF.md.
# "the reviewer ran to completion" and "the reviewer said PASS" are two
# different questions; conflating them is exactly the ambiguity a
# publication gate cannot afford. `_verdict_of()` now extracts the exact
# word instead of just checking existence, so callers can tell all three
# outcomes apart: no verdict at all (still a hard failure, unchanged),
# PASS/PASS-with-nits (success), and CHANGES-REQUIRED (the reviewer DID
# complete and DID answer, but the answer was "not yet publishable" -
# distinct from a failure, but not success either).
#
# Codex#2 (round 26, 2026-09-20), reproduced exactly as reported: this used
# to accept the LAST matching verdict line ANYWHERE in the transcript, so
# `Overall verdict ...: PASS` followed by "Audit incomplete because the
# process terminated ..." (or a truncated run that happened to print a
# verdict line earlier, e.g. while quoting the prompt) passed as a
# successful review. The prompts require the verdict to be the very last
# line, so that is what is enforced: only the final NON-EMPTY line of the
# transcript is examined, and anything after a verdict makes it "no verdict".
_verdict_of() {
  grep -v '^[[:space:]]*$' "$1" | tail -1 \
    | grep -oE "^Overall verdict for commit ${COMMIT}: (PASS-with-nits|PASS|CHANGES-REQUIRED)[[:space:]]*\$" \
    | tail -1 \
    | sed -E 's/^Overall verdict for commit [^:]*: *//' \
    | tr -d '[:space:]'
}

# Called after a reviewer has finished, BEFORE its verdict is read.
_assert_tree_unchanged() {
  local f="$1"
  if [ "$(git rev-parse HEAD)" != "$FULL_COMMIT" ] || ! _tree_is_clean; then
    echo "!! the repository changed during the review (HEAD or tracked files); the verdict does not apply to commit ${COMMIT}" | tee -a "$f"
    return 1
  fi
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
  _assert_tree_unchanged "$f" || return 1
  local verdict
  verdict="$(_verdict_of "$f")"
  if [ -z "$verdict" ]; then
    echo "!! codex exec exited 0 but no PASS/PASS-with-nits/CHANGES-REQUIRED verdict was found in $f" | tee -a "$f"
    return 1
  fi
  if [ "$verdict" = "CHANGES-REQUIRED" ]; then
    echo "   review completed: CHANGES-REQUIRED (publication blocked) -> $f"
    return 2
  fi
  echo "   done: $f ($verdict)"
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
  _assert_tree_unchanged "$f" || return 1
  local verdict
  verdict="$(_verdict_of "$f")"
  if [ -z "$verdict" ]; then
    echo "!! agy exited 0 but no PASS/PASS-with-nits/CHANGES-REQUIRED verdict was found in $f" | tee -a "$f"
    return 1
  fi
  if [ "$verdict" = "CHANGES-REQUIRED" ]; then
    echo "   review completed: CHANGES-REQUIRED (publication blocked) -> $f"
    return 2
  fi
  echo "   done: $f ($verdict)"
}

# Exit code convention (Codex#5 / Antigravity SKOS-ADV-20, round 17):
#   0 = every requested reviewer completed AND said PASS/PASS-with-nits
#   1 = at least one reviewer failed, timed out, or produced no verdict
#       at all (worse than a real verdict - we don't even know the
#       outcome); takes priority over 2 below if both occur
#   2 = every requested reviewer completed, but at least one said
#       CHANGES-REQUIRED - not a failure of the REVIEW PROCESS, but
#       publication is explicitly blocked
overall_exit=0
_note_result() {
  local status="$1"
  if [ "$status" -eq 1 ]; then
    overall_exit=1
  elif [ "$status" -eq 2 ] && [ "$overall_exit" -eq 0 ]; then
    overall_exit=2
  fi
}

case "$WHICH" in
  codex)
    if run_codex; then codex_result=0; else codex_result=$?; fi
    _note_result "$codex_result"
    ;;
  antigravity)
    if run_antigravity; then agy_result=0; else agy_result=$?; fi
    _note_result "$agy_result"
    ;;
  both)
    if run_codex; then codex_result=0; else codex_result=$?; fi
    _note_result "$codex_result"
    echo
    if run_antigravity; then agy_result=0; else agy_result=$?; fi
    _note_result "$agy_result"
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
