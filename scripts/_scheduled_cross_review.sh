#!/usr/bin/env bash
# One-shot wrapper for the scheduled cross-AI review (see run_cross_review.sh).
# Invoked by a transient systemd --user timer. Runs both reviewers, then leaves a
# marker in HANDOFF.md so the result is picked up in the next session.
set -uo pipefail

export PATH="$HOME/.npm-global/bin:$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
REPO="$HOME/workspace/security-knowledge-os"
cd "$REPO" || exit 1

STAMP="$(date -Iseconds)"
COMMIT="$(git rev-parse --short HEAD)"
LOG="$REPO/reviews/_scheduled-$(date +%Y%m%d-%H%M%S).log"

# Codex#8 (round 15, 2026-09-14), reproduced exactly as reported: this
# wrapper always wrote a "実行済み" success marker into HANDOFF.md and
# always exited 0, regardless of whether run_cross_review.sh actually
# produced a verdict or preflight passed - both exit codes were
# discarded (the review's status was never checked at all; preflight's
# was explicitly thrown away with `|| true`). `{ ...; } | tee "$LOG"`
# also runs the whole block in a subshell (it's the left side of a
# pipe), so a status captured INSIDE it cannot simply be read as a
# normal variable afterward - written to small status files instead,
# which survive the subshell boundary.
STATUS_DIR="$(mktemp -d)"
{
  echo "scheduled cross-review start: $STAMP  commit $COMMIT"
  bash scripts/run_cross_review.sh both
  echo "$?" > "$STATUS_DIR/review"
  echo "scheduled cross-review end: $(date -Iseconds)"
  echo "--- preflight after review ---"
  ./.venv/bin/python scripts/preflight.py > "$STATUS_DIR/preflight.out" 2>&1
  echo "$?" > "$STATUS_DIR/preflight"
  grep -E '^\[|preflight:' "$STATUS_DIR/preflight.out" || true
} 2>&1 | tee "$LOG"

review_status="$(cat "$STATUS_DIR/review" 2>/dev/null || echo 1)"
preflight_status="$(cat "$STATUS_DIR/preflight" 2>/dev/null || echo 1)"
rm -rf "$STATUS_DIR"

# Codex#5 / Antigravity SKOS-ADV-20 (round 17, 2026-09-14), reproduced
# exactly as reported: run_cross_review.sh's exit code 2 (every reviewer
# completed, but at least one said CHANGES-REQUIRED - see its own exit-
# code convention comment) is NOT a failure of the review PROCESS the
# same way exit 1 (a reviewer crashed / produced no verdict at all) is -
# conflating them made a real, completed CHANGES-REQUIRED review look
# exactly like "something went wrong and we don't know the outcome" in
# both the status label and the warning line below. Distinguish all
# three states explicitly.
if [ "$review_status" -eq 0 ] && [ "$preflight_status" -eq 0 ]; then
  STATUS_LABEL="成功（PASS/PASS-with-nits）"
elif [ "$review_status" -eq 2 ] && [ "$preflight_status" -eq 0 ]; then
  STATUS_LABEL="完走・CHANGES-REQUIRED（公開はブロック中、指摘対応が必要）"
else
  STATUS_LABEL="要確認（review_exit=$review_status, preflight_exit=$preflight_status）"
fi

# marker for the next session
MARK="$HOME/HANDOFF.md"
TMP="$(mktemp)"
{
  echo "# Handoff: $(date +%Y-%m-%d) — Security Knowledge OS 相互レビュー自動実行 — ${STATUS_LABEL}"
  echo
  echo "- \`scripts/run_cross_review.sh both\` を $STAMP に自動実行（対象 commit \`$COMMIT\`、review_exit=$review_status, preflight_exit=$preflight_status）。"
  echo "- 出力: \`~/workspace/security-knowledge-os/reviews/\` の codex-*.md / antigravity-*.md / _scheduled-*.log"
  if [ "$review_status" -eq 1 ] || [ "$preflight_status" -ne 0 ]; then
    echo "- **⚠️ review または preflight が失敗/verdict無しで終了した可能性がある。ログを確認すること。**"
  elif [ "$review_status" -eq 2 ]; then
    echo "- レビューは完走したが CHANGES-REQUIRED。指摘対応サイクルへ。"
  fi
  echo "- **次にやること**: 出力を読み、verdict + 指摘 + 対応方針を HANDOFF.md 本体に要約 → 指摘対応 → preflight → 公開 GO → 初 push。"
  echo "- Codex が再度 usage limit だった場合はログにその旨が出ているので、時間をおいて \`scripts/run_cross_review.sh codex\` を再実行。"
  echo
  echo "---"
  echo
  cat "$MARK"
} > "$TMP" && mv "$TMP" "$MARK"

if [ "$review_status" -eq 1 ] || [ "$preflight_status" -ne 0 ]; then
  echo "done WITH FAILURES (review_exit=$review_status, preflight_exit=$preflight_status). marker added to $MARK"
  exit 1
fi
if [ "$review_status" -eq 2 ]; then
  echo "done: review completed, CHANGES-REQUIRED (publication blocked). marker added to $MARK"
  exit 2
fi
echo "done. marker added to $MARK"
