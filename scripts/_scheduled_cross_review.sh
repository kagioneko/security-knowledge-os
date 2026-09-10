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

{
  echo "scheduled cross-review start: $STAMP  commit $COMMIT"
  bash scripts/run_cross_review.sh both
  echo "scheduled cross-review end: $(date -Iseconds)"
  echo "--- preflight after review ---"
  ./.venv/bin/python scripts/preflight.py 2>&1 | grep -E '^\[|preflight:' || true
} 2>&1 | tee "$LOG"

# marker for the next session
MARK="$HOME/HANDOFF.md"
TMP="$(mktemp)"
{
  echo "# Handoff: $(date +%Y-%m-%d) — Security Knowledge OS 相互レビュー自動実行済み（要サマリ）"
  echo
  echo "- \`scripts/run_cross_review.sh both\` を $STAMP に自動実行（対象 commit \`$COMMIT\`）。"
  echo "- 出力: \`~/workspace/security-knowledge-os/reviews/\` の codex-*.md / antigravity-*.md / _scheduled-*.log"
  echo "- **次にやること**: 出力を読み、verdict + 指摘 + 対応方針を HANDOFF.md 本体に要約 → 指摘対応 → preflight → 公開 GO → 初 push。"
  echo "- Codex が再度 usage limit だった場合はログにその旨が出ているので、時間をおいて \`scripts/run_cross_review.sh codex\` を再実行。"
  echo
  echo "---"
  echo
  cat "$MARK"
} > "$TMP" && mv "$TMP" "$MARK"

echo "done. marker added to $MARK"
