---
id: KU-0013
title: "モデルは侵害されている前提で権限とリーチャビリティを絞る"
category: methodology
source_type: standard
source_ref: "https://atlas.mitre.org/ (MITRE ATLAS) ; https://genai.owasp.org/llmrisk/llm06-excessive-agency/"
classification: public
status: reviewed
risk_ids: []
version: "1.0"
last_reviewed: "2026-09-10"
requires_ip_review: false
provenance:
  source_title: "MITRE ATLAS; OWASP Top 10 for LLM Applications 2025 - LLM06"
  source_url: "https://atlas.mitre.org/"
  source_version: "2026"
  source_license: "MITRE ATLAS Terms of Use (free use with attribution); CC-BY-SA-4.0 (OWASP GenAI Security Project)"
  derivation: summary
  last_verified: "2026-09-10"
  usage_note: "Original Japanese-language summary of assume-compromise / reachability analysis."
---

## Summary
「AIを騙されないようにする」だけでは足りない。プロンプトインジェクションは完全には防げないため、
「モデルが騙された後でも事故にならない」設計を前提に評価する。モデルの侵害＝システムの侵害では
ない。到達範囲と権限が正しく絞られていれば、モデルが負けてもシステムは持ちこたえる。

## Conditions
- 未信頼の入力（ユーザー入力・取得した文書・Web・PDF）がモデルに到達し、かつ
- モデルがツール・外部送信・永続メモリ・認証情報のいずれかに到達できる。

## Risk
単発の応答は安全に見えても、到達範囲（reachability）と実行権限（authority）が広いと、
1回のインジェクションが実害（データ持ち出し・破壊操作・永続汚染）に変わる。

## Evidence
- 未信頼入力の経路
- 到達可能なコンポーネント（tool / memory / outbound / credential）
- 各コンポーネントでの実行権限
- Human Approval の境界

## Failure Mode
取得した文書に埋め込まれた指示にモデルが従い、送信ツールを承認なしで呼び出す。

## Detection Clues
- 未信頼コンテンツが指示と同じ文脈に混在し、隔離マーカーがない。
- 高影響ツール（write / delete / send / shell）に承認ゲートがない。
- 認証情報の生値がモデルまたはツールから読める。

## Mitigations
- 最小権限。読み取りで足りるなら書き込み権限を与えない。
- 高影響操作には Human Approval ゲートを必須にする。
- 未信頼コンテンツを指示から分離する。
- 認証情報はブローカ経由の短命ハンドルにする（KU-0009）。
- 「一番小さく効く切り所」を見つけ、そこで断ち、切れたことを安全なプローブで再検証する。

## Safe Test
Sandbox で、取得文書に `*.invalid` 宛の送信指示を埋め込んだカナリア文書を読み込ませ、
モデルが拒否または Human Approval へ回すことを確認する。

## Limitations
権限を絞っても、モデルが「持っている権限」を騙されて使うことは止められない。多層で守る。

## Related Knowledge
- KU-0002
- KU-0004
- KU-0007
- KU-0009
