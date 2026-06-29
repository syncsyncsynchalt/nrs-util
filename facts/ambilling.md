# ambilling FACTS（co-located）

ALL.Net Plus Billing（alpbEx）クライアント。**単独 exe を持たず nrs.exe にリンクされる am* ライブラリ**。
索引 `_index.md` / 横断知見 `workflow.md`。confidence: [S]=静的 [L]=実走 [I]=推論。

## 現状（stub）。実装 `src/logic/patches.c`
| static_VA | 内容 |
|---|---|
| 0xA065C0 | `alpbExGetExecStatus` → 5(offline idle) 固定。Error 1000(amlib errCode 0x15) 回避。device-presence 連鎖は `devices.md` |

`FUN_007000c0`(alpbEx billing poll)が 0xA065C0 の戻り -2("Not initialized")を default 分岐 → `DAT_016f5af0=0x15` →
表示 1000。status 5 は poll/credit executor/debug dump の3 caller すべてで no-op(idle) → ALL.Net traffic も
accounting も errCode も発生しない。**network_role=serve**（将来 billing サーバ化で実応答へ）。
実コイン/クレジット計上が要るなら要見直し（credit transaction を start/close しなくなる）。

## 将来（実 billing）
`ib.naominet.jp:8443`(HTTPS/TLS1.1, keychip 署名 CA)。仕様は ALL.Net billing 層＝`ref.md` の RingEdge 純正イメージ / TeknoParrot を正として要再 RE。
