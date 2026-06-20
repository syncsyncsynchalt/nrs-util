# ambilling — FACTS（co-located）

ALL.Net Plus Billing（alpbEx）クライアント。**単独 exe を持たず nrs.exe にリンクされる am* ライブラリ**。
横断定数は `../ARCH.md`、索引は repo ルート `FACTS.md`。confidence: [F]/[S]/[I]。

## 現状（stub）— 実装は `../patches.json`
| static_VA | 内容 |
|---|---|
| 0xA065C0 | `alpbExGetExecStatus` → 5(offline idle) 固定。Error 1000(amlib errCode 0x15) 回避。device-presence 連鎖は `../devices/FACTS.md` |

`FUN_007000c0`(alpbEx billing poll)が 0xA065C0 の戻り -2("Not initialized")を default 分岐 → `DAT_016f5af0=0x15` →
表示 1000。status 5 は poll/credit executor/debug dump の3 caller すべてで no-op(idle) → ALL.Net traffic も
accounting も errCode も発生しない。**network_role=serve**（将来 billing サーバ化で実応答へ）。
実コイン/クレジット計上が要るなら要見直し（credit transaction を start/close しなくなる）。

## 将来（実 billing）
`ib.naominet.jp:8443`(HTTPS/TLS1.1, keychip 署名 CA)。仕様 `../../docs/bsnk_ringedge.md §4`。
