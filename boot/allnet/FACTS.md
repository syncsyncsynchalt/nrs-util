# ALL.Net — FACTS（co-located）

横断定数は `../ARCH.md`、索引は repo ルート `FACTS.md`。confidence: [F]/[S]/[I]。

## 現状（stub）
| 何 | RVA | 内容 |
|---|---|---|
| connection.js | 0x32DCE0 | `FUN_0072dce0`(ALL.Net server status) → 0(resolved) 固定。SYSTEM STARTUP state6（詳細 `../startup/FACTS.md`） |
| billing.js | 0x6065C0 | `alpbExGetExecStatus` → 5(offline idle)。Error 1000（device-presence 連鎖は `../devices/FACTS.md`） |

両者とも persistence=persistent、**network_role=serve**（将来ネットワーク化で実サーバ応答へ移す層）。

## 将来ネットワーク対応
ALL.Net 4 サービス（Authentication PowerOn / DownloadOrder / Billing / AiMeDB）と BBS タイトルサーバの
設計は `README.md`。仕様は `../../docs/bsnk_ringedge.md §4`。実装時はこのディレクトリに追加するだけ
（構造改変不要）。筐体 identity は `../../cabinet/default.toml` の `[identity]`。
