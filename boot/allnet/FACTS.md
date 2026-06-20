# ALL.Net — FACTS（co-located）

横断定数は `../ARCH.md`、索引は repo ルート `FACTS.md`。confidence: [F]/[S]/[I]。

## 現状（stub）
実装は `patches.json`（純バイト patch 表。旧 `connection.js`/`billing.js` を移送）。
| static_VA | 内容 |
|---|---|
| 0x72DCE0 | `FUN_0072dce0`(ALL.Net server status, amlib_device_status_getter) → 2(ready) 固定。state4 network + state6 allnet 両立（詳細 `../startup/FACTS.md`） |
| 0xA065C0 | `alpbExGetExecStatus` → 5(offline idle)。Error 1000（device-presence 連鎖は `../devices/FACTS.md`） |

両 patch は **network_role=serve**（将来ネットワーク化で実サーバ応答へ移す層）。Phase 5 で 0xA065C0 は
`ambilling`、0x72DCE0 は `mxnetwork` へ subsys 再帰属。

## 将来ネットワーク対応
ALL.Net 4 サービス（Authentication PowerOn / DownloadOrder / Billing / AiMeDB）と BBS タイトルサーバの
設計は `README.md`。仕様は `../../docs/bsnk_ringedge.md §4`。実装時はこのディレクトリに追加するだけ
（構造改変不要）。筐体 identity は `../../cabinet/default.toml` の `[identity]`。
