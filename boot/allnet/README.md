# allnet/ — ネットワーク層（予約地・現状は stub）

現状は ALL.Net 接続段を **satisfy（resolved 固定）/ billing offline** で通すだけ（`connection.js` / `billing.js`）。
将来の**ネットワーク完全対応はこのディレクトリへの追加だけで済む**ように予約してある。

## 将来の実装計画（仕様 = `../../docs/bsnk_ringedge.md §4`）

| 機能 | エンドポイント | メモ |
|---|---|---|
| Authentication PowerOn | `naominet.jp /sys/servlet/PowerOn`（DFI） | 応答の `host`/`uri` がタイトルサーバを指す。redirect は TP 同様ホスト名書換（`../ARCH.md` TeknoParrot Patches §） |
| Download Order | `/sys/servlet/DownloadOrder` | `stat≠1` で配信抑止（スタンドアロン） |
| Billing | `ib.naominet.jp:8443`(HTTPS/TLS1.1) | keychip 署名 CA。TLS1.1 は reverse proxy 終端 |
| AiMeDB | `aime.naominet.jp` | カード/プレイヤー identity |
| Title/Battle server | PowerOn 応答の host | **BBS 固有・未文書化＝ブラックボックス RE**（最難関） |

## 設計予約（追加だけで済む理由）
- **identity**: `../../cabinet/default.toml` `[identity]` に serial/keyid/mainid を確保済。マルチプレイは
  筐体ごとに distinct にするだけ。
- **endpoint**: 同 `[network] host` を SP=loopback / MP=共有ホストで切替。
- **方針**: `network_role=serve` のモジュール（`amnet/*`, `keychip/client`, `allnet/*`, `startup/pras`）は
  「patch で誤魔化す」より「実サーバが本当に resolve」へ移す（serve > suppress）。
