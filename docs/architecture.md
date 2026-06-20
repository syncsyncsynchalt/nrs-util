# nrs-util アーキテクチャ方針（北極星とロードマップ）

承認済みの設計方針（2026-06-12）。「どうあるべきか」の単一ソース。現状・実装詳細は `../STATUS.md`/`../boot/`。

## 北極星（最終形）

**Frida 無しで動く、サービスをエミュレートする小さなネイティブ起動層。**
- 小さな**ネイティブ・ローダ**（TeknoParrot の BudgieLoader 相当の自前版）が nrs.exe を spawn し、
  **byte パッチを適用**し、**JVS pipe と keychip/PCPA サーバを常駐ホスト**する。
- **Frida は解析の足場に降格**（Ghidra と並ぶデバッグ専用ツール）。出荷物に Frida を含めない。
- 構成は現行の `boot/<subsys>/` + `boot/MANIFEST.json` + `cabinet/*.toml` をそのまま土台にする。

## 指導原理

1. **patch < serve**: 外部から正しく応答(serve)できるものはゲームを patch しない。patch は
   「外から渡しようがない純内部述語」に限る。これは micetools 思想であり、脆い patch を減らすと
   ロード順依存も版差脆弱性も自然に減る。
2. **persistent > runtime**: satisfy は決定的な `patchCode`/served 応答で行う。実行時 Interceptor/
   watchdog は**ゲームのチェックと毎 tick レースする**ため不安定（下記 [race 知見]）。
3. **構成の単一ソースは MANIFEST**。ロード順は元の数値順を厳守（[load-order 知見]）。

### [load-order 知見] ブートはロード順に敏感
`boot/MANIFEST.json` の `load_order` をサブシステム順に並べ替えたら keychip 初期化前で停止（白画面）した
（2026-06-12, `BUGS.md` 該当エントリ）。原因は in-process patch がロード順・同一番地競合に依存するため。
→ load_order は元の数値順(00..32)に固定。根本対策は原理1（serve 化で patch を減らす）。

### [race 知見] device-presence エラーは runtime satisfy のレース
アトラクト未到達時に Error 1000/0903/8006 が**実行ごとに異なる**のは、Interceptor/watchdog ベースの
satisfy がゲームのチェックとレースし、勝った側のエラーが出るため（固定の壊れた状態なら毎回同じエラーになる）。
→ satisfy を決定的 `patchCode`/served に寄せればレースが消える（原理1・2）。

## ロードマップ（優先順）

- **P0 — 安定アトラクトの回復**（足場）。再ブートループ/device-satisfy レースを安定化。クリーン環境で
  `boot/launch.py --spawn` が確実にアトラクト到達することを実写確認できる状態にする。
- **P1 — 実行時 Frida 依存の根絶**（差分①②）。MANIFEST の `persistence=runtime` 群を撤廃:
  - **JVS を TeknoParrot 方式の named pipe `\\.\pipe\teknoparrot_jvs` + 共有メモリ `TeknoParrot_JvsState`**
    に置換（`amjvs/watchdog.js` の正しい代替。SHM は `pcpa_server` が既に生成）。
  - 残り runtime フックはネイティブ・ローダ常駐スレッド or 正しいサーバ応答で代替。
  - → ここで「Frida 無し起動」達成、patchCode 群はローダが当てるだけになる。
- **P2 — keychip/PCPA サーバを micetools 級に**（差分④⑤）。`pcpa_server.py` を keyword 別
  `callbacks/<group>.py` に分解。暗号は当面 `code=54` bypass で十分、network/billing を本格化するなら
  KCF/AES を実装（micetools が正準）。
- **P3 — ネットワーク層は「追加」で**（差分⑥）。`boot/mxnetwork/` の予約枠に PowerOn/DownloadOrder/
  Billing/AiMeDB/タイトルサーバを足す。SP=loopback / MP=共有ホストの切替は `cabinet` の
  `network_role=serve` 設計で種を撒いてある。今やる必要はないが seam は維持。

## 維持するもの（既に正しく収束済み）
- `boot/<subsys>/` 実機準拠構成（micetools の地図）。
- `MANIFEST.json` 単一ソース + `check_doc_sync` + ロード順=数値順固定。
- `cabinet/*.toml` プロファイル（TP + micetools 由来）。
- 「TeknoParrot と micetools の両方を正として参照、推測禁止」。

## 一言で
**「最小手数で patch して起動」から「サービスを正しく serve してゲームを普通に起動させ、Frida 無しで
完結する小さなローダ」へ。** patch は不可避な内部述語だけ、JVS は pipe、keychip はサーバ、network は追加で。
これでロード順の脆さ・device-satisfy レース・版差脆弱性が消え、TP の堅牢さと micetools の正準性に近づく。
