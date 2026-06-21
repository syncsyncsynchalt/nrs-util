# 現在地

## 到達状態: clean ATTRACT（エラーシーン無し）

`boot/launch.py --spawn` で amlib SYSTEM STARTUP SM（`FUN_0089a010`）が state10(DONE)まで完走し、
nrs.exe がアトラクト（全国ランキング demo）をエラーシーン無しで巡回描画。実写検証
`captures/verify-region-neutralize.png`。検証は必ず `tools/runtime/screenshot_window.py`(PrintWindow)で
実写確認する（errNo=0 等のログだけでクリーン判断しない）。

## boot 構成

`boot/` の dir は RingEdge 実行ファイル名に一致（`mxkeychip`/`mxsegaboot`/`mxnetwork`/`mxgfetcher`/
`mxstorage` ＋ `am*` ライブラリ ＋ `ambilling`）。ソースは token 最小・AI 編集容易な形に統一:
- **単純固定バイト patch** = 所属サブシステムのモジュールに `patch()` 1行（`lib/base.js` の helper）。中央テーブルなし。一覧監査 `tools/static/patch_audit.py`。
- **複雑系** = `.js` モジュール + helper（`patch()`/`hook()`/`watch()`）。生 `Memory.patchCode`/`Interceptor.attach`/`setInterval` を直書きしない。
- **log-only 診断** = `<subsys>/diag.js`（起動修正時に読まなくてよい）。
- 規約 `boot/CONVENTIONS.md §0`、機械検証 `tools/hygiene/check_doc_sync.py`（va[]/idiom を検証）。
- **挙動不変の機械検証** = `tools/hygiene/patch_invariance.py`（spawn-suspended で全 patch/hook の効果集合＋衝突番地順序を HEAD と diff）。`--compare HEAD` が空一致であることを確認する。

## satisfy チェーン（どのエラーをどう満たすか）

**error→fix の正本は各サブシステムモジュールの `patch()` note（errNo/state）＋ 各モジュールヘッダの `// va:`。一覧は `tools/static/patch_audit.py`。**
起動シーケンス全体は `boot/mxsegaboot/FACTS.md`（SYSTEM STARTUP `FUN_0089a010`）。
patch 化されない fix のみ: 8006 amNet DHCP=`mxkeychip/server/pcpa_server.py`（`&` 区切り） /
0903 region=`mxkeychip/region.js`（setter NOP） / JVS=`amjvs/*` / dongle=`amdongle/*`。

## 残存 Frida 依存（= 完全スタンドアロン化の残課題）

`MANIFEST.json` の `persistence=runtime` 群が detach で revert する。satisfy 本体は patchCode/data-write
（持続）+ pcpa_server（served）で済んでおり、detach 後も ATTRACT は維持される。残るのは下記の回復/前進系:

| 依存 | 場所 | 型 |
|---|---|---|
| pcpaOpenClient エラー回復 | `boot/mxkeychip/client.js` | Interceptor.attach |
| HLSM state=7→8 force / 診断 / bootDone | `boot/mxgfetcher/getstatus.js` | Interceptor.attach |
| 0x98ADC0 GETSTATUS_FIX | `boot/mxgfetcher/getstatus.js` | Interceptor.attach |
| recv getStatusRecvDone | `boot/lib/base.js` | Interceptor.attach |

北極星と P0–P3 ロードマップ（runtime 依存の根絶 / JVS 入力を TP 方式 named pipe `\\.\pipe\teknoparrot_jvs` +
SHM `TeknoParrot_JvsState` で実装 / pcpa を micetools 級へ / network 層を追加）は `docs/architecture.md`。

## 既知の OPEN 課題

device-scene latch（display struct `DAT_016f5a80` への errCode 固着）は **最初に立った errCode が latch する
レース**。満たし方は決定的 patchCode/served に寄せ、setter NOP 化で watchdog 依存を外す。詳細・errCode setter
全マップは `BUGS.md`。

---

## 起動

```powershell
$py="$env:LOCALAPPDATA\Programs\Python\Python313\python.exe"
& $py boot\launch.py --spawn --duration 90
# MANIFEST.json の load_order でモジュールを連結ロード（数値順固定。順序変更厳禁＝BUGS.md 参照）
# pcpa_server (boot\mxkeychip\server\pcpa_server.py) は launch.py が自動起動（既存なら skip）
# attract 到達後 detach → patchCode/pcpa_server で継続
```

## ログ確認

```powershell
& $py tools\logs\read_log.py -f "(REGION_CHK|ERRCODE|HLSM|Error 09)"
& $py tools\logs\session_summary.py
```

## 参照

| 知りたいこと | 参照先 |
|---|---|
| 横断定数 / ポート / ワイヤ形式 / TP パッチ | `boot/ARCH.md` |
| サブシステム別アドレス / 構造体 | `boot/<subsys>/FACTS.md`（索引 `FACTS.md`） |
| boot 構成・ロード順・persistence | `boot/MANIFEST.json`（単一ソース） |
| バグ・根本原因・アンチパターン・失敗の記録 | `BUGS.md` |
| 北極星・ロードマップ | `docs/architecture.md` |
| 逆コンパイル C / xref | Ghidra MCP `mcp__ghidra__decompile_function_by_address` |
| TeknoParrot 設定・JVS（正は `C:\src\TPBootstrapper\`） | `docs/teknoparrot.md` |
| mxkeychip/PCP/KCF（正は `C:\src\micetools\` 直読） | `docs/micetools.md` |
