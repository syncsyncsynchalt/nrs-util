# 現在地

## 到達状態: clean ATTRACT（エラーシーン無し）

`boot/launch.py --spawn` で amlib SYSTEM STARTUP SM（`FUN_0089a010`）が state10(DONE)まで完走し、
nrs.exe がアトラクト（全国ランキング demo）をエラーシーン無しで巡回描画。実写検証
`captures/verify-region-neutralize.png`。検証は必ず `tools/runtime/screenshot_window.py`(PrintWindow)で
実写確認する（errNo=0 等のログだけでクリーン判断しない）。

## satisfy チェーン（実写検証済み・正は MANIFEST/各 FACTS）

各エラーをどの boot モジュールが満たすか。アドレス・機構は `boot/MANIFEST.json` と `boot/<subsys>/FACTS.md`、
根本原因は `BUGS.md` が単一ソース（ここは索引）。

| ブロッカー | 解 | モジュール |
|---|---|---|
| Error 1000 billing (0x15) | alpbExGetExecStatus→5 | `boot/allnet/billing.js` |
| 5101 IC Card R/W (0x17) | presence プローブ healthy | `boot/devices/cardreader.js` |
| 951 USB I/O (0xf) | I/Oボード present + jvs_error=0 | `boot/devices/usbio.js` |
| 5501 Touch Panel (0x16) | resp=1/err=0 | `boot/devices/touchpanel.js` |
| 8005/8001 Network (0x14) | network_type=LAN / allnet `return 2` | `boot/amnet/network_type.js` / `boot/allnet/connection.js` |
| 8006 amNet DHCP | pcpa 応答を `&` 区切りに統一（真因＝`\r\n` 区切り） | `boot/keychip/server/pcpa_server.py` |
| 0903 region (0x4) | region setter の errCode ストアを NOP（TP 方式＝検査無力化） | `boot/keychip/region.js` |
| EXTEND IMAGE (state5) | FUN_0072b3a0→done | `boot/startup/extend_image.js` |
| ALL.Net (state6) / P-ras (state7) | resolve / FreePlay | `boot/startup/pras.js`, `boot/allnet/connection.js` |
| JVS / dongle / platform | patchCode 群 | `boot/amjvs/*`, `boot/amdongle/*`, `boot/amplatform/*` |

## 残存 Frida 依存（= 完全スタンドアロン化の残課題）

`MANIFEST.json` の `persistence=runtime` 群が detach で revert する。satisfy 本体は patchCode/data-write
（持続）+ pcpa_server（served）で済んでおり、detach 後も ATTRACT は維持される。残るのは下記の回復/前進系:

| 依存 | 場所 | 型 |
|---|---|---|
| pcpaOpenClient エラー回復 | `boot/keychip/client.js` | Interceptor.attach |
| HLSM state=7→8 force / 診断 / bootDone | `boot/amgfetcher/getstatus.js` | Interceptor.attach |
| 0x98ADC0 GETSTATUS_FIX | `boot/amgfetcher/getstatus.js` | Interceptor.attach |
| recv getStatusRecvDone | `boot/lib/base.js` | Interceptor.attach |
| JVS watchdog | `boot/amjvs/watchdog.js`, `input.js` | Frida timer |

北極星と P0–P3 ロードマップ（runtime 依存の根絶 / JVS を TP 方式 named pipe `\\.\pipe\teknoparrot_jvs` +
SHM `TeknoParrot_JvsState` に置換 / pcpa を micetools 級へ / network 層を追加）は `docs/architecture.md`。

## 既知の OPEN 課題

device-scene latch（display struct `DAT_016f5a80` への errCode 固着）は 0903 を含め順次 setter NOP 化で
解消中。現状 clean attract 到達済みだが、watchdog 依存を完全に外す残作業あり。詳細・errCode setter 全マップは
`BUGS.md`。**最初に立った errCode が latch するレース**なので、満たし方は決定的 patchCode/served に寄せる。

---

## 起動

```powershell
$py="$env:LOCALAPPDATA\Programs\Python\Python313\python.exe"
& $py boot\launch.py --spawn --duration 90
# MANIFEST.json の load_order でモジュールを連結ロード（数値順固定。順序変更厳禁＝BUGS.md 参照）
# pcpa_server (boot\keychip\server\pcpa_server.py) は launch.py が自動起動（既存なら skip）
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
| keychip/PCP/KCF（正は `C:\src\micetools\` 直読） | `docs/micetools.md` |
