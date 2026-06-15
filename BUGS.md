# Bug Catalog — Live (OPEN / RISK / ANTI-PATTERN)

Format: ## [STATUS] SYMPTOM — status is OPEN|RISK|ANTI-PATTERN
Each entry: symptom → root cause → fix/workaround.
**解決済みバグ（FIXED）と修正経緯の参考 NOTE は `docs/bugs_archive.md` に分離**（本体を軽く保つため。
過去の root-cause/アドレス/アンチパターン記録が要るときはそちらを検索）。

---

## [大半解決] device-presence エラーシーン残留（0903/8006/1000…）— clean attract 到達（2026-06-13）

UPDATE 2026-06-13: 8006(amNet `&`修正)→8001(allnet return 2)→**0903(region setter NOP)** と latch を順に潰し、
**クリーン attract 到達**（`captures/verify-region-neutralize.png` = 全国ランキング demo 描画、エラーシーン無し）。
最後の 0903 を TeknoParrot 方式（チェック無力化）で恒久解消したのが決め手（詳細は `docs/bugs_archive.md` の
[FIXED] Error 0903 region setter check-neutralization）。残る理論リスクは
他コード（0xa board-table / 0x14 network）が watchdog clear より速く display struct へ snapshot する場合だが、
実機ではこの run で 0xa は latch→clear のみ・画面非固着。順次 setter NOP 化で watchdog 依存を外すのが残作業。

Symptom（解決前）: HLSM は stable attract(state0, 数千 tick, 再ブート無し)に到達するのに、画面に device エラー
シーン(Error 0903 Wrong Region / 8006 / 1000 等)が**1つ貼り付いて消えない**。satisfy を1つ直すと次のエラーへ
前進（8006→8001→0903 を実測）。
Root cause（判明分）: 起動初期に errCode 0xa(board-table)/0x4(region)/0x14(network) が **display struct
`DAT_016f5a80` のフィールド**へ latch → レンダラ `FUN_006f2730`(RVA 0x2f2730) が記述子(+0x00 errCode /
+0x10 errNo)を毎フレーム描画し続ける。watchdog は `DAT_016f5af0`(amlib master errCode)を毎 tick クリアするが
**display struct 側はクリアしない**ため、underlying チェックが後で PASS(REGION_CHK PASS 等)してもシーンが残る。
重要: これは**再編成の回帰ではない**。朝(10–11時台)の run も同一の latch(0xa/0x4/0x14)を持つ。可視 attract
到達(788KB, 07:54)は別状態。device-scene を確実にクリアする手当ては未解決（既存の課題）。
次の一手候補: `FUN_006f2730` を Ghidra で解析し描画記述子の出所(`DAT_016f5a80` 系)を特定 → attract 到達後に
errCode/errNo フィールドを 0 クリアする watchdog/patch を追加（または builder `FUN_00489130` を抑止）。

実機比較観測（2026-06-13, amNet `&` 修正の検証中）: **同一コミット相当でも latch する errNo は run ごとに
変わる**＝latch は「最初に立った errCode」のレース。実写2枚で確認:
- **force ON（コミット状態, `\r\n`）→ 画面 "Error 1000 Unknown Application Error"**（`captures/verify-baseline-forceON.png`）
- **force OFF + pcpa `&` 修正 → 画面 "Error 8001 Network address error (DHCP)"**（`captures/verify-amnet-fix.png`）
どちらも errCode 0x14 latch=1回・HLSM BOOT_DONE/ATTRACT 到達は同一。**8006 を正しく直して amNet が native
解決(ret=0)しても device-scene は消えない**＝この latch は amNet の成否と独立（underlying PASS でも display
struct が残る、という上記 root cause を再確認）。よって clean attract の最終ブロッカーは本 [大半解決] 課題。
8001(network) の underlying: `FUN_006fe040` が `DAT_016019a6`(ip_match) 真を要求。ip_match=`(mask&ip)==(ref&mask)`
（ref=`DAT_0160198a`）。nic IP は query_nic_status 応答の inline 解析で ctx+0x3c へ入る（`boot/amnet/FACTS.md`）。

### errCode setter 全マップ（Ghidra search_decompiled で確定）
各 setter は `if (DAT_016f5af0 == 0) { DAT_016f5af0 = X; }`＝**最初に立ったエラーが latch して固着**（以降は ==0 ガードで上書き不可）。`FUN_006c35c0` が =0 でクリア。実機ランで latch 観測=0xa→0x4→0x14。

| errCode | setter | デバイス/意味 | 既存対応 |
|---|---|---|---|
| 4 | FUN_00458fd0 / FUN_0045a7f0 | region | **✅ check-neutralization 化済 (2026-06-13)**: errCode 4 ストアを NOP10（0x59109/0x5A846）。keychip/region.js。詳細 `docs/bugs_archive.md` |
| 2/3/7 | FUN_0045a6f0 | platform | amplatform/* |
| 0xd | FUN_0045a320 | — | 未対応 |
| 0xe | FUN_004591b0 | — | 未対応 |
| 0x18 | FUN_0050a340 | — | 未対応 |
| 6/10(0xa)/0xb | FUN_00679cb0 | storage/**board-table(10)** | devices/storage.js（10 は未抑止の疑い） |
| 1 | FUN_006f0a80 | — | keychip/setup.js(KCHOLD) |
| (iVar2) | FUN_006f0ad0 | USB I/O | devices/usbio.js |
| 0x15(=1000) | FUN_007000c0 | alpbEx billing | allnet/billing.js ✅ |
| 0x17/0x16/0x14 | FUN_0089a010 | SYSTEM STARTUP (card/touch/**network**) | devices/*, amnet/* |
| 0x16 | FUN_008b2e00 | touch | devices/touchpanel.js |

deterministic fix の2案: (A) latch する setter の `DAT_016f5af0 = X` を NOP 化（suppress。ただし
FUN_0089a010 等は load-bearing で要慎重・stable attract を壊す恐れ）。(B) DAT_016f5af0 を**毎フレーム 0 に
保つ高頻度 watchdog** で scene-SM が error を「見ない」ようにする（低リスク。要 scene-SM が errCode を毎
フレーム読む前提の検証）。(C) scene-SM の error 分岐 reader を特定して patch（最も確実だが要 RE）。
⚠️ いずれも stable attract（既達）を壊さないこと。検証は `screenshot_window.py` 実写必須。

**方針統一（2026-06-13）**: TeknoParrot 方式＝**チェック無力化(A)に統一**する（TP は dongle/keychip/region
検査をフックで通過させる＝データを正そうとしない）。data-write+watchdog で「データを正す」アプローチは、
正規の供給源が無い値（PcbRegion 等）では timing-fragile になり display-snapshot を取り逃す。region(4) を
最初に (A) へ変換済（詳細 `docs/bugs_archive.md`）。残りの latch コード（0xa board-table / 0x14 network 等）も
順次 setter NOP 化して watchdog 依存を外すのが目標（FUN_0089a010 は load-bearing なので慎重に）。

---

## [RISK] amNet bind hook IP hardcoded to 192.168.1.209

Risk: If teknoparrot.ini [Network]Ip changes, amNet query_nic_status must also return the new IP, AND the bind hook target constant must be updated.
Location in boot/launch.py: `var TARGET_IP_LE = 0xD101A8C0;` (192.168.1.209 little-endian).
pcpa_server.py returns `ip_address=192.168.1.209` in query_nic_status response.
All three must match: teknoparrot.ini → pcpa_server.py → boot/launch.py bind hook.

---

## [ANTI-PATTERN] onLeave hook on crash-before-return function

onLeave requires the function to return normally. If the function crashes or calls ExitProcess, onLeave never fires.
Solution: Use Memory.patchCode to overwrite the function entry.

---

## [ANTI-PATTERN] Frida output pipe truncation

`... | Select-Object -First N` closes the pipe. Python receives SIGPIPE → exits → Frida detaches → game exits.
Solution: Use `--duration N` flag or `Start-Process` (background) + check log file afterward.

---

## [ANTI-PATTERN] python.exe Windows Store alias

`python.exe` and `python` resolve to Windows Store stub → exit code 49 "Python was not found".
Solution: Full path `%LOCALAPPDATA%\Programs\Python\Python313\python.exe`.

---

## [ANTI-PATTERN] Frida QuickJS missing standard globals

Not available: `Array.from`, `String.prototype.padStart`, `Uint8Array.map`.
Available alternatives: `ptr.readU8()`, manual for-loops, `new Uint8Array(ptr.readByteArray(n))`.

---

## [ANTI-PATTERN] args[1] as bufLen in platform/dongle hooks

For amPlatformGet*/amDongleGet* functions, args[1] (bufLen) reads stack garbage, not a valid length.
Solution: Ignore args[1]; use `writeUtf8String()` for strings or a safe hardcoded max.

---

## [ANTI-PATTERN] NOP state=7 counter threshold (JA at 0x4581DE) causes crash

Symptom: nrs.exe crashes immediately when state=7 runs (WerFault.exe / Y:\err.log spam → exit).
Cause: HLSM (FUN_00457FE0) case=7 sets `param_1[1]=1` as a "P-ras active" flag before checking the
counter/FUN_006FF650 result. If the JA at 0x4581DE is NOP'd (to skip the counter threshold), FUN_006FF650
is called on the very first tick — state=7 advances to state=8 in the same tick. param_1[1] is set=1
AND the state advances, triggering an error in another thread that checks param_1[1] out-of-band.
Root cause: case=7 body has side effects (param_1[1]=1) that another subsystem observes. Fast advance
via JA NOP exposes a race — the other thread sees param_1[1]=1 while the state is already at 8.
Safe bypass: Use HLSM Interceptor.attach onEnter to write param_1[0x18]=8 BEFORE the first-switch runs.
This makes the first-switch copy 0x18→0x14=8 and dispatch to case=8 directly, skipping case=7 body
entirely → param_1[1] stays 0. FUN_006FF650 is still patchCode'd to return 1 as a belt-and-suspenders
for the natural path (post-Frida-detach counter timeout at DAT_00c91568 threshold).
Location: 0x4581AF (case=7 start), 0x4581B6 (param_1[1]=1 write), 0x4581DE (JA = do NOT NOP).
