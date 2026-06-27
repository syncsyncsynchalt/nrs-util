# Bug Catalog — Live (OPEN / RISK / ANTI-PATTERN)

Format: ## [STATUS] SYMPTOM — status is OPEN|RISK|ANTI-PATTERN
Each entry: symptom → root cause → fix/workaround.
解決済み FIXED の履歴は `git log` 参照（本体は live: OPEN/RISK/ANTI-PATTERN のみ軽く保つ）。

---

## [OPEN] device-presence エラーシーン残留（0903/8006/1000…）

Symptom: HLSM は stable attract(state0, 数千 tick, 再ブート無し)に到達するのに、画面に device エラー
シーン(Error 0903 Wrong Region / 8006 / 1000 等)が**1つ貼り付いて消える前提が崩れる**ことがある。
**latch する errNo は run ごとに変わる**＝latch は「最初に立った errCode」のレース。
Root cause: 起動初期に errCode 0xa(board-table)/0x4(region)/0x14(network) が **display struct
`DAT_016f5a80` のフィールド**へ latch → レンダラ `FUN_006f2730`(RVA 0x2f2730) が記述子(+0x00 errCode /
+0x10 errNo)を毎フレーム描画し続ける。watchdog は `DAT_016f5af0`(amlib master errCode)を毎 tick クリアするが
**display struct 側はクリアしない**ため、underlying チェックが後で PASS(REGION_CHK PASS 等)してもシーンが残る。
**8006 を正しく直して amNet が native 解決(ret=0)しても device-scene は消えない**＝この latch は amNet の成否と
独立（underlying PASS でも display struct が残る）。
8001(network) の underlying: `FUN_006fe040` が `DAT_016019a6`(ip_match) 真を要求。ip_match=`(mask&ip)==(ref&mask)`
（ref=`DAT_0160198a`）。nic IP は query_nic_status 応答の inline 解析で ctx+0x3c へ入る（`boot/mxnetwork/FACTS.md`）。
手当て候補: `FUN_006f2730` を Ghidra で解析し描画記述子の出所(`DAT_016f5a80` 系)を特定 → attract 到達後に
errCode/errNo フィールドを 0 クリアする watchdog/patch を追加（または builder `FUN_00489130` を抑止）。
順次 setter NOP 化で watchdog 依存を外すのが目標。

### errCode latch 機構（root cause）
各 setter は `if (DAT_016f5af0==0) { =X }`＝**最初に立った errCode が latch して固着**（`FUN_006c35c0` が =0 クリア）。
実機 latch 観測=0xa→0x4→0x14。**handled errCode の fix は各サブシステムモジュールの `patch()`**（一覧 `tools/static/patch_audit.py`）、各 setter 関数は要時 Ghidra
`search_decompiled` で再導出する（正は実装）。
- **0xa board-table**(`FUN_00679cb0`)= **解消済**。board index `DAT_01601953` を 2 に固定（`devices/presence.js`
  patch `0x45A18E`）して table[2]=8 を満たす＝値供給。setter NOP ではなく入力を正す方式（`FUN_006c5470` の
  0x11/0x1e も同時解消）。詳細 `devices/FACTS.md`。
- **0xd=`FUN_0045a320` / 0xe=`FUN_004591b0`** = setter は `if(DAT_016014a4)` でゲートされ、amHmInit 失敗
  （HW モニタ不在→flag=0）で経路ごと無効化＝**現構成では発火せず**（要対応外）。
- **未対応（要時 setter を NOP）**: 0x18=`FUN_0050a340`。

deterministic fix の2案: (A) latch する setter の `DAT_016f5af0 = X` を NOP 化（suppress。ただし
FUN_0089a010 等は load-bearing で要慎重・stable attract を壊す恐れ）。(B) DAT_016f5af0 を**毎フレーム 0 に
保つ高頻度 watchdog** で scene-SM が error を「見ない」ようにする（低リスク。要 scene-SM が errCode を毎
フレーム読む前提の検証）。(C) scene-SM の error 分岐 reader を特定して patch（最も確実だが要 RE）。
⚠️ いずれも stable attract（既達）を壊さないこと。検証は `screenshot_window.py` 実写必須。

**方針**: TeknoParrot 方式＝**チェック無力化(A)に統一**する（TP は dongle/mxkeychip/region
検査をフックで通過させる＝データを正そうとしない）。data-write+watchdog で「データを正す」アプローチは、
正規の供給源が無い値（PcbRegion 等）では timing-fragile になり display-snapshot を取り逃す。
latch コード（0xa board-table / 0x14 network 等）は
順次 setter NOP 化して watchdog 依存を外す（FUN_0089a010 は load-bearing なので慎重に）。

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
