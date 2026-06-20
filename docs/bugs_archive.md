# Bug Archive — Resolved Bugs (FIXED) & Historical Notes

`BUGS.md` の本体を軽く保つため、**解決済みバグ（FIXED）** と **修正の経緯を残す参考 NOTE** をここに分離。
live な未解決課題・リスク・アンチパターンは `BUGS.md` に残る。各エントリは
「symptom → root cause → fix/workaround」。アドレスは static_VA（特記ある箇所のみ RVA）。

---

## [FIXED] ブートが keychip 前で停止（白画面・固まる）— boot モジュールのロード順依存

Symptom: 再編成後、白い画面で固まりアトラクト未到達。ログ上 `query_application_status`(appslot 40102) を
延々ループし、keychip コマンド(`ds.compute`/`ssd.proof`/`version`)を一度も送らず、HLSM(FUN_00457FE0)も
0 回。`amDongleBusy` は赤鯡（旧成功ランも busy=0x1 でアトラクト到達）。
Root cause: `boot/MANIFEST.json` の `load_order` を**サブシステム別**に並べ替えたこと。コード行は旧と同一
（行 diff で差分ゼロ）だが、**ブートは frida モジュールのロード順に敏感**。旧の数値順(00..32)では keychip
setup(21)/region(08)/recv(00) 等が特定の相対位置にあり、これを崩すと初期 init チェーンが進まない。
Diagnosis（決め手）: 旧スクリプト（git 復元・byte 同一）＋現行 pcpa で起動 → keychip=22/HLSM=26 で到達。
新スクリプト（サブシステム順）→ keychip=0。新スクリプトを**旧の数値順に並べ替える**と keychip=22/HLSM=26 に回復。
Fix: `boot/MANIFEST.json` の `load_order` を**元の数値ファイル順(00..32)に忠実化**（分割した子は親の位置に連続配置）。
ファイル構造（subsys 別ディレクトリ）はそのまま。`_doc` に「numeric-faithful 維持」を明記。
Anti-pattern: **boot モジュールを「見やすさ」でロード順変更しない**。順序は MANIFEST が単一ソース。
追加/分割時も元の相対順序を保つこと（`boot/CONVENTIONS.md` 参照）。

---

## [FIXED] Error 8006 Network timeout (DHCP) — 真因は pcpa_server の `\r\n` フィールド区切り（2026-06-13 確定）

Symptom: amNet 応答抽出 `0x5814E0`(=amNetworkResponseCheck) が **ret=-1** を返し amNet(DHCP/NIC)が解決せず
SM ループ → Error 8006「Network timeout error (DHCP)」。
**真の Root cause（Ghidra で確定）**: PCP パーサ `pcppChangeRequest`(static 0x98bb30) は **`&` をフィールド
区切り**とし、**`\r` または `\n` を見た時点でパースを打ち切る**。`pcpa_server.py` は amNet 応答だけ
`response=query_dhcp_status\r\nresult=0\r\n...` と **`\r\n` 区切り**にしていたため、最初の `\r` でパースが
止まり `response` ペア1個しか登録されず、抽出器が `result` を見つけられず -1（→default→0xffffffff）。
get_status 等の `&` 区切り応答が正常動作していたのと対照的。「`\r\n` が必須」という旧 FACTS 記述は誤りで、
それを回避するため runtime force-patch で誤魔化していた、という構図。
**Fix（serve 経路の正攻法）**: [boot/mxkeychip/server/pcpa_server.py](../boot/mxkeychip/server/pcpa_server.py) の
`query_dhcp_status`/`query_nic_status` 応答を **`&` 区切り**に変更（他の応答と統一）。これで native
`0x5814E0` が **ret=0** を返し、ctx を自力で満たす（dhcp_status=3 / nic_ready=1）。旧 force-patch
（`amnet/state.js` の 0x5814E0 onLeave force）は**撤去**し log-only monitor に置換（persistence: monitor）。
検証（force OFF + `&`）: `amNetDIAG orig=0 nDhcp=3 nicReady=1`、`8006` ログ 0 件、HLSM stable ATTRACT 到達。
これで amNet は runtime hook 無し（pcpa_server だけ）で serve され、detach 耐性も持つ。nic プロパティ連鎖
（query_nic_status が ip/mask/gw/dns を inline で返す）の機序は `boot/mxnetwork/FACTS.md` 参照。
**残課題**: 画面には別の device-scene エラーが残る（`BUGS.md` の [大半解決] device-presence 参照。8006 自体は解決）。

---

## [FIXED] Error 0903 "Wrong Region" — region setter を check-neutralization で恒久解消（2026-06-13）

Symptom: 8006/8001 を上流で潰すと、次の latch として errCode 0x4(region) が display struct に固着し画面
"Error 0903 Wrong Region"（`captures/verify-devstatus2-fix.png`）。REGION_CHK は PASS・HLSM は ATTRACT 到達
なのに残る（display struct latch）。
Root cause（Ghidra 確定）: region ゲート `(DAT_016014c4[PcbRegion] & DAT_01601989[dongleRegion] & 5)==0` で
`FUN_00458fd0`/`FUN_0045a7f0` が `DAT_016f5af0=4` を latch。dongleRegion は pcpa `appboot.region=01` で満たせるが
**PcbRegion(`DAT_016014c4`) はバイナリ内に writer が無い**（全 xref READ）＝本来 mxGetHwInfo/基板コンフィグが
供給する基板値。検査をバイパスした本構成では 0 のままで `(0 & x & 5)=0` は不可避。`region.js` の forceRegion
data-write は **`FUN_00458fd0` が amlib init 初期に着弾前へ走り** errCode 4 を display struct(`DAT_016f5a80`)へ
snapshot するため取りこぼす（timing-fragile）。
Fix（TeknoParrot 方式＝チェック無力化）: errCode 4 の `MOV dword ptr [0x016f5af0],4`（C7 05+addr4+imm4=10B）を
**両 setter で NOP10**（`0x59109`=FUN_00458fd0 / `0x5A846`=FUN_0045a7f0, patchCode 永続）。先行 `if(==0)` ガード
直後の単純ストアで、呼出元 `FUN_006c3730`/`FUN_00643de0` は両関数の戻り値を捨てる（xref/decompile 確認）ため、
ストア除去だけで region error は二度と latch せず制御フロー・戻り値も不変。`DAT_016014c4=01`(PcbRegion) の
data-write は anti-tamper `FUN_0048f9c0` の region-index 整合（01→0=JAPAN）用に**維持**（errCode 抑止用ではない）。
比較: micetools は実 KCF(`AM_APPBOOT.m_Region`)で `appboot.region` を正しく返す「データを正す」解（PcbRegion は
実基板供給前提）。TP は region 検査をフックで通過する「チェック無力化」解。本構成は基板値の供給源が無いので
TP 方式が正しい。実装 `boot/mxkeychip/region.js` / 詳細 `boot/mxkeychip/FACTS.md`「amlib region gate」。
検証（2026-06-13 実機, `captures/verify-region-neutralize.png` = 全国ランキング attract デモ描画＝クリーン）:
NOP10 verify=true（0x59109/0x5A846）。決定打 `REGION_CHK 458fd0#1 game=0x0 dongle=0x1 (game&eff&5)=0x0 -> FAIL
errCode=0` ＝ FUN_00458fd0 が PcbRegion=0 のまま早期に走り gate FAIL するが、NOP で errCode は **0**（旧 run は
=4 latch）＝data-write レースの正体を実証。`ERR_DISPLAY`/`0903`/`Error 09` ログ 0 件、HLSM BOOT_DONE/ATTRACT 到達。

---

## [FIXED] patchCode code[i]=value writes nothing (Frida QuickJS)

Symptom: patchCode callback runs without error but memory bytes unchanged.
Cause: In Frida QuickJS, `code[i] = value` sets a JavaScript property on the NativePointer object. It does NOT write to process memory.
Fix: Use `code.writeByteArray([b0, b1, ...])`.
Verification: After patchCode, log `ptr.add(i).readU8()` for each patched byte to confirm.

---

## [FIXED] amPlatformGetPlatformId persistent Error 0901 after Frida detach

Symptom: Game shows "Error 0901 Wrong Platform" after Frida --duration expires. Before detach, hook was suppressing it.
Cause: Previous fix used Interceptor.attach (onLeave), which is removed when Frida detaches. The native function compares hardware ID with string at VA 0xADFD70="AAL" (3 ring-type codes: "AAL","AAM","NEC"). On PC, hardware returns different string → mismatch → error.
Fix: Replace Interceptor.attach with `Memory.patchCode` at each function entry:
  - At entry: `mov eax,[esp+4]` (buf arg); write string bytes byte-by-byte; `xor eax,eax; ret 4`
  - Function is stdcall(char* buf), ret 4 confirmed by disasm (both 0x58200B and 0x582201)
  - patchCode writes are PERSISTENT (survive Frida detach and process lifetime)
  - Use `patchPlatformFunc()` helper that generates machine code from fillStr
  - **Current value: "AAL"** (hardware board ID matched against "AAL"/"AAM"/"NEC" comparisons).
    "RingEdge" was used initially but fails all comparisons → still Error 0901. Changed to "AAL".
Confirmed: nrs.exe alive 3+ min after 180s Frida detach with no Error 0901 (frida-20260608-165012.txt)

## [FIXED] amPlatformGetPlatformId bufLen bug → Error 0901 Wrong Platform (prior bug)

Symptom: `[amPlatform] buf="R"` or `buf="Rin"` in logs; game displays "Error 0901 Wrong Platform".
Cause: hookPlatform read `args[1]` as bufLen. For these functions args[1] is stack garbage (observed: 1 or 3). `Math.min("RingEdge\0".length, 1) = 1` → only "R" written.
Fix: `this.buf.writeUtf8String(fillStr)` in onLeave. No bufLen needed; writeUtf8String appends null terminator automatically. (Superseded by patchCode fix above.)

---

## [FIXED] amBackupWrite access violation → Windows ER kills nrs.exe after ~16s

Symptom: EXCEPTION log at RVA 0x5858F3 (`mov eax,[esi]`, esi=dangling ptr); game exits; "PDB search" log spam.
Cause: 0x5858D0 (`amBackupReadRecord`, 旧名 amBackupWrite_entry) reads `*param_1`(=記録記述子) at 0x5858F3.
null は弾くが、当時は **mxsram が無効ハンドルで記録配列の初期化が中途半端 → param_1 が dangling** だった
（keychipSM state3 後）。
旧 Fix（暫定）: patchCode 0x5858D0/0x5858E1 → `MOV EAX,-21; RET 8`（全 amBackup を -21 短絡。crash は止むが
セーブ機構が全死。`amBackupRecordReadDup: error(-21)` をログに出していた）。
真 Fix（2026-06-13 撤去）: `boot/mxdrivers/devices.js` の mxsram を micetools `mxsram.c` 準拠＋
`data/nvram/sram.bin` 永続化にしたことで amBackup→amSram→mxsram が実データで成立、記録配列が正しく初期化され
param_1 が有効化。blanket stub（`boot/ambackup/stub.js`）を撤去し native amBackup を再活性化。
（万一 0x5858F3 が再発したら、0x9858D0 で第1引数の可読性 guard を入れる＝旧 stub のピンポイント版。）

---

## [FIXED] keychipSM state4 crash → init thread death → calls=0 forever

Symptom: amJvspAckSwInput never called (calls=0 in JVS_DIAG). initFlag stays 0.
Cause chain: keychipSM state4 → calls 0x457AF0 → DLL-internal access violation at DLL+0xdb58f3 → init thread dies → amJvspInit never reached → jvs_initialized_flag=0 → game main loop polling never starts.
Fix: patchCode at 0x457AF0: `31 C0 C3` = `XOR EAX,EAX; RET`. onLeave hook is useless here — function crashes before returning.

---

## [FIXED] JVS polling loop never iterates despite initFlag=1 and n640=1

Symptom: calls=0; JVS_DIAG shows initFlag=1, n640=1 but still no calls.
Cause: `jvs_node_count` at 0x12B785C was never forced. Game loop is `for(i=0; i<jvs_node_count; i++)`. node_count=0 → zero iterations → amJvspAckSwInput never called.
Fix: Watchdog setInterval forces 0x12B785C = 1 every 2s.
Note: initFlag alone is not sufficient. Both initFlag AND node_count must be ≥1.

---

## [FIXED] JVS watchdog fired once then stopped (setTimeout → setInterval)

Symptom: n640 forced to 1 at t=5s, but subsequent JVS_DIAG shows n640 back to 0.
Cause: Game resets n640 each tick. setTimeout fires only once.
Fix: Replace setTimeout with setInterval(2000ms). Force-write all JVS state variables every tick unconditionally.

---

## [FIXED] keychip.ds.compute loops endlessly — pcpaSend ret=-4

Symptom: pcpaSend count #9000+; keychipSM state3 loops. pcpa_server receives CONN on 40106 but no REQ.
Cause: hookPcpa forced `ret.replace(0)` on pcpaOpenClient regardless of the natural return value.
  - Natural: orig=1 = "new connection established, socket handle stored in stream struct".
  - Forced: 0 = "use cached connection" — but 40106/40104 had NO prior cached socket.
  - Result: pcpaSendRequest found no valid socket → returned -4 without calling OS send().
  - 40102 was immune because its first connection was made before the Frida hook was installed
    (pre-hook connection established a valid cached socket; forced-0 then hit that cache).
Fix: Changed to `if (orig < 0) { ret.replace(0); }` — only overrides genuine errors.
Verified root cause: pcpa_server 40106 showed CONN but no REQ for 4s; frida had no raw send() between pcpaOpenClient and pcpaSend for 40106; 40102's raw send() did fire normally.

---

## [FIXED] amNet dhcp_status infinite loop — state 0 never advances to state 1

Symptom: amNet SM (port 40104) loops forever in state 0; game never reaches bind().
Cause chain:
  1. TeknoParrot intercepts winsock on port 40104 and returns response WITHOUT "response=" prefix.
  2. 0x5814E0 (amNet response extractor) calls pcpaGetRecvValue(stream, "response") → NULL → returns -6.
  3. 0x581A30 (async driver) stores ctx+0x14=-6 when 0x5814E0 fails.
  4. SM tick: [0x16019a0]=-6 < 0 → jl clears [0x160199b] → dispatch re-runs state 0 handler → loop.
Fix:
  - boot/launch.py: hookAmNet IIFE hooks 0x5814E0 onLeave; when ret≠0 force ALL amNet ctx fields:
      ctx+0x30=3 (dhcp_status), ctx+0x68=1 (dhcp ready), ctx+0x38=TARGET_IP_LE (nic ip), ctx+0x69=1 (nic ready)
  - Reason ALL must be set unconditionally: 0x581C40 (state 3 NIC query initiator) uses the SAME string
    address 0xADFA0C as 0x581AE1 (state 1 DHCP query). At runtime 0xADFA0C = "query_dhcp_status" for both.
    So lastPcpaReqName is always "query_dhcp_status" regardless of state; checking req name is unreliable.
  - pcpa_server.py: added "response=<req>\r\nresult=0\r\n" prefix to amNet responses (for standalone mode).
    （上記 [FIXED] Error 8006 で `\r\n` → `&` に是正済み。）
Expected log: "[amNet] 5814E0 forced all: dhcp=3 nic=0xd101a8c0" then bind(192.168.1.209:...) fires.

---

## [NOTE] amNet state3 uses same "query_dhcp_status" string as state1; fix must set ALL ctx fields

After state1 succeeds (dhcp_status=3 → state→3), state3's query initiator (0x581C40) sends
the SAME request name as state1: the string at 0xADFA0C = "query_dhcp_status" at runtime.
So 0x5814E0's hook must unconditionally set BOTH dhcp fields (ctx+0x30=3, ctx+0x68=1) AND
nic fields (ctx+0x38=IP, ctx+0x69=1), regardless of lastPcpaReqName.
Checking req name alone is unreliable because both state1 and state3 use identical string addr.

---

## [NOTE] amJvspAckSwInput error return (-11) + switch buffer IS read despite error

History: amJvspAckSwInput natively returned -11 (FUN_009877e0 GetReport fails without real JVS HW).
Now: `boot/amjvs/input.js` patchCodes 0x5883D3 (`MOV EAX,EDI` → `XOR EAX,EAX`, persistent) so the
function returns 0 on GetReport failure → errCnt stays 0. The onLeave Interceptor therefore sees 0.
Despite the original error, writing to args[4] (outPtr) in onLeave propagates to node+0x643 (sw643)
as observed in JVS_DIAG. The game reads the switch struct directly from node memory rather than from
the function's return path. Injection via outPtr write-in-onLeave IS effective for setting sw643 bits.
- SERVICE injection: outPtr.writeU8(0x40) → sw643=0x40 ✓ (confirmed tick=22)
- START injection: outPtr.writeU8(0x80) → sw643=0x80 ✓ (confirmed phase=3)
Whether the game's state machine ACTS on sw643 is still unconfirmed (no display).

---

## [FIXED] Game crashes ~t+7s after 2nd DeviceIoControl 0x47080c

Symptom: nrs.exe terminates ~t+7–8s; JVS polling thread stopped (identical call counts across ticks).
No EXCEPTION log → TerminateProcess, not access violation.
Cause: after auth, game fires a 2nd DeviceIoControl 0x47080c (JVS reset, h=0x6e8) → polling thread exits
→ game calls amJvspInit (0x586720) to restart → tries pipe/COM2/COM1, all fail → returns -4 (ENODEV).
bypassJvs hook had EXCLUDED -4 from its force-0 logic → no JVS thread → JVS error handler → TerminateProcess.
Fix: force ALL ret<0 → 0 in amJvspInit hook + forceCtxConnected(). The -11→0 (amJvspAckSwInput),
statusFn→1, nodeInfo version-byte hooks keep the restarted thread healthy.
Anti-pattern: Do NOT re-add the `-4` exclusion — without -11→0 it lets the thread die after -4→0 forcing.

---

## [FIXED] Error 0903 Wrong Region after Frida detach

Symptom: Game shows "Error 0903 Wrong Region" after Frida --duration expires. State=0 [ATTRACT] was stable during session. Error appears 0-120s after detach.

Cause A (re-boot path): HLSM state=0 handler (at static_VA 0x458237) checks 3 re-boot conditions, converging at static_VA 0x458271 (= RVA 0x58271; `89 5D 18` = `mov ctx.next, 1`):
  - A. FUN_006FF980() != 0 (RVA 0x2FF980)
  - B. DAT_0210B508 ([0x210B508]) != 0: persists throughout session.
  - C. counter >= threshold: ctx+0x10 incremented each tick at state=0; timed re-boot.
After Frida detach, if any condition fires: state=0→1→boot→5→Error 0903.

Cause B (Interceptor.replace + patchCode conflict — ROOT CAUSE of FUN_00975140 persistence failure):
  - `Interceptor.replace` was used at 0x575140 (FUN_00975140).
  - `patchCode` was also applied at 0x575140 (forEach list).
  - On Frida detach, `Interceptor.replace` RESTORES ORIGINAL BYTES, overwriting patchCode.
  - Result: FUN_00975140 returns -5 after detach → [0x1286FEC] becomes non-zero → potential Error 0903 path.

Fix:
  1. Removed `Interceptor.replace` at 0x575140. Patched exclusively via patchCode (persistent).
     FUN_00975140 now returns 0 permanently after first Frida session.
  2. FUN_006FF980 kept as `Interceptor.replace` (bootDone gating) — needed because
     DAT_0210aed0/aed2/aed4 flags (checked by hlsm_region_check) require real keychip hardware;
     without keychip these flags are never set → counter threshold (18000 ticks ≈ 5min) would block boot.
  3. Removed patchCode at 0x2FF980 from GETSTATUS_FIX — Interceptor.replace conflicts with it.
     After detach: FUN_006FF980 returns 0 naturally (hardware flags never set) → condition A is false.
  4. patchCode RVA 0x58271 → NOP×3 (GETSTATUS_FIX) blocks conditions B and C permanently.
     Result: state=0 cannot advance after attract mode, regardless of FUN_006FF980's return value.

Anti-pattern: Never combine `Interceptor.replace` + `patchCode` at the same address.
  On Frida detach, `Interceptor.replace` restores saved original bytes, overwriting patchCode.
Anti-pattern: Patching only FUN_006FF980 (condition A) is insufficient — conditions B and C remain active. Patch the convergence point at 0x458271 instead.

---

## [FIXED] amlib Region error (DAT_016f5af0=4) — 2nd region path, masked the real operand

Symptom: After fixing the 0x387/0x5744F0 path, Error 0903-class region error persisted post-detach.
Cause: A SEPARATE region check at FUN_00458fd0:49 / FUN_0045a7f0:40 (NOT touched by any prior patch):
  `if ((DAT_016014c4 & DAT_01601989 & 5) == 0) DAT_016f5af0 = 4;`  (mask 5 = bit0|bit2)
  - DAT_01601989 = dongle region (amDongleGetRegion → pcpa keychip.appboot.region). Was 0x02(USA) → `&5`=0.
  - DAT_016014c4 = game/PCB region (TeknoParrot PcbRegion). Has NO writer in the binary → stays 0x00.
  - Diagnostics proved: game=0x00, dongle=0x01(after fix), gate(DAT_016014a2)=1 → `0 & 1 & 5 = 0` FAIL.
  - This binary is a JAPAN build (FUN_0048f9c0 decodes 0x01=JP/0x02=US/0x08=EXP). JAPAN region = 0x01.
Fix:
  1. pcpa_server.py: keychip.appboot.region 02 → 01 (JAPAN) — fixes dongle operand.
  2. boot/launch.py: force DAT_016014c4=0x01 (RVA 0x12014C4) + DAT_01601744=0x01 (RVA 0x1201744).
     Frida DATA writes PERSIST post-detach (only Interceptor hooks revert) → permanent.
Verified: REGION_CHK diag shows game=0x1 dongle=0x1 → PASS; Error 0903 no longer displayed.
Note: DAT_016f5af0 (amlib master errCode, struct DAT_016f5a80 field) collects MANY hw-absence init
errors (2/3/7=platform!="AAL", 4=region, 6=storage, 10=board-table, 0xb/0xd/0xe/0x14-0x18). On real
RingEdge all pass → 0. In bypass several fail. Watchdog clears DAT_016f5af0 (RVA 0x12F5AF0) each tick.
The error display reads it via the struct pointer (not visible as DAT_016f5af0 in C → can't patch by name).
(注: この 2nd region path は後に check-neutralization 化で恒久解消。上記 [FIXED] Error 0903 region setter NOP 参照。)

---

## [FIXED] Error 1000 → Error 5101 → Error 951 → Error 5501 → Error 8005: amlib device-presence チェーン

TP-alignment 作業(2026-06-12)で、boot 後に居座るエラーシーンが**デバイス presence チェックの連鎖**だと判明。
各 errNo は描画ビルダ `FUN_00489130`(autoscene; scene-type→scene-ID) が積むが、**発生源は個別のデバイス
presence チェック**。1つ satisfy するごとに次のデバイスエラーへ前進する。

エラーメッセージテーブル(連続, 直接 xref 不可＝pointer table 経由):
`0xbd0374` IC Card R/W / `0xbd038c` Touch Panel / `0xbd03a4` USB Device / `0xbd041c` Keychip /
`0xbd0464` Game Program on Storage / `0xbd0518` Sound Function / `0xbd0534` Graphic Function。
init SM `FUN_0089a010` の "CHECKING ..." 文字列: IC CARD R/W / TOUCH PANEL / NETWORK / EXTEND IMAGE / CONNECTION。

### [FIXED] Error 1000 "Unknown Application Error" (amlib errCode 0x15 = alpbEx billing)
真因: `FUN_007000c0`(RVA 0x3000c0, alpbEx_billing_poll) が `FUN_00a065c0`(ALL.Net billing client status)
の未処理戻り値で `DAT_016f5af0=0x15` を立てる（実サーバ不在）。
修正: `boot/patches.json(0xA065C0)`(alpbExGetExecStatus→5, offline idle)で解決。実機確認: 1000 消滅し次の 5101 へ前進。

### [FIXED] Error 5101 "IC Card R/W Not Found" (errCode 0x17)
- 真因: `FUN_0089a010` state2("CHECKING IC CARD R/W")が presence プローブ
  `FUN_004f6310`(*statusのbit1)/`FUN_004f6330`(bit4=R/Wエラー)を読む。status は `*FUN_004f3e30()`
  (device-list の type 0x21/0x21 = IC Card R/W デバイス, status word は [dev+4]+4)。実機リーダ非在で
  bit4=1 → errCode 0x17 → error state9 → scene errNo 5101(sticky)。
- 修正: `boot/devices/cardreader.js` が両プローブを `xor eax,eax;ret`(healthy)に patchCode(verify=true)。
  TP の emulated aime reader と同じ「リーダ正常」end-state のアサート(satisfy)。
- 実機確認: 5101 消滅、HLSM attract 維持 → 次の USB Device 951 へ前進。

### [FIXED] Error 951 "USB Device Not Found" (errCode 0xf)
- 真因: `FUN_00679de0`末尾が `DAT_016b88dc<1`(USB I/Oボード未検出)→ `iVar2=-0x70(-112)` →
  `FUN_006f0ad0` が `switch(DAT_016b7000)` default → errCode 0xf → scene 951。
- エスケープ: `DAT_016b88dc>=1`(I/Oボード present) かつ `jvs_error_state(0x16b8670)==0`。
- 修正: `boot/devices/usbio.js` が I/Oボード present フラグと jvs_error_state=0 を維持。

### [FIXED] Error 5501 "Touch Panel Not Found" (errCode 0x16)
- 修正: `boot/devices/touchpanel.js` (patchCode, 永続)。

### [FIXED] Error 8005 "Network type error (WAN)" (errCode 0x14)
- 修正: `boot/patches.json(0x6FF18A/AC/B3)` (patchCode, 永続)。

---

## [FIXED] get_status recv completion — raw winsock bypasses PCPA async SM

Root cause: port 40113 uses raw `recv()` (not pcpaRecvResponse), so `[stream+0x21C]` (completion state)
is never updated → `0x58B260` never returns 1 → SM loops. Fix: `boot/mxgfetcher/getstatus.js` sets
`getStatusRecvDone` flag in `recv` hook; `0x58ADC0 onLeave` forces ret=1 once. Also patches `0x575140`
(result= field checker) → always return 0 (was always -5 → blocked parser). Details in FACTS.md §patchAmGfetcher.

---

## [NOTE] JVS P1 call rate during init: ~0.5Hz (not 30Hz)

During game init (phase=0, before attract), amJvspAckSwInput fires at ~0.5Hz for panel=0.
WAIT_BEFORE_SVC=300 (designed for 30Hz = 10s) would take 600s at init rate.
Calibrated to WAIT_BEFORE_SVC=20 (~40s at 0.5Hz). If game advances to attract/play mode,
the rate should jump to ~30Hz and thresholds may need re-tuning.

---

## [NOTE] keychip.ds.compute confirmed on port 40106, not 40110

Static analysis found `PUSH 40110` at VA 0x978ADC. That PUSH is for a different pcpaOpenClient call.
Frida logs show: pcpaSet("keychip.ds.compute") → connect 127.0.0.1:40106.
Do not route ds.compute to port 40110.
