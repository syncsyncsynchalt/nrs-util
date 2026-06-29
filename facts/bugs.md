# Bug Catalog — Live (OPEN / RISK / ANTI-PATTERN)

Format: ## [STATUS] SYMPTOM — status is OPEN|RISK|ANTI-PATTERN
Each entry: symptom → root cause → fix/workaround.
解決済み FIXED の履歴は `git log` 参照（本体は live: OPEN/RISK/ANTI-PATTERN のみ軽く保つ）。

---

## [ANTI-PATTERN] デバイスエミュ: IOCTL ハンドシェイクだけ通すと init は成功するがデータ面欠落で I/O 全滅

**症状**: `amBackupRecordRead/WriteDup: error(%d)` が洪水化。columba(DMI)修正で -21 は消えたが別コードが残る。

**根本原因**: amBackup の記録は board type 3 で **2 デバイスに分割**（area0,1=EEPROM/mxsmbus, area2,3=SRAM/mxsram。
`facts/mxdrivers.md` 記述子テーブル節）。`amSramInit`(0x986380) は **PING/geometry/sector の IOCTL ハンドシェイクのみで
成功**し `amSram_initFlag=1` にする。しかし記録 R/W の実体は **SetFilePointer(0xADC178)+ReadFile/WriteFile**（worker
0x985bc0/0x985c80）であり、このデータ面を未エミュだと **init は通るのに SRAM area の R/W が全失敗** → 洪水。
「init OK」を「デバイス動作」の証拠と取り違えるのが罠（ログ上は初期化成功に見える）。

**修正**: host が `SetFilePointer` をフック(ABI v4 `on_set_file_pointer`)→ `mxdev_seek`/`mxdev_read`/`mxdev_write` が
`nvram.bin` を memory-map した backing で記録を授受。GET_SECTOR_SIZE は authoritative 値 **RINGEDGE2=4**（micetools）を返す。

⚠️ **自己訂正**: 「sector 512 だと sub-512 record I/O が弾かれて洪水が残る」は**誤り**だった。実体検証で
SRAM 系 4 record(BACKUP/HM_PEAK/TIMEZONE/ERROR_LOG)は**全て明示パディングで正確に 512B/512境界**＝512 でも
アラインメント検査は通る。**洪水の原因はデータ面の欠落のみ**で sector size は無関係。4 は authoritative かつ厳密に
緩いので採用したが、これは fidelity 改善であって洪水 fix ではない。

**教訓**: ①デバイスは「制御面(IOCTL)」と「データ面(Read/Write/Seek)」の二層。init が通ってもデータ面の配線を
実体(nrs.exe の呼出経路＋実ドライバ mxsram.sys の IRP)で裏取りせよ。②**値の根拠は推論でなく実体で確かめる**——
record サイズを構造体定義(amBackupStructs.h)で算出する前に「sub-512 だろう」と推論したのが誤りの元。値は実装が正。

---

## [FIXED→新ブロッカー] EEPROM(amBackup area0,1) は SetupDi で開くため standalone で init 失敗 → -3 洪水

**症状（2026-06-29 実走）**: `amBackupRecordWriteDup/ReadDup: error(-3)` が洪水化（14098 行中 14044 行）。
boot は main loop に到達するが backup write 連続失敗で塞がり、touch poll(`touch.read`)へ進めない。

**根本原因（実体逆コンパイルで確定）**: EEPROM device は **名前 CreateFile ではなく SetupDi で開く**。
`amEepromCreateDeviceFile`(0x984910) = `SetupDiGetClassDevsA`→`SetupDiEnumDeviceInterfaces`→
`SetupDiGetDeviceInterfaceDetailA`→`CreateFileA(DevicePath)`。standalone には mxsmbus の **PnP デバイスが無い**ため
列挙が失敗しデバイス未オープン → `amEepromInit`(0x985160) 失敗（後始末 `FUN_00984bd0` が initFlag を 0 に戻す）→
EEPROM write fn(0x984E20)が `initFlag(0xccf4e0)==0` を見て **-3** を返し続ける。**mxdevices.c の名前ベース mxsmbus
エミュ(`mxdev_create L"mxsmbus"`)はこの SetupDi 経路では一度もヒットしない**。⚠️ `mxdrivers.md` の「amEepromInit 成功」
は誤り（別環境 or 願望）— 実体では SetupDi で失敗する。

**修正（globals poke で amEepromInit 成功状態を再現）**: `api.c` `eeprom_force_ready()`（on_jvs_tick から one-shot）。
eeprom ctx(base `0xccf4e0`, amEepromInit 逆コンパイルで確定したレイアウト)を再現:
`+0x00`=initFlag=1 / `+0x04,+0x08`=6 / `+0x0c`(`0xccf4ec`)=mutex(CreateMutexA) / `+0x10`(`0xccf4f0`)=device handle=
**H_MXSMBUS** / `+0x14`(`0xccf4f4`)=0x57。device handle を H_MXSMBUS にすると write/read fn の
`DeviceIoControl(0x9c40200c, i2c@0x57)` が既存 mxsmbus エミュ(`mxdev_ioctl`→AT24C64AN→eeprom.bin)へ流れる。
on_jvs_tick は main loop（storage init 後）で回るので amEepromInit は既に試行済み＝initFlag==0 を見て安全に上書き。
**実走検証: `eeprom.force_ready` 後 amBackupWriteDup error 14044→0、ログ 14098→35 行**。

**残課題（修正で露出した下流ブロッカー, 次工程）**:
- **timing**: force_ready は first main-loop frame で走るため、**早期 storage init の region/serial チェックには間に合わない**
  （その時 eeprom 未 provisioning）。STATIC を読む層を通すには **より早い hook で provisioning する必要**あり
  （patches_apply 等。ただし amEepromInit が initFlag!=0 で -4 を返す経路の caller 影響を要確認）。
- **content**: `amlib: Region error. (00, 01, 05)` ＋ `amHmInit() failed.`。eeprom.bin は blank(0xFF)＝**STATIC レコードに
  有効な region/serial が無い**ため region チェックで停止（`mxdrivers.md` 予告の層）。新規 eeprom.bin に STATIC を
  seed する必要（region code/serial/CRC の構造を要 RE）。

---

## [ANTI-PATTERN] native host: reload ロック保持中に hooked API を呼ぶと self-deadlock（実機検証で発見・修正済）

**症状**: host.dll 注入後、breadcrumb が `hooks.ok` で停止し `logic.ok` 以降が出ない。nrs.exe 本体は別スレッドゆえ生存継続（即クラッシュせず）。cdb のモジュールロード情報で logic_live.dll はロード済＝LoadLibrary 成功と確認。

**根本原因**: `reload_load_initial` が `g_logic_lock` を **exclusive 保持**したまま logic の `bind()`→`patches_apply()`→`host_log()`→`fopen("nrsedge.log")`→**CreateFile（host がフック済）**→`h_CreateFileW` を呼ぶ。フック detour が**同一スレッドで `g_logic_lock` を shared 取得**しようとし、SRWLock は非再帰なので **exclusive 自己保持中の shared 要求＝self-deadlock**。

**修正**: `bind()` は **ロックの外**で呼び、`g_logic_lock` exclusive は **g_api/g_logic_mod のポインタ swap の一瞬だけ**に限定（`src/host/reload.c` の `do_load`）。これで bind 内の hooked API（logging 等）が安全に shared ロックを取れる。
**教訓**: host のフックは g_logic_lock(shared) を取る。**そのロックを exclusive 保持したまま logic コードを実行しない**（logic は hooked API を呼びうる）。reload の重い処理（load/bind）はロック外、swap だけロック内。

---

## [OPEN] device-presence エラーシーン残留（0903/8006/1000…）

Symptom: HLSM は stable attract(state0, 数千 tick, 再ブート無し)に到達するのに、画面に device エラー
シーン(Error 0903 Wrong Region / 8006 / 1000 等)が**1つ貼り付いて消える前提が崩れる**ことがある。
**latch する errNo は run ごとに変わる**＝latch は「最初に立った errCode」のレース。

**実測ステータス（2026-06-28, 深刻度=間欠・低頻度）**: `tools/runtime/frida_diag/error_scene_probe.js`（描画 choke
point `error_scene_render` 0x6f2730 を attach）を連結し **6 連続 headless run（1×90s + 5×22s）でサンプリング → 全て
clean attract、`error_scene_render` の呼出は 0 回、REGION_CHK 全 PASS errCode=0、ERRCODE latch 無し**＝本ビルドで
**非再現**。既知 fix（region errCode store NOP 0x459109/0x45A846・board-index 0x45A0F9・USB I/O errCode 0x6F0B80）が
効いている。残るレース（おそらく 0x14 network 早期 or cold-start 依存）は低頻度。probe は常設 diag として残し、
再現時に caller backtrace で dispatch 元を即捕捉する（`--diag tools/runtime/frida_diag/error_scene_probe.js`）。
→ 修正設計（(C) 案）は **repro を 1 件捕まえてから**着手（B1 の教訓＝供給元を推測で当てない）。

Root cause（2026-06-28 再導出・実体検証済）: 起動初期に errCode 0xa(board-table)/0x4(region)/0x14(network)
が `amlib_master_errCode`(0x16f5af0) へ latch する。**latch の正体は `if(amlib_master_errCode==0) =X` ガード＋
native に per-tick クリアが存在しないこと**（クリアは init の `amlib_reset_init`(0x6c35c0) のみ＝1 ブートで最初に
立った errCode が次の reset まで固着）。`amlib_master_errCode` は別 global ではなく **0x16f5a80 amlib 構造体の +0x70
フィールド**。描画の choke point は **`error_scene_render`(0x6f2730)**＝記述子 param を読む（**+0x0c=メッセージ ptr /
+0x10=errNo(%04d) / +0x16=flags(bit2=Caution)**。ptr==0 なら "Unknown Application Error"/1000）。この関数は
**直接 xref が無く関数ポインタ(scene テーブル)経由で登録**され、scene-SM から dispatch される。
errCode→errNo→記述子の橋渡しは**ポインタ相対アクセス**で行われ DAT_016f5af0 の直接 xref に出ない。
※ 旧記述の「builder `FUN_00489130`」は誤り（実体は `autoscene_builder`＝汎用シーン compositor で error 専用でない）。
※ `amlib_subsystem_state==8` は新規エラーを latch せず `DAT_01698ec8|=0x800` で抑止する（state 0xd/0xe も bypass）
＝error 供給側(`usbio_errCode_mapper`/`keychip_errCode1_latcher` 等)に共通のゲート。
**8006 を正しく直して amNet が native 解決(ret=0)しても device-scene は消えない**＝latch は amNet の成否と独立
（最初に立った errCode が固着、underlying PASS でも記述子が残る）。
8001(network) の underlying: `FUN_006fe040` が `DAT_016019a6`(ip_match) 真を要求。ip_match=`(mask&ip)==(ref&mask)`
（ref=`DAT_0160198a`）。nic IP は query_nic_status 応答の inline 解析で ctx+0x3c へ入る（`boot/mxnetwork/FACTS.md`）。

**次の一手（具体）**: 静的は関数ポインタ越えで止まるので、**runtime で `error_scene_render`(0x6f2730) を
Interceptor.attach し `Thread.backtrace` で caller(scene-SM)＋param_1(記述子)の出所を特定**する（B1 の教訓＝
推測で橋渡し関数を当てない）。choke point が 1 関数(0x6f2730)に集約されている利点を使い、scene-SM 側で
attract 到達後に error scene の dispatch を抑止する((C) 案)のが本命。setter 個別 NOP は供給源が多く非効率。

### errCode latch 機構（root cause）
各 setter は `if (DAT_016f5af0==0) { =X }`＝**最初に立った errCode が latch して固着**。
実機 latch 観測=0xa→0x4→0x14。

⚠️ **訂正（2026-06-28, B2 再検証で発覚）**: 旧記述は「`FUN_006c35c0` が DAT_016f5af0 を毎 tick =0 クリアする
watchdog」としていたが、decompile で否定。**`FUN_006c35c0` は `amlib_reset_init`＝init 時の初期化ルーチン**
（`_memset(&DAT_016f5a80,0,0x9c)` ＋多数の init 呼び出し）で毎 tick の watchdog ではない。さらにこの memset は
0x16f5a80..0x16f5b1c を一括クリアし、**`amlib_master_errCode`(0x16f5af0) は別 global ではなく 0x16f5a80 構造体の
+0x70 フィールド**。よって「display struct 側はクリアしない／master は毎 tick クリア」という旧モデルは少なくとも
init 時点で成立しない。**追加調査で確定: native に per-tick クリアは存在しない**（DAT_016f5af0 の WRITE xref は
全て setter の `=X` か init の `=0` のみ。`=0` を毎 tick 行う native 関数は無い）。旧モデルが言う「毎 tick クリア」は
実は **region.js の Frida `setInterval(250ms)` watchdog**（`va(0x16F5AF0).writeU32(0)`）を native と取り違えたもの。
従って native の latch は単純に「最初の errCode が次の reset まで固着」。**handled errCode の fix は各サブシステム
モジュールの `patch()`**（一覧 `tools/static/patch_audit.py`）、各 setter 関数は要時 Ghidra `search_decompiled` で
再導出する（正は実装）。描画 choke point と次の一手は上の Root cause 参照。
- **0xa board-table**(`FUN_00679cb0`)= **解消済**。board index `DAT_01601953` を 2 に固定（`devices/presence.js`
  patch `0x45A18E`）して table[2]=8 を満たす＝値供給。setter NOP ではなく入力を正す方式（`FUN_006c5470` の
  0x11/0x1e も同時解消）。詳細 `devices/FACTS.md`。
- **0xd=`FUN_0045a320` / 0xe=`FUN_004591b0`** = setter は `if(DAT_016014a4)` でゲートされ、amHmInit 失敗
  （HW モニタ不在→flag=0）で経路ごと無効化＝**現構成では発火せず**（要対応外）。
- **未対応（要時 setter を NOP）**: 0x18=`FUN_0050a340`。

deterministic fix の2案: (A) latch する setter の `DAT_016f5af0 = X` を NOP 化（suppress）。(B) DAT_016f5af0 を**毎フレーム 0 に
保つ高頻度 watchdog** で scene-SM が error を「見ない」ようにする（低リスク。要 scene-SM が errCode を毎
フレーム読む前提の検証）。(C) scene-SM の error 分岐 reader を特定して patch（最も確実だが要 RE）。

⚠️ **訂正（2026-06-28, B2 再検証）**: 「FUN_0089a010 の setter を NOP すると stable attract を壊す恐れ」は
**バイトの取り違え**だった。decompile で確定（`amlib_init_sm_SYSTEM_STARTUP` 0x89a1c5/0x89a28a/0x89a3ed/0x89a5ec）—
4 つの errCode write は全て `if(amlib_master_errCode==0){=X} *(param_1+4)=9;` の形で、**device/network チェック
失敗時のエラー分岐**にあり `state=9` 遷移と同居する（正常進行は state 5→6→7/8→10）。よって `=X` のバイトだけ
NOP しても **`state=9` 分岐は残る＝SM はエラー状態へ進む**。NOP は**破壊的ではなく無効**（attract は壊れないが
何も直らない）。真に load-bearing なのは setter ではなく **`state=9` 分岐（別バイト）と上流の device/network gate**。
従って (A) を FUN_0089a010 に適用するなら setter ではなく state=9 分岐を対象にする必要があり、それは gate skip で
リスクが高い → このループでは (B)/(C)（display-struct latch 側）を優先するのが妥当。
⚠️ いずれも stable attract（既達）を壊さないこと。検証は `screenshot_window.py` 実写必須。

**方針**: TeknoParrot 方式＝**チェック無力化(A)に統一**する（TP は dongle/mxkeychip/region
検査をフックで通過させる＝データを正そうとしない）。data-write+watchdog で「データを正す」アプローチは、
正規の供給源が無い値（PcbRegion 等）では timing-fragile になり display-snapshot を取り逃す。
latch コード（0xa board-table / 0x14 network 等）は
順次 setter NOP 化して watchdog 依存を外す。**ただし FUN_0089a010 内の write は state=9 分岐と同居するため
setter 単独 NOP は無効**（上記 B2 訂正）。0x14 network はこの SM 内（LAB_0089a3e4）なので display-struct 側で対処する。

---

## [RISK] JVS 入力注入: ネイティブ JVS 経路の再駆動は禁止（amjvs/input.js）

**症状**: `amjvs/input.js` 初版は poll_state(`va(0x16B7EA0)`)を毎フレーム再アームし、amlib リーダ
3 関数（0x988390/0x9884F0/0x9885E0）を onLeave で成功扱いにして `jvs_inner_input`(0x67B3A0)→
`jvs_credit_handler`(0x67B450) のネイティブ JVS 経路を毎フレーム走らせた。結果、resume 約 5–6 秒後に
WerFault 起動＋`NtTerminateProcess code=0xC0000096`(STATUS_PRIVILEGED_INSTRUCTION) でクラッシュ
（attract 到達前）。coin フック単体を外しても再発。

**根本原因**: ネイティブ JVS **ハードウェアポーリング経路全体**（poll_state 再アーム＋amlib リーダ3関数の
強制成功）を毎フレーム再駆動したこと。その結果として inner_input 以降の native 経路へ不正な状態を流し込み、
attract 到達前にクラッシュした（精密な crash site は未特定）。

⚠️ **訂正（2026-06-28, B1 再検証）**: 旧記述は crash を「`FUN_0097db80`(credit dispatch) が billing
オフラインで未初期化コールバックへ jump」と帰属させていたが、**これは実装で否定された誤り**（嘘のブロック要因）。
Ghidra 再導出（`FUN_0097db80`/`0097d320`/`0097d900`/`0097da50`）で確定:
- `FUN_0097db80` は完全ガード — init 未了(`DAT_01288550==0`)で `-3` return、index 範囲チェック、
  `(&DAT_012885a4)[i]!=0`（=**カウント値**、関数ポインタではない）を確認してから**固定**関数を呼ぶ。
  「未初期化コールバックへ jump」する経路は存在しない。privileged 命令を踏む箇所も無い。
- credit 経路の実体は **amCredit**（`DAT_01288550` ブロック、init=`amCreditInit` 0x97D320＝freeplay.js が hook 済）。
  これは **ALL.Net Plus billing(alpbEx 0xA065C0) と独立**で、billing をオフラインにしても正常 init する。
  「billing オフライン衝突」は**カテゴリ錯誤**（alpbEx と amCredit の混同）。
- 教訓（メタ）: crash を隣接コードへ憶測で帰属させ、n=1 の事故を「coin は billing オンライン化まで不可」という
  恒久ルールへ過一般化していた。crash site は実測で特定してから帰属させること（正は実装）。

**解決**: ネイティブ JVS 経路を**一切再実行しない** direct-write 方式へ変更。jvs_update_main(0x67B150)
onEnter で入力を poll し JVS node BSS（switch +0x643../analog +0x648..）を直接書くだけ。app 側の入力読取
（root-scene→usbio_jvs_io_update→FUN_0067b860/6e0/620）が node BSS を直接デコードするため、poll_state や
inner_input を触らずに入力が反映される（probe `tools/runtime/frida_diag/jvs_input_probe.js` で裏取り）。
ビット/analog 配置は FUN_0067b620/6e0 のデコードで確定（sys bit7=TEST, +0x643 bit7=START …, analog 中心
0x8000）。**教訓**: ネイティブ JVS **ハードウェアポーリング経路**を入力注入のために再駆動しない（direct-write で足りる）。
coin/credit は **billing にブロックされない**（上記訂正）。現状未実装なのは native リーダ経路を state.js が
失敗扱いにして credit_handler が走らないため＝**未実装であってブロックではない**。実装するなら amCredit
カウンタへの direct-write か、credit dispatch（ガード済で安全）を限定的に駆動する。当面は FreePlay=1 で不要。

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

---

## [RISK] patches.c 0x457AF0（delete_directory_recursive 無効化）は撤去禁止

`src/logic/patches.c` の `{0x457AF0, RET0, ...}` は、注記が「keychipSM state4 crash helper」だったが誤りである。
実体は `delete_directory_recursive`(0x457af0) の無効化で、RET0 でこの関数を即 0 返しにし、ゲームによる実ディレクトリの再帰削除を阻止している。

**何を阻止しているか**: `keychipSM_FSM`(0x457910) は case 4 で appdata 不一致のとき `delete_directory_recursive(DAT_01265904, 1)` を呼ぶ。
`DAT_01265904` は実行時に設定されるアプリデータ・ディレクトリのパス。
削除は `DeleteFileA` とサブディレクトリ再帰で行われ、不可逆である。

**削除が発火する条件**（keychipSM_FSM case 4 を実体で導出）:

    削除発火 ⟺ format∈{4,5} ∧ DAT_016014b0==0 ∧ DAT_01601b23≠0 ∧ DAT_016014af==0

**各ゲートの standalone 値**（setter を Ghidra で実体トレース）:

- `appdata_gameid_region_match`(DAT_016014b0, setter `amlib_storage_init_all` 0x4597c0)：`=!(保存gameID=="SBVA" ∧ region一致)`。エミュ EEPROM は 0xFF 初期化（`src/logic/driver/mxdevices.c` の map_nvram フォールバック）ゆえ gameID≠"SBVA"。初回起動や blank eeprom.bin では必ず不一致になり **b0=0（削除許可側、確定）**。
- `appdata_delete_inhibit`(DAT_016014af, setter `appdata_delete_flags_init` 0x45a1f0)：billing/network チェック（FUN_0097dca0/0097f5a0/0097f780）が全成功し local_4==1 のときだけ 1。standalone は billing offline ゆえ **af=0（削除許可側）の公算が高い**。
- `keychip_appdata_delete_gate`(DAT_01601b23, setter `keychip_appdata_delete_gate_probe` 0x45a8f0)：`stat("W:/")` と実行時生成パスの存在、および FUN_00969a00()==0 のとき 1。**静的には確定できない**。値が実行時のファイルシステム状態に依存し、加えて当該関数の decompile は std::string デストラクタ（FUN_00a74f0a）が "does not return" と誤マークされて制御フローが壊れている。

**撤去が危険な理由**: 削除ブランチの入口（b0==0）は standalone で確定的に開く。
残る安全弁は b23 一つだが、その値は実行時 FS 依存で静的に保証できない。
W: ドライブや当該パスが存在すれば b23 が 1 になり、削除が実走しうる。
device presence パッチ（951/8001/8005 等）とは種類が違う。
あれは状態の偽装（read を固定）で、エミュが実状態を供給すれば冗長化する。
本パッチは削除という行為の阻止であり、エミュが供給できる代替が存在しない。

**撤去してよい唯一の条件**: keychipSM が standalone で常に case 4 から state 5（フォーマット、削除回避）へ進む、すなわち b23 が常に 0 だと実測で確認できた場合に限る。
確認には keychipSM_FSM の case4/state5 遷移と b23 をランタイムでログ化する。
それまでは保持する。

**リスク非対称**: 撤去して誤れば代償はアプリデータの不可逆削除、得るものは no-op パッチ 1 件の削減。
この非対称だけで保持が正当化される。
