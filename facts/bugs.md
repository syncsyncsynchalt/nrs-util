# Bug Catalog — Live (OPEN / RISK / ANTI-PATTERN)

`## [STATUS] SYMPTOM` — OPEN|RISK|ANTI-PATTERN のみ。解決済 FIXED は `git log`。

---

## [ANTI-PATTERN] ストリーミング serial device: TX=1B/WriteFile, RX=cbInQue ゲート
COM1 touch handshake 未完(touch.read=0 / touch.write=0 で state 0x32 固着 mode0)。根因(実体 RE):
1. RX ポンプ `serial_rx_pump`(0x67C0C0) は `ClearCommError` の cbInQue!=0 のみ ReadFile。stream device は CLEAR_ERROR で COMSTAT 0 化すると cbInQue=0→ReadFile 永久不着。**常に 1 フレーム受信待ちと cbInQue 申告**せよ。
2. TX フラッシュ `serial_tx_flush`(0x67C070, thread `serial_tx_thread` 0x67C1A0) は TX リングを **1B ずつ WriteFile**。`on_write_file` を 10B 一括前提で書くと n=1 で ack ゼロ。**バイト蓄積→同期ヘッダ始まりの固定長フレーム組立**(`TouchPanel.rx[]`/`rx_len`)必須。
教訓: serial transport は RX=cbInQue ゲート / TX=バイトストリーム。JVS(master 駆動 1write=1frame)を流用不可。効かない時はまず touch.read/write の hex を見る。

## [ANTI-PATTERN] loader dual-mode 化後の「クラッシュ」誤診
`loader.exe <path>` は unknown verb で何も起動しない(2026-06-29 dual-mode 化: 引数なし=GUI / 引数=CLI verb)。正=`loader.exe start --wait=N --freeplay 0 --game-dir DIR`。nrs:0 を即 inject crash と帰属せず `nrsedge.log` 有無・loader stdout を先に見る。host.dll は loader cwd(nrs-util) と nrs cwd(bbs) 両方に配置。

## [ANTI-PATTERN] デバイスエミュ: IOCTL ハンドシェイクだけ通すとデータ面欠落で I/O 全滅
`amBackupRecordRead/WriteDup: error` 洪水。amBackup 記録は board type 3 で 2 デバイス分割(area0,1=EEPROM/mxsmbus, area2,3=SRAM/mxsram; mxdrivers.md)。`amSramInit`(0x986380) は PING/geometry/sector IOCTL のみで成功し flag=1 にするが、記録 R/W 実体は **SetFilePointer(0xADC178)+ReadFile/WriteFile**(worker 0x985bc0/0x985c80)。データ面未エミュだと init 通過でも R/W 全失敗。修正: host が SetFilePointer フック(ABI v4 `on_set_file_pointer`)→`mxdev_seek/read/write` が `nvram.bin` mmap backing で授受。GET_SECTOR_SIZE=RINGEDGE2=4。SRAM 4 record は 512B/512 境界ゆえ sector size は洪水と無関係。教訓: デバイス=制御面(IOCTL)＋データ面(R/W/Seek)の二層、両方を実体(nrs 呼出＋mxsram.sys IRP)で裏取り。

## [ANTI-PATTERN] host reload: lock 保持中に hooked API を呼ぶと self-deadlock（修正済・fix は src に在）
`reload_load_initial` が `g_logic_lock` exclusive 保持のまま `bind()`→…→`CreateFile`(host フック済)→detour が同一スレッドで shared 取得を試み、SRWLock 非再帰ゆえ self-deadlock(breadcrumb `hooks.ok` で停止)。fix=`reload.c do_load`: bind はロック外、exclusive は g_api/g_logic_mod ptr swap の一瞬のみ。**教訓: 重い load/bind はロック外、swap だけロック内(logic は hooked API を呼びうる)**。

---

## [OPEN] device-presence エラーシーン残留（0903/8006/1000…）
Symptom: stable attract(state0, 数千 tick)到達なのに device エラーシーン(0903 Wrong Region / 8006 / 1000 等)が 1 枚貼り付く。latch する errNo は run ごと変化=「最初に立った errCode」のレース。**間欠・低頻度**(既知 fix が効き現ビルドで概ね非再現、残るレースは 0x14 network 早期 or cold-start 依存疑い)。

Root cause: 起動初期 errCode 0xa(board-table)/0x4(region)/0x14(network) が **`amlib_master_errCode`=0x16f5a80 構造体 +0x70(=0x16f5af0)** へ latch。各 setter は `if(amlib_master_errCode==0){=X}`＝最初の errCode が固着(実機観測 0xa→0x4→0x14)。**per-tick クリア無し**(WRITE xref は全て setter=X か init=0)。クリアは init の `amlib_reset_init`(0x6c35c0, `memset(&DAT_016f5a80,0,0x9c)`) のみ。
描画 choke point = **`error_scene_render`(0x6f2730)**: 記述子 param `+0x0c`=msg ptr / `+0x10`=errNo(%04d) / `+0x16`=flags(bit2=Caution)。ptr==0→"Unknown Application Error"/1000。**直接 xref 無し**(関数ポインタ=scene テーブル経由登録、scene-SM から dispatch。橋渡しは ptr 相対で DAT の直接 xref に不出現)。
- `amlib_subsystem_state==8` は新規 latch せず `DAT_01698ec8|=0x800` で抑止(state 0xd/0xe も bypass)=供給側共通ゲート。
- **8006 を直し amNet が ret=0 でも device-scene は消えない**=latch は amNet 成否と独立。
- 8001 underlying: `FUN_006fe040` が `DAT_016019a6`(ip_match) 真要求。ip_match=`(mask&ip)==(ref&mask)`(ref=`DAT_0160198a`)。nic IP は query_nic_status 応答 inline 解析で ctx+0x3c(mxnetwork.md)。

各 errCode(handled fix は `src/logic/patches.c` 静的パッチ、setter 関数は要時 `search_decompiled` 再導出):
- **0xa board-table**(`FUN_00679cb0`)=解消済: board index `DAT_01601953`=2 固定(patches.c/dipsw, 0x45A18E)で table[2]=8 供給(setter NOP でなく入力を正す。`FUN_006c5470` の 0x11/0x1e も同時解消; devices.md)。
- **0xd=`FUN_0045a320` / 0xe=`FUN_004591b0`**: setter は `if(DAT_016014a4)` ゲート、amHmInit 失敗(HW モニタ不在→flag=0)で経路無効=現構成で不発。
- **未対応**(要時 setter NOP): 0x18=`FUN_0050a340`。

**FUN_0089a010(`amlib_init_sm_SYSTEM_STARTUP`, setter 0x89a1c5/0x89a28a/0x89a3ed/0x89a5ec) 内 setter 単独 NOP は無効**: 4 write は全て `if(errCode==0){=X} *(param_1+4)=9;` 形で device/network 失敗分岐にあり `state=9` 遷移と同居(正常=state 5→6→7/8→10)。`=X` NOP でも state=9 分岐が残り SM はエラーへ。load-bearing は setter でなく **state=9 分岐＋上流 device/network gate**。0x14 network はこの SM 内(LAB_0089a3e4)。

**方針**: TP 方式=チェック無力化(A)に統一(data-write+watchdog は正規供給源無き値=PcbRegion 等で timing-fragile)。ただし FUN_0089a010 内 write は state=9 同居で単独 NOP 無効ゆえ 0x14 等は display-struct 側で対処。deterministic 案: (A)setter `=X` NOP / (B)errCode を毎フレーム 0 保つ watchdog / (C)scene-SM の error 分岐 reader を patch(最確実・要 RE)。**⚠️ stable attract を壊すな、検証は GUI スクショ必須**。
**次の一手**: 静的は関数ポインタ越えで止まる→**runtime で `error_scene_render`(0x6f2730) を host hook し caller 戻り番地＋param_1(記述子)を JSONL 化し出所特定**(cdb bp+kb 可)。choke point 1 関数集約の利点で attract 到達後 dispatch を抑止((C))が本命。repro 1 件捕獲後に着手。

---

## [RISK] ネイティブ JVS ハードウェアポーリング経路の再駆動は禁止（旧 Frida input.js の教訓）[F]
旧 input.js(Frida) が poll_state(`va 0x16B7EA0`) 毎フレーム再アーム＋amlib リーダ3関数(0x988390/0x9884F0/0x9885E0)を onLeave 成功扱いにし native JVS 経路(`jvs_inner_input`0x67B3A0→`jvs_credit_handler`0x67B450)を毎フレーム走らせ、resume 5–6 秒後 `NtTerminateProcess 0xC0000096`(PRIVILEGED_INSTRUCTION) crash(attract 前, coin フック外しても再発)。根因=ポーリング経路全体の再駆動で inner_input へ不正状態流入(精密 crash site 未特定)。
crash は credit dispatch と無関係(実体確定): `FUN_0097db80` は完全ガード(init 未了 `DAT_01288550==0` で -3, index/`(&DAT_012885a4)[i]!=0` チェック後に固定関数 call。未初期化 jump も privileged 命令も無し)。credit 実体=**amCredit**(`DAT_01288550`, init `amCreditInit` 0x97D320)で alpbEx billing(0xA065C0) と独立=オフラインでも正常 init。
**解決(現行方針)**: native 経路を一切再実行しない **direct-write** 方式。`jvs_update_main`(0x67B150) onEnter で入力 poll し JVS node BSS(switch +0x643../analog +0x648..)を直書き。app 側 read(root-scene→usbio_jvs_io_update→`FUN_0067b620/6e0/860`)が node BSS を直接デコードするため poll_state/inner_input を触らず反映。bit/analog 配置は 0067b620/6e0 decode で確定(sys bit7=TEST, +0x643 bit7=START…, analog 中心 0x8000)。当面 FreePlay=1 で coin 注入不要。

---

## [ANTI-PATTERN] python.exe Windows Store alias
`python.exe`/`python` は Store stub→exit 49 "Python was not found"。フルパス `%LOCALAPPDATA%\Programs\Python\Python313\python.exe`。

## [ANTI-PATTERN] args[1] as bufLen in platform/dongle hooks
amPlatformGet*/amDongleGet* の args[1](bufLen) はスタックゴミ。無視し `writeUtf8String()` か安全な hardcode max を使う。

## [ANTI-PATTERN] HLSM case=7 の side-effect で fast-advance が race → crash（旧 Frida-era, 現 native impl には無し）[F]
`hlsm_boot_network_sm`(0x457FE0) case=7 は counter/`FUN_006FF650` 判定前に `param_1[1]=1`("P-ras active" フラグ)を書く。JA at **0x4581DE**(counter 閾値スキップ)を NOP すると初 tick で state=7→8 に同 tick 進行し param_1[1]=1 のまま別スレッドが out-of-band 観測→crash(WerFault/err.log)。**教訓: case body に他 subsystem が観測する side-effect あり、fast-advance は race。JA 0x4581DE を NOP するな**。安全 bypass(Frida-era) は onEnter で param_1[0x18]=8 を書き case=8 直行、case=7 body 回避。位置: 0x4581AF(case7 開始)/0x4581B6(param_1[1]=1)/0x4581DE(JA=NOP 禁止)。※現 native logic に該当 hook は無し=歴史的注意。

---

## [RISK] patches.c 0x457AF0（delete_directory_recursive 無効化）は撤去禁止
`patches.c {0x457AF0, RET8_0, 5}` = `delete_directory_recursive`(0x457af0) を即 0 返しにしゲームの実ディレクトリ再帰削除を阻止。**スタブは `ret 8` 必須**: 0x457af0 は `__thiscall(this,arg1,arg2)`=callee-clean で 8B を `ret 8` 掃除(実体: 末尾 0x457fd1 RET 0x8 / call 元 0x4579F4 に add esp,8 無し / 自己再帰 0x457DE3 同様)。bare `ret`(31 C0 C3) だと 8B 残りスタック破壊→発火時 crash。正=`RET8_0`(31 C0 C2 08 00)。amDongleBusy(0x975E00) が bare `RET0` で正しいのは引数 0 だから=ret 即値は関数ごと実体確認。
**何を阻止**: `keychipSM_FSM`(0x457910) case4 で appdata 不一致時 `delete_directory_recursive(DAT_01265904,1)`(実行時設定 appdata パス, `DeleteFileA`＋再帰、不可逆)。
**発火条件**(case4 実体): `format∈{4,5} ∧ DAT_016014b0==0 ∧ DAT_01601b23≠0 ∧ DAT_016014af==0`。
- `DAT_016014b0`(setter `amlib_storage_init_all` 0x4597c0)=`!(保存gameID=="SBVA" ∧ region 一致)`。エミュ EEPROM は 0xFF 初期化(mxdevices.c map_nvram fallback)ゆえ gameID≠"SBVA"→初回/blank で必ず不一致 **b0=0(削除許可, 確定)**。
- `DAT_016014af`(setter `appdata_delete_flags_init` 0x45a1f0)=billing/network(FUN_0097dca0/0097f5a0/0097f780) 全成功時のみ 1。standalone は billing offline ゆえ **af=0(削除許可)公算高**。
- `DAT_01601b23`(setter `keychip_appdata_delete_gate_probe` 0x45a8f0)=`stat("W:/")`＋生成パス存在＋`FUN_00969a00()==0` で 1。**静的確定不能**(実行時 FS 依存, decompile は std::string dtor `FUN_00a74f0a` の "does not return" 誤マークで制御フロー破損)。
**撤去危険の非対称**: 削除入口(b0==0)は standalone で確定的に開き、残る安全弁は b23 のみ(実行時 FS 依存で静的保証不能。W: 存在で b23=1→削除実走)。device presence パッチ(read 固定=状態偽装、エミュ供給で冗長化)と種類が違い、削除阻止はエミュ代替が存在しない。**撤去可の唯一条件**: keychipSM が standalone で常に case4→state5(削除回避)=b23 常に 0 と実測確認できた時のみ(keychipSM_FSM case4/state5 遷移と b23 を runtime ログ化)。誤撤去の代償=appdata 不可逆削除, 得るもの=no-op パッチ 1 件削減。保持。
