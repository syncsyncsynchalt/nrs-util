# STATUS — 現在地と次の一手

## フェーズ: ★パッチ監査（presence 詐称の冗長化）— device emu 完成で 25→23 — 2026-06-30

**鉄則「パッチ原則ゼロ」の前進**: touch/card が「presence 詐称のみ」→「実 serial protocol emu」へ昇格した結果、
presence 詐称 2 パッチが冗長化したと**Ghidra ＋ 差分ライブテスト（スクショ実証）**で確定し撤去。`patches.applied 25→23`。
- **撤去① `0x4F6310`** IC Card ready(`cardrw_ready_bit1`=card_flags>>1&1): boot state2(`amlib_init_sm` 0x89a010)が
  `!=0` を無期限ポーリング。card.c の実 handshake が card_flags bit1 を立てるので詐称不要。
  実走: **"CHECKING IC CARD R/W … OK"→attract 到達**(5101 不在)。
- **撤去② `0x8B3B00`** Touch status(`touchpanel_status`=ctx+0x18): handshake 完走で game 自身が `FUN_008b2ad0`
  default case で `ctx+0x18=1`("touch panel ok.")を立てる。boot state3 が `!=0` を無期限ポーリング＝詐称不要。
  実走: **"CHECKING TOUCH PANEL … OK"→attract 到達**(5501 不在)。
- **保持判定 `0x6F0B80`** USB I/O board errCode(951): `usbio_board_count`(0x16b88dc)は vtable USB 列挙(`FUN_0067cbe0`)
  で検出＝**COM4 JVS emu と別経路**ゆえ standalone で count=0。撤去すると boot が **Error 0910(Wrong Resolution Setting)で停滞**
  し attract 不達（実証）。シリアルエミュで冗長化しない read-fake＝**保持**。
- **検証手法**: `loader.exe start --wait`＋プロセス内蔵 GL キャプチャ(`capture.req`→`capture.png`)で SYSTEM STARTUP の
  device チェック行と最終 attract を直接確認。ログ event(mmgp.diag 等)は boot 進行を正確に表さず誤判定の罠＝**スクショが正**。
- 監査の網羅: 残り 20 パッチ（billing/dongle/network/region/storage/no_selfshutdown/COM4 名/`0x457AF0` action-block）は
  対応サブシステムのエミュ未完 or action-block ゆえ非冗長（`facts/workflow.md`「read-fake と action-block の区別」）。

---

## フェーズ: ★COM2 カードリーダー = SEGA独自 IC Card R/W 確定 + bring-up 足場 — 2026-06-30

**COM2 の素性を Ghidra 実体 sweep で確定**: 従来 facts が「Aime」と記していたが、nrs.exe に `Aime`/`felica`/`IDm` 文字列は
**ゼロ**。自称 "IC Card R/W"、`.?AVJcvCard@@` はゲームデータ class（HW無関係）。実体 = **SEGA 独自 bare-byte
command/ACK シリアル（checksum無, 8E1/9600）**。Aime/FeliCa ではない。詳細・コマンド表は `facts/devices.md` §カードリーダー。
- **既存 DB バグ修正**: `cardrw_ready_bit1/rw_error_bit4/device_status_ptr` を `0x8f…`→`0x4f…`（4↔8 transposition）に訂正。
  `data/known_names.json` に card プロトコル関数 28 個追記（opcode builder/ACK表/status decode/容量map/FSM）。
- **方針確定 = 仮想カード永続 R/W**（UID+データブロックの仮想カード, card.bin 永続化。TeknoParrot 流）。
- **Phase A done + live 検証成功**（`src/logic/driver/card.{h,c}` + api.c 配線）: COM2 を `0xC0114003` で仮想化し
  byte-exact handshake を実装。`loader.exe restart --wait` で実走 → **handshake 完全動作**:
  `f7→0a` / `68 06 40→0a`(`FUN_00884f40(6,0x40)`) / `68 01 dc→0a` / `48→0a` が実機で成立、
  **`phase=ready` / `subsys.card=ok` / `card.read` 発火** ＝ COM2 が実プロトコルで認識され boot 通過。
  - フレーム = `[ACK b0][status b1][payload]`、再同期なし。半二重 turnaround を opcode 長テーブルで実装。
    request/response ゆえ CLEAR_ERROR の `cbInQue=card_rx_pending()`（応答がある時だけ）。
  - **TX framing 実測確証**（推定→確定）: **0xF7=1B（trailer 無し）**, 0x68=3B(`FUN_00884f40`固定), 0x48=1B。
  - init SM = `card_init_handshake_sm`(0x670f70): case10→f7, case0xC→`68 06 40`, case0x10→0x48、成功で
    `DAT_016ae538=1`(device found)→substate10。transport pump=`card_transport_pump`(0x674530):
    case1=init(0x670f70)/case3=poll-read(`FUN_00671470`)/case5=write(`FUN_00671de0`)。
- **Phase B1 done + live 検証成功（operational init 完走）**: 実走で init 最終段 **`b8 cf`（0xB8 SET COMM SPEED）** を
  ACK `0a` → **`[game] card slot ok` 発火**＝カードリーダー init が実プロトコルで完全完了（touch の「touch panel ok」相当）。
  - **0xB8 確定**: `card_cmd_setspeed_0xB8`(0x884ff0) が `B8 CF`(2B) 送出、ACK 0x0A(len1)→`card_apply_baud_setcommstate`(0x67c4c0)が
    SetCommState、latch `DAT_012658c8=1` で以後再送なし。card.c: cmd_len(0xB8)=2 / 応答 `0A`。
  - **present/absent 極性を実体で確定**（`card_status_decode` 0x66f8a0 + `FUN_008850c0`）: **ACK 一致(byte0=期待ACK)→present、
    nocard=単バイト `5A`('Z')**。frame 長は `card_frame_len_for`(0x8848d0) 表（再同期なし）。
    旧 Phase A の nocard `0B 5A…` は present 誤認だったと判明し `5A` 単体に修正（実装前に RE で捕捉）。
  - read SM 全フロー確定: `card_read_sm`(0x671470) reset→sense(28)→search(4D)→[present: select(2D)→read(0D×N)→commit(AD)]→halt(38)。
- **Phase B2 ブロッカー特定（真の上流 = MMGP ネットワーク play-session, 2026-06-30）**: attract→credit→card-auth は **card でも
  alAbEx auth でもなく MMGP ハンドシェイク**が gate（詳細 `facts/gameflow.md`）。credit scene(`credit_touch_scene_update` 0x5eaae0)は
  `mmgp_task_update`(0x6f3b40)経由で advance し、(1)`mmgp_input_service_gate`(0x89e930): `DAT_0227fe6c & 0x400` set/0x100/0x200 clear ＋
  `DAT_0227fe70 & 4`、(2)MMGP txn result==2（'E'/0x45 net-reception タスクの 0x2206 応答, `mmgp_txn_result` 0x562c80）、
  (3)`DAT_016b8b6b`(coin lockout)=0 を要求。
  - **実機検証**: alAbEx auth flags 強制(`api.c network_auth_force_ready`)→ `subsys network:ok` にはなるが **attract→credit 開通せず**＝
    alAbEx は scene gate ではないと確定。touch も既知 blocker だったのは `DAT_0227fe6c` を touch/JVS が供給する経路ゆえ。
  - **次（P5 network 層）**: `DAT_0227fe6c|=0x400`＋`DAT_016b8b6b=0`＋**MMGP txn を成功させる**（'E' タスク 0x2206 応答 or txn `+0x1ac=2`）。
    開通すれば credit→card-auth→**card SEARCH(0x4D)** が走り、下記 card data 層を live 検証可。
- **Phase B card data 層（MMGP 開通後）**: present=1 で poll に `0B`+8B UID record（byteswap 順 live 確証: UID=DAT_0169e314/type=DAT_0169e31c）
  ＋0D ヘッダ(2B+128B, UID@+0x04 BE)＋容量分の data＋0xAD write＋`card.bin` 永続化（logic から直接 Win32 file I/O, abi 不変）。

---

## フェーズ: ★★★タッチパネル(COM1)完動化 + プロセス内蔵 GL キャプチャ枠組み — 2026-06-30

**COM1 タッチパネルを serial プロトコルで完全エミュ・実走検証済み**（`src/logic/driver/touch.c` + api.c 配線）。
詳細は `facts/devices.md` §タッチパネル。boot まで段階的に3層解決して到達:
1. **EEPROM SetupDi 修正**（`bugs.md`/`api.c eeprom_force_ready`）で amBackup -3 洪水(14044件)停止 → attract 到達。
2. **ClearCommError cbInQue 修正**: serial RX ポンプ`FUN_0067c0c0`は `cbInQue!=0` のみ ReadFile。touch handle の
   CLEAR_ERROR で `cbInQue=10`(常に1フレーム受信待ち)を申告 → ReadFile 発行 → 'T' ストリーム開始。
3. **★核心: TX フラッシュは 1 バイトずつ WriteFile**（`FUN_0067c070`, SerialThread `FUN_0067c1a0`）。`touch_on_write`
   が 10B 一括前提だったので n=1 で ack ゼロ → handshake が +0x28=0 で timeout → state 0x32 固着。
   **修正＝バイト蓄積→'U'始まり10Bフレーム組立**（`TouchPanel.rx[]`）→ 'p'/'P' に 'P'(byte3=6) ack。
   **live: handshake `present=1/mode=1/hs=0` 完了・「touch panel ok.」発火**。bypass(+0x2b8 注入)は不要化・撤去。
   touch-active = status byte `+0x166 & 3`、押下エッジ→`+0x210[0]`（`FUN_008b3310` mode1 処理）。
   **`touch.event` で `active=1 status=1 edge=1 x234=507(中央)` の完全シーケンス取得＝押下・座標・離し全て正常**。

**プロセス内蔵 GL フレームキャプチャ**（`src/host/capture.c`, gdiplus/opengl32 link）: 外部 CopyFromScreen は窓遮蔽・
GL backbuffer 非取得・Get-Process 間欠失敗で不安定だった。host が SwapBuffers/wglSwapBuffers をフックし、cwd の
`capture.req` 検知で `glReadPixels`(GL_BGRA)→GDI+ で `capture.png` 原子保存（alpha は 0xFF 不透明化）。
**テスト枠組み `tools/test/touch_test.ps1`**（ASCII のみ。PS5.1 が UTF-8 BOM無しを CP932 誤読し parse 失敗するため）:
`-Action shot`(capture.req→png) / `coin -N` / `touch -X -Y -HoldMs`(client比率) / `info`。窓は EnumWindows で title='WGL'。

**残課題（touch 自体は完動）**: attract「画面をタッチしてください」を touch しても scene が進まない（`touch.event` は
発火するが card/login/scene msg 無し）。BBS はカードベースで touch 後に **Aime カードリーダー(COM2/class 0x21)** を
要求するが COM2 は presence 詐称のみ・実 I/O 未エミュ。**次=COM2 card reader emulation**（touch と同様 serial protocol。
COM2=SEGA独自 IC Card R/W と確定済・上記最新フェーズ参照）。
診断ログ（touch.diag/serial.diag/touch.event/touch.write）は api.c に残置（card 作業で有用。不要なら間引き可）。

⚠️ **loader.exe は dual-mode 化済み**（2026-06-29）。起動は `loader.exe start --wait=N --freeplay 0 --game-dir DIR`。
旧 `loader.exe <nrs-path>` は "unknown verb" でゲーム起動せず（「クラッシュ」と誤認しやすい）。host 変更時は host.dll を
**nrs-util(loader cwd, inject 元) と bbs(nrs cwd, logic ロード元) 両方**へ配置。logic のみなら bbs へコピーで hot-reload。

---

## フェーズ: ★パッチ削減（OS 境界エミュ化）+ 自律テスト起動法の確立 — 2026-06-29

**ゲームメモリパッチ削減**: `patches.applied count 29→25`（4 byte-patch 撤去）。鉄則「パッチ原則ゼロ＝OS 境界で仮想化」へ前進。
全てライブ確認済み（host.ready→安定 attract、errCode 0 件）:
- **platform "AAL"** (0x981FF0): columba DMI(`mxdevices.c build_dmi`)が OEM 文字列 index2="AAL" を供給済み＝冗長。
- **dipsw board index** (0x45A0F5/F9): `dipsw_force_ready`(`api.c`) が dipsw ctx を H_MXSMBUS で provision し、read の mxsmbus IOCTL(`mxdev_ioctl` cmd5, index0=0x20)へ流す。素の `amDipswRead` が board index 2 を算出。
- **OsVersion** (0x981D60): 仮想ファイル `C:\System\SystemVersion.txt`(`api.c` on_create_file/on_read_file)で 8 バイトを供給。
- 定石・詳細: `facts/workflow.md`「パッチ削減の定石」/ `facts/amplatform.md` / `facts/devices.md`。

**自律テスト起動法を CLI 化（2026-06-29）**: `loader.exe` を **dual-mode** 化。引数なし=従来 GUI、引数あり=ヘッドレス CLI。
`start --wait` / `stop` / `restart` / `status` / `wait --event` / `logs --cat|--subsys|--grep|--tail` を **JSON on stdout + 機械可読 exit code** で提供（旧 PostMessage ハック廃止）。
host が `host_log` 全イベントを観測し **`nrsedge.status.json`**（phase / errors / patches / subsys ready）を原子更新（`src/host/status.c`。abi 不変・logic 無改変）。
1 ショットで起動到達点が判る。`build host loader` 通過・read-only verbs ライブ確認済。手順は `facts/workflow.md`「自律ゲームテスト」。

**残りパッチ（高コスト・別タスク）**: network(amNet SM 解決 or NIC エミュ) / dongle・card・touch(新規デバイス protocol) /
billing(ローカル ALL.Net) / region(amJvsp keychip txn) / no_selfshutdown(action-block)。network は bugs.md [OPEN] の独立 latch が絡む。

**横断知見をプロジェクトメモリへ集約**: 旧ユーザー単位メモリ（起動法/RE方法論/パッチ削減/清書/移植）を `facts/workflow.md` へ移管。

---

## フェーズ: ★★ATTRACT 安定到達（クリーン起動・実機確認）+ GUI コントロールパネル完備 — 2026-06-28

**運用知見**: nrs.exe を**手動起動しない**（必ず統合 GUI「▶起動」= in-process 注入経由）。
手動起動は二重起動 / keychip ポート(40100..40113)競合でゲームが数秒で終了する。クリーン起動なら attract 安定。
**統合 GUI**: `src/host/loader.c`（native Win32・Python 不要。`loader` ターゲットを cmake build → `build/Debug/loader.exe`。
旧 control_panel.exe + 旧 loader.exe(CLI) + 旧 run.ps1 の inject/tail を一本化）= 起動(in-process 注入)/終了/再起動・FreePlay/TEST/Windowed・
入力設定/テスト（GUI 直接ポーリングでゲーム不要）・ログ（ts/色分け/フィルタ/検索/I-O抑制/JSONL書出）。設定は nrsedge.cfg → host。

**= 過去 Frida 実装の boot-critical 全サブシステムを native 化し、実機で attract まで到達。end-to-end 検証成功。**
次の目標: attract → ゲーム開始（入力検証 + コイン + **タッチパネル**）。

**ライブ検証 OK**: 統合 GUI の ▶起動（= in-process 注入。`loader.exe` は引数を無視するので注入は必ずボタン経由。
自律実行は `facts/workflow.md` 参照）で `nrsedge.log` に
`host.attach→patches.applied→logic.bind→logic.ok→gamehooks.ok→keychip.server.up→windowed.hooks→host.ready`
が全て出力、nrs.exe 実行継続（ユーザー確認「動作しています」）。patches.applied の count はパッチ撤去で変動（現在 25。2026-06-29 時点）。
発見・修正したバグ: **reload ロック保持中の hooked API self-deadlock**（`facts/bugs.md` 参照。`do_load` で修正）。
デバッグ手法: breadcrumb で `hooks.ok`→停止を特定 → cdb のモジュールロードで logic_live ロード済確認 → コード解析で deadlock 断定。

**移植台帳: `facts/port_status.md`（旧 boot 全モジュール → native の欠落ゼロ追跡）。**
追加移植: keychip PCP サーバ(`host/keychip_server.c`) / mxdrivers(`logic/driver/mxdevices.c`: columba DMI=RINGEDGE2 +
mxsram/mxsuperio/mxsmbus eeprom) / amplatform(AAL) / freeplay / keychip present hold / windowed。**全ビルド通過。**
残り(非 boot-gating): rtc / getstatus 動的 / mxgfetcher recv / client.js pcpaOpenClient(server 稼働で不要かも) / region 条件 hook。

旧 Frida 実装は破棄済み。native C（host + reloadable logic）へ完全移行。**全ターゲットがビルド通過**。

### 完了
- **P0 RE 帯**: `facts/`(旧 FACTS 保全) / `data/known_names.json`(serial/transport 追記) / `ref.md` /
  COM map・kdserial・JVS=COM4・columba=DMI 反映。drift 訂正済み。
- **破壊的移行**: 旧 Frida 製品・旧ツール・docs・captures 削除。RE エンジン/知見は保全。
- **骨格 + ビルド検証**:
  - `cmake -B build -G "Visual Studio 17 2022" -A Win32` 構成 OK（MSVC x86 検出）。
  - **`logic.dll` / `host.dll` / `loader.exe` 全てビルド成功**。
  - **MinHook を `third_party/minhook` に vendor**（host が link）。
- **JVS フレームエンジン** `src/logic/driver/mxjvs.c`（micetools `jvs_base.c`+`jvs_837_14572.c` を lift）:
  RESET/ASSIGN_ADDR/READ_ID/GET_*_VERSION/GET_FEATURES/READ_SW/READ_COIN/READ_ANALOG/GPIO/COIN_DECREASE、
  マスク/エスケープ/チェックサム/複数コマンド対応。READ_ID/GET_FEATURES/READ_SW(入力反映)/
  複数コマンドを実装。
- **COM4 シリアル傍受**を `src/logic/api.c` に配線（CreateFileA/W→sentinel、Write→frame→Read で応答）。
  host hook は CreateFileA も対応（nrs は A 版で COM4 を開く）。
- **P3 入力層**: `mxjvs_set_input`（論理入力→JVS 13bit sw / analog ch1=X ch0=Y / TEST / coin エッジ。
  bit 配置 facts/devices.md 準拠）+ `input.c`（GetAsyncKeyState ポーラ、既定バインド）。api.c が
  Write 毎に poll→set_input。sw/analog/coin マッピング実装済み。
- **旧 impl 静的パッチ全移植** `src/logic/patches.c`: ambilling/amdongle/amjvs(forgery)/devices(board index
  0xa/0xb・touch/card presence)/mxnetwork/mxsegaboot/mxstorage/region/mxgfetcher の**全静的バイトパッチ +
  node/region データ書込み**を `patches_apply()` が bind 時に nrs.exe へ適用。**全ビルド通過**。
  ＝旧 impl の「attract 到達」静的基盤を native で再現。詳細・残り動的分は `facts/port_status.md`。
- **game-function hook 機構** `src/host/gamehook.c`（reload-safe: detour=安定 host／logic=g_api 経由）。
  第一利用として **amjvs/input.js を移植**: `on_jvs_tick`(jvs_update_main PRE→node BSS 直書き) +
  `on_sys_override`(dipsw read 後/sysinput 前→DAT_0160194c TEST/SERVICE 上書き)。全ビルド通過。
- **amplatform/identity**(patches.c: "AAL"/"WindowsXP") + **freeplay**(on_jvs_tick 内 per-frame) +
  **keychip present hold**(on_keychip_hold game-fn hook 0x6F0A80) 移植。
- **keychip PCP サーバ** `src/host/keychip_server.c`（旧 pcpa_server.py 移植・winsock 7 ポート・
  認証バイパス code=54・mxmaster/amNet/billing 応答。host 常駐 reload-safe）。**全ビルド通過**。

### 次の一手（P2 ライブ統合 — 実機が要るためここから手動/対話）
1. **`loader.exe start --wait` で実起動検証**: `host.dll` 注入 → JSONL ログで `jvs.open(COM4)` と
   `amJvspInit` が **state 偽装無しで正規 init** するか確認（旧クラッシュ誤診の最終クローズ）。
2. **overlapped シリアル対応** ← 最重要未解決。nrs の JVS poll スレッド(`jvs_poll_thread` 0x9896C0)は
   **overlapped ReadFile/WriteFile + event 待ち**。現状 api.c は同期完了で返すため event が signal されず
   **poll が止まる恐れ**。OVERLAPPED 経路（event signal / 即時完了の作法）を実機で詰める。
3. **フレーム組立**: 現状「1 write=1 frame」を仮定。nrs が分割 write する場合は host 側でバッファリング。

### ロードマップ
P2(JVS ライブ) → P3 入力(KB/XInput→`mxjvs` の sw/analog) → P4 driver(columba/dipsw/touch/card) →
P5 system(keychip in-proc/network) → P6 crackproof + 実起動(touch) → P7(任意) 配布。

### 未確定（facts/ 参照）
overlapped シリアルの作法 / COM2 device protocol / kdserial 設定元(`DAT_01696ad4`) /
R-GRIP rate 入力源 / touch screen protocol / CrackProof 干渉範囲 / micetools が BB を実起動できるか。

### ビルド/反復メモ
- 反復（人間）: VSCode タスク「👤 ビルドして GUI を開く」（build→GUI 起動）。反復（自律）: `loader.exe start --wait`/`status`/`stop`。logic 変更は host が auto-swap（再起動不要）。
- MinHook は vendor 済（`third_party/minhook`、`.git` 除去）。`build/` 等は `.gitignore` 済。
