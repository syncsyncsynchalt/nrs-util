# STATUS — 現在地と次の一手

## フェーズ: ★★カード挿入が反映されない件を解消＝amGfetcher get_status 無限ループ根絶（card_force_present 復帰）— 2026-07-01

**「カードを抜き差ししても反映されない」の真因を live capture で確定・genuine 修正**。カード sel 画面(EntryModeCheckCard 0x5e6200)の
present gate `device_status+0x5628` を供給する `card_force_present`(api.c) が、40113 get_status 無限ループのため無効化されていた。
- **真因（旧仮説を live 実証で棄却）**: 旧記述「PCPP フレーム未成立/raw recv」は誤り。kc.wire 一時計装で 40113 を実測→応答は正常フレームで
  届き**リトライで再接続**していた。実体は **amGfetcher 全応答が `result_field_checker`(0x975140) を通り、`result=0` は
  fall-through で -5（エラー）**＝トランザクション失敗ループ。amInstall は result=success 済だったが **amGfetcher 応答だけ result=0 で残置**。
- **修正（keychip_proto.c・静的パッチ追加ゼロ, patches=15 維持）**: amGfetcher 応答を `result=success` 化。get_status=`status=uptodate`＋
  work_*4 フィールド、resume=`firstreq=0`（parser 0x9746c0 要求・値は nrs.exe 実バイトで "0"/"1" 確定）。
- **ライブ実証**: 40113 が `pause→set_auth_params→resume→isrelease→get_status` を**各1回で settle**（633→1）、errors=0。
  `card_force_present` genuine 復帰＋test card(present=1) 注入下でも **40113 ループ再発なし・`card.force_present`(ds+0x5628=1)発火・
  `card.read` 応答**＝カード挿入検出信号がシーンへ供給される。詳細 `facts/mxgfetcher.md`（Ghidra: result_field_checker/amgfetcher_* 命名済）。
- **次**: GUI で実カード挿入→card-select 画面が「カード使用」を受理するか実写確認（headless では表示検証不可）。UID whitelist(count=0 観測)と
  card data read(0x0D/0x2D)の実挙動＝Phase B card data 層。

### ★続き: attract→card-select 自動到達を試行＝gameflow フロンティア前進＋headless 限界の確定（2026-07-01）
- **EntryMode scene factory を特定**: `entrymode_scene_factory`(0x5ec6e0)`(mgr,sel)` が sel 0=card-auth/1=credit… を生成（`data/known_names.json`・`facts/gameflow.md`）。
  **呼出元は間接**（entry-mode マネージャの vtable slot）＝**sel を進める gate がこのマネージャ内**＝attract→credit/card-auth の真の gate。cdb live トレース向き。
- **headless 限界を実測確定**（`facts/gameflow.md`「headless 限界」）: (a) boot が ~50% で attract 手前停滞（CREATE_NO_WINDOW のループ差）、
  (b) touch device が attract で未 poll になる run が多く（COM1 read 0〜2）注入タッチを消費しない。⇒ **完全自動の card-select 到達は不可、GUI/実機が確実**。
- **headless タッチ注入ツールを追加**（`nrsedge.touch.json` → `api.c touch_control_poll`、COM1 'T' 注入。json 無しでは inert）。card 反映修正は**回帰なし**（Run B で card.force_present 再確認）。
- **card whitelist 確定**: `card_read_sm`(0x671470) は count=0/bypass=1 で全受理（accept-all, standalone 相当）。UID 拒否は count>0 かつ不一致時のみ。

---

## フェーズ: ★EXTEND IMAGE を image-present gate で純正 OK 化＋P_extimg 撤去（patches 16→15）— 2026-07-01

**state5「CHECKING EXTEND IMAGE」を実筐体「イメージ導入済み」境界供給で純正 OK 表示にし、静的パッチ `P_extimg`(0x72B3A0)を撤去**（`patches.applied 16→15`）。
- **真因（Ghidra 実体）**: extend-image install の実体は **ALL.Net 配信タスク**（`NetworkTask_ctor` 0x72b490、install_ctx=`devMgr+0x258`=`field[0x96]`）。
  getter `extend_image_install_status`(0x72b3a0)の state→status マップ消費を boot SM(0x89a4eb)が解す: install 経由で attract に抜ける唯一路は
  **state 0xc=Install Error + error0（"NG"表示のまま前進）**＝旧 `P_extimg`/初回 gamehook と同挙動（STATUS の「EXTEND IMAGE NG は正常」の正体）。**"OK" 純正路は substate1 の
  image-present gate `DAT_01601b23`≠0 skip 枝のみ**（`keychip_appdata_delete_gate_probe` 0x45a8f0 がファイル存在＋検証で立てる本物の gate。"delete" 名は誤導で実体は image-present）。
- **修正（host gamehook・静的パッチ撤去）**: 
  - **primary**: gamehook `d_extimg_gate_probe` が `keychip_appdata_delete_gate_probe`(0x45A8F0, amlib_master_init から call＝SM より前)を **POST** し `DAT_01601b23=1` を force
    → state5 substate1 が "CHECKING EXTEND IMAGE … **OK**"→state6（INSTALLING 行を出さず install 完全 skip）＝TP の extend-image 提供と等価。
  - **fallback（多層防御）**: `d_ext_install_kick`（`extend_image_install_begin` 0x72eaf0 POST）が install_ctx に state=0xc/error0 を provision（万一 gate 経路を通らず install 試行に入っても "NG"だが前進＝旧 P_extimg 相当）。
- **★ライブ実証（スクショ確認）**: SYSTEM STARTUP **全行 OK**（IC CARD/TOUCH/NETWORK/**EXTEND IMAGE OK**/ALL.NET AUTH/UPLOAD/GAME SERVER/LOCAL GAME SERVER）・
  **"NG"/"INSTALLING EXTEND IMAGE" 行ゼロ**・errors=0・patches=15・P-ras 初期化→attract タイトル到達。gate=1 は state1 case1 で extended リソース再ロード(`FUN_007416e0` 列)を誘発するが boot 健全（image-present 時の genuine 挙動）。
- 回帰時は gamehook 2 本撤去＋`patches.c` の P_extimg 復活で即フォールバック。真の install SM 完走（実配信）は ALL.Net 層エミュ＝Phase B2 前提（network status も現状 `0x6FF1B3`/`0x72DCE0` で詐称中）。
- **残 15 パッチ**: keychip-serial region NOP 6・action-block 2（delete_dir/no-selfshutdown）・billing 1・network/region cluster 4（`FUN_006ff900` 束撤去=Phase B2）／infra 1（COM4）／is-DVD 1（撤去不可）。

---

## フェーズ: ★amDongleBusy(0x975E00)を amInstall エミュで純正化（patches 17→16）— 2026-07-01

**残 read-fake の保留候補 `0x975E00 amDongleBusy` を genuine エミュ化して撤去**（`patches.applied 17→16`）。
- **真因**: `amDongle_top_level_init`(0x457500) は **ブロッキング init**（`do{outerSM/keychipSM}while(!=done)`）で、両 SM が
  `amDongleBusy`(=ctx[0xc]=pcpaRecvResponse 未完で busy)を待つ。keychip_server が **amInstall(port 40102)の query に正式応答して
  いなかった**ため SM が完走せず busy のまま＝RET0 が busy を 0 詐称して強制前進させていた（旧 facts「recv-completion gap assert」の正体）。
- **修正（host・静的パッチ追加ゼロ）**: `keychip_proto.c` に amInstall 応答を実装＝`response=<verb>&result=success&status=<S>`
  （FUN_00977d50 が "response" を verb 照合、FUN_009765d0 が result==success 要求）。steer 先（実体確定）:
  query_slot_status=**complete** / query_application_status=**inactive** / query_appdata_status・check_appdata=**error**。
  - appdata=**error(-1)** は 3 consumer の唯一の交差解: keychipSM case3 query が gameid 不要で成功・case4 が format 回避で state7-done・
    appdata task(FUN_00977230)が terminate（0/1/2 は check_appdata⇄query 無限ループ、3/4/5 は format/gameid 一致要求）。詳細 `facts/amdongle.md §amInstall`。
- **実 install(request type 2)は boot 不発ゆえ 40103(未 serve)不要**＝「40103 依存」懸念は誤りと確定。
- **差分ライブ実証**: RET0 撤去後 `errors=0`・SYSTEM STARTUP 全行 OK（EXTEND IMAGE NG は標準筐体で正常）・**"ERROR." 不在**・
  appdata loop 不在（40102 traffic 有界: query 各1-2回）・**attract タイトル「画面をタッチしてください」(FREE PLAY)** へクリーン到達。baseline の
  amHmInit/Region error(01,01,00,05) のみ。一時計装(pcp.io ログ)は撤去済。
- **残 16 パッチ**: 撤去困難9（keychip-serial region NOP 6・action-block 2・billing no-OFF 1）／network/region cluster 4
  （`FUN_006ff900` ALL.Net region で束撤去＝Phase B2）／infra 1（COM4）／is-DVD 1（多重 global 脱結合・撤去不可）。
  read-fake の安い勝ちは取り切った＝次の削減は network/region 層の大仕事。

---

## フェーズ: ★read-fake 再監査 — region DATA-write 0x16014C4 撤去（patches 18→17）— 2026-07-01

**残 read-fake 4個を Ghidra 実体＋差分ライブで再監査し、`0x16014C4`(region_game_pcb DATA write)を撤去**（`patches.applied 18→17`）。
- **撤去（0x16014C4）**: EEPROM STATIC seed（`mxdevices.c eeprom_seed_static`, m_Region@+0x0C=01）が genuine 供給するため
  bind 時 direct-write は旧「直書き」の残置で冗長。bind write は CrackProof clobber されるので実供給は seed が担う。
  **差分ライブ実証**: 撤去後も `Region error (01,01,00,05)` の**第1 operand=01**（region_game_pcb が seed 由来で 01 維持）＝
  direct-write 不在でも genuine 供給される直接証拠。SYSTEM STARTUP "ERROR." 不在で **attract タイトル「画面をタッチしてください」(FREE PLAY)** に
  クリーン到達・errCode カスケード無し（errors=1 は既知良性 app-data。amHmInit failed も baseline）。詳細 `facts/mxkeychip.md`。
- **保持確定（0x4FDA50 is-DVD）**: SYSTEM STARTUP state5 で `FUN_004fda50()`(=`DAT_01696ad8==1||==2`)が true→`+0x1c=0xc`→
  errCode 0xc latch→error state9。`DAT_01696ad8=1`(SERVER ロール兼用 global)ゆえ素では true＝関数 RET0 は多重定義 global の
  脱結合で**撤去不可**（0 を書くと SERVER→SATELLITE 表示破壊。workflow.md）。
- **保留（中〜高リスク, 別タスク）**: `0x975E00 amDongleBusy`＝amInstallInit(40102/**40103 未 serve**)の install SM 完走に依存。
  `0x72B3A0 extend_image`＝state5 case3 で install 状態が complete に達しないと boot hang の恐れ。撤去には serve 拡張/state 解析が要る。
- **残 17 パッチの構造**: 撤去困難9（keychip-serial region NOP 6・action-block 2・billing no-OFF 1）／network/region cluster 4
  （`FUN_006ff900` ALL.Net region 供給で束撤去＝Phase B2 同層）／保留2（amDongleBusy/extend_image）／infra 1（COM4 文字列）／is-DVD 1。

---

## フェーズ: ★★★0951 を keychip PCP 応答で解消 → SYSTEM STARTUP COMPLETE → GP購入画面到達 — 2026-07-01

**951 の genuine 修正に成功し、boot 全 errCode カスケード解消＝attract を越え「ゲームポイント(GP)の購入」画面まで到達**（従来の attract 停滞を突破）。
- **修正 = keychip_server の `keychip.appboot.systemflag` 応答を `00`→`01`（bit0 を立てる）**（`src/host/keychip_proto.c` KC_SYSFLAG）。
  根拠（cdb+Ghidra 実証）: `amDongleSetupKeychip`(0x96d523) case5 が systemflag bit0(`local_c[0]&1`)で `keychip_ctx+0xc=1` を設定
  → `FUN_0096c5f0=(ctx+4 && ctx+0xc)=1` → `DAT_016014a3=1` → `input_update_merge_dinput_jvs` の usbio escape 成立 → errCode 0xf(951) を**未然防止**。
- **メモリポーク無し**（keychip 自前コードが PCP 応答から ctx+0xc を立てる＝鉄則どおり OS 境界エミュ）。DAT_016014a3 は usbio 2 関数のみ READ で副作用なし。
- **error scene は latch 後 errCode クリアでは消えない**（実証済）＝**未然防止が必須**。systemflag 修正は latch 自体を防ぐので scene が出ない。
- **ライブ実証**: keychip_ctx+0xc=1 / DAT_016014a3=1 / amlib_master_errCode=0 / 画面 = SYSTEM STARTUP 全行 OK（EXTEND IMAGE NG は標準筐体で正常）→ COMPLETE → **GP購入画面（FREE PLAY, 260/520/1300 GP, SYSTEM OPERATOR FIONA）**。
- 残ログ error=1 は良性（appdata "Failed to check application data area"）。Region(01,01,00,05) は network region の既知非致命（0x45A846 維持）。
- **クリーンアップ完了・実証**: 951 で無効だった暫定策（d_board_check の usbio count/io_status 供給・d_dinput_create 隠し窓 hook）を撤去。
  撤去後も errCode=0・**SYSTEM STARTUP COMPLETE → WARNING → BORDER BREAK Scramble タイトル/attract「画面をタッチしてください」(FREE PLAY)** まで正常到達を実写確認。
- **現状の genuine 修正（host gamehook + keychip PCP のみ・静的メモリパッチ追加ゼロ・patches=18 維持）**:
  - 0910(board-table errCode 0xa): `d_board_check`(0x679CB0 PRE)が board_index=2 + DAT_0160194c bit0x20=0 供給。
  - 0951(keychip errCode 0xf): `keychip_proto.c` KC_SYSFLAG=01（systemflag bit0）→ keychip 自前が keychip_ctx+0xc=1。
  - dipsw ctx provision: `on_dipsw_provision`(abi v6, dipsw read PRE / amDipswInit POST)＝genuine dipsw device 化。
- **到達点更新: attract タイトル到達**（従来の「attract 停滞」を突破）。タッチ→GP購入画面も確認済（FREE PLAY）。次は実プレイ/入力検証・MMGP play-session（`facts/gameflow.md`）。

---

## フェーズ: ★Error 0951 の真因を動的デバッグで解明＝keychip 層（USB/マウスではない）— 2026-07-01

**実機 cdb で 0951「USB Device Not Found」の正体を確定**: USB/マウスではなく **keychip ctx の +0xc 欠落**。多層連鎖（全て cdb live 確認）:
1. usbio チェック `input_update_merge_dinput_jvs`(0x679de0): **SysMouse は count=1 で genuine 検出済**（dinput.diag 実証。マウスは正常）。
2. だが末尾で `usbio_io_status=-0x70` になる。count>=1 枝の条件 `(1 < DAT_016b88e0) || (DAT_016b88e4 != 1)`。**`DAT_016b88e4` はコードで一度も WRITE されず常に 0**（writer 不在、xref は READ と DATA のみ）＝`(e4 != 1)` 恒真 → iVar2=-0x70。
3. 唯一の escape = `DAT_016014a3 != 0`（`if (DAT_016014a3 != 0 || iVar2==0) skip`）。`usbio_errCode_mapper`(0x6F0AD0) が `io_status` default → errCode 0xf(=errNo 951)。
4. `DAT_016014a3 = FUN_0096c5f0() = (keychip_ctx+4 != 0 && keychip_ctx+0xc != 0)`（FUN_00459220 keychip 成功枝で設定）。
5. **keychip_ctx(live 0x1b43488): +0=1, +4=1, +8=1, +0x10=1, だが +0xc=0**（唯一欠落）→ FUN_0096c5f0=0 → DAT_016014a3=0 → escape 不成立 → 951。
- **実機（実 keychip）は +0xc が立つので 951 不在**。keychip_server エミュは +4/+8/+0x10 まで満たすが **+0xc を立てる1ステップが欠けている**。
- **error scene は errCode クリアでは消えない**（latch 後は事後クリア不可、未然防止のみ有効）を実証（amlib_master_errCode=0 にしても 951 シーン残存）。
- **試行錯誤の記録（いずれも 951 に無効）**: dinput_create_device に取得可能窓供給（hidden window）/ board-check で usbio count=1+io_status=0 供給 / on_jvs_tick で errCode 0xf クリア。真因が keychip_ctx+0xc のため全て的外れだった。
- **次**: `amDongleSetupKeychip` のどの段（どの PCP 応答）が keychip_ctx+0xc を立てるか特定 → keychip_server を補完（genuine に +0xc=1）。`facts/mxkeychip.md` 参照。
- 教訓: errNo 表示名は内部 errCode と無関係（0910=board-table, 951=keychip）。多層依存は cdb live トレースでしか辿れない。

---

## フェーズ: ★Error 0910 の真因を動的デバッグで解明＝board-table errCode 0xa（解像度ではない）+ consumer hook で修正 — 2026-07-01

**実機 cdb 動的解析で 0910「Wrong Resolution Setting」の正体を確定**: 解像度エラーではなく **board-table check の errCode 0xa**。
- **cdb 実証**: error_scene_render(0x6f2730) に bp → descriptor `+0x00=errCode 0xa` / `+0x10=errNo 0x38e(910)` / msgPtr→0xbd04b4("Wrong Resolution Setting")。
  メモリダンプで `board_index DAT_01601953=5`（本来 2）→ `amlib_storage_board_check`(0x679cb0) の `table[5]=0x04≠8` → `amlib_master_errCode=0xa`。SEGA カタログが errNo 910 にこの文言を割当てているだけ。
- **真因**: 標準 PC に mxsmbus PnP が無く amDipswInit が handle=-1。早期 `amDipswRead`→`FUN_009836e0` が handle 無効で書込まず、byte3 が stack garbage 0x5x → board_index 5。
- **dipsw ctx provisioning の前倒し（amDipswInit 0x9842a0 detour, on_dipsw_provision abi v6）は不発**: board_index を確定する最初の read が provisioning より更に前（cdb で dipsw.force_ready 発火時刻 vs board check を実証）。
- **修正（gamehook エミュ・静的パッチ追加なし, patches=18 維持）**: `amlib_storage_board_check`(0x679cb0) を **PRE hook**（`src/host/gamehook.c` d_board_check）し、判定直前に **board_index=2 と DAT_0160194c bit0x20=0 を供給**。dipsw read のタイミングに非依存で errCode 0xa(→errNo 910)/0xb を確実に断つ。旧 dipsw byte patch(0x45A0F5/F9)と同 effect を host gamehook で実現。
- **ライブ実証**: errCode `0xa→0xf` 遷移（latch race で次が surface）＋画面 `0910→0951`。0xa 解消を確認。
- **残: 0951(errCode 0xf, USB Device)** はヘッドレス自律テスト（実マウス/前景 WGL 窓なし→usbio count=0）の fallback（STATUS:951 予告どおり）。実マウス環境では count=1 で非発生。実機検証待ち。
- 関連実装: abi v6 `on_dipsw_provision`（dipsw read PRE / amDipswInit POST で ctx provisioning＝genuine dipsw device 化）+ d_board_check（consumer 供給）。

---

## フェーズ: ★region DATA-write 2個を撤去（genuine 供給で冗長化, patches 20→18）— 2026-06-30

**`patches.applied 20→18`**。region=JAPAN の DATA write `0x1601744`(region_cached)/`0x1601989`(region_dongle) を撤去。
**差分ライブ実証**: patches=20(両 write 有) と patches=18(撤去) で **ログ error 3件・画面とも完全一致**＝撤去でビット等価。
- **撤去根拠（実体 xref+decompile）**: 両 global は game 自身の writer が稼働中エミュから genuine 供給を受ける＝DATA write は冗長。
  - `0x1601989` ← `FUN_00459220` の `FUN_0096f160(&region_dongle)` = keychip `appboot.region` PCP（keychip present 枝。`on_keychip_hold` で presence 維持・`keychip_server` が `=01`）。`amlib_region_gate` が直読み。
  - `0x1601744` ← `FUN_0045acc0` の `DAT_01601744 = DAT_016014c4`（region_game_pcb/STATIC seed=01 のコピー、`amlib_eeprom_ok` 成立時）。
  - **撤去後も `Region error (01,01,00,05)` の第2 operand=region_dongle が 01 維持**＝keychip 供給がライブで効いている直接証拠。
- **`0x16014C4`(region_game_pcb/STATIC) は維持**: anti-tamper `FUN_0048f9c0` の region-index 整合用（gate/anti-tamper 直読み）。
- **`(01,01,00,05)` の第3 operand=00** は ALL.Net network region(`FUN_006ff900`)未供給の**別件**＝`0x45A846` 維持で errCode 抑止（撤去前から同一・非致命）。
- **注意（環境要因）**: 本ヘッドレス自律テストは attract で `Error 0910 Wrong Resolution Setting` を表示するが、**baseline(patches=20)でも同一表示**＝STATUS:951 節の usbio fallback（count=0）で、本撤去とは無関係。実機（実マウス＋表示）では出ない。
- 次の region 削減候補は **ALL.Net network region 層**（`FUN_006ff900` 供給で 0x45A846/0x6FF980/network 0x6FF1B3/0x72DCE0 を束ねる）＝Phase B2 と同層・別タスク。

---

## フェーズ: ★951(USB Device)を実 SysMouse で純正化 — `0x6F0B80` 撤去（patches.applied 21→20）— 2026-06-30

**Error 951 ＝「USB Device」セルフテスト = 実体は DirectInput の SysMouse**（`device2`, GUID_SysMouse）だったと判明。
`usbio_board_count`(0x16b88dc) を +1 するのは `dinput_create_device`(0x67CBE0)＝CreateDevice(GUID_SysMouse)+SetDataFormat(c_dfDIMouse2)+
SetCooperativeLevel(hwnd@0x1696e0c) の成功で、joystick 列挙は count に触らない。
- **ライブ実証（dinput.diag, api.c 計装）**: 開発 PC の実マウス＋WGL ウィンドウ下で `count=1 / mouse 非null / hwnd==FindWindow("WGL")`。
  ＝素の `usbio_errCode_mapper`(0x6F0AD0) が 951 経路に入らない。
- **`0x6F0B80` byte patch を撤去 → restart 後 phase=ready・951/0910 不在・errors=1(既存 app-data のみ)を確認**（patches.applied 21→20）。
  touch/card と同じ「詐称→純正供給」格上げ。詳細 facts/devices.md「USB Device (951)」・facts/amjvs.md「DirectInput 入力系」。
- **fallback**: 真のヘッドレス/マウス無し環境では count=0 で 951 再発しうる → `0x6F0B80` 復活ではなく「前景ウィンドウ＋システムマウス供給」で解く。
- 旧 facts「撤去不可・0910 停滞」は **マウス不在(count=0)前提の旧実測**で、本実証により覆した（訂正済）。
- `dinput_diag`(api.c) は fallback 検知の canary として残置（count=0 が出れば 951 回帰の原因が即判る）。

---

## フェーズ: ★billing パッチ統合 — 23→22（status 5→8 で 0x701280 撤去）— 2026-06-30

**`patches.applied 23→22`**。billing の2パッチを1つに統合（A 統合）。差分ライブ実証済（SYSTEM_STARTUP 完走=scene 稼働, billing/state7 エラー無し）。
- **変更**: `0xA065C0 alpbExGetExecStatus` を **5→8**。status 8 が `alpbEx_billing_poll`(0x7000C0) case8 で `alpbEx_billing_ready=1` を
  game 自身に立てさせる（accounting 開始せず）→ boot SM state7 の `pras_billing_ready_check`(旧 0x701280)が ready!=0 で自然通過 → **0x701280 撤去**。
- **RE 確定（撤去の根拠, facts/ambilling.md）**: `alpbEx_billing_enabled` は無条件 1 で **OFF 経路がコード上存在しない**ため enabled=0 回避は不可、
  ready=1 は poll の status 2/8 のみ（PowerOn から立つ口は無い）。status 8 が3 caller 全てで安全（attract で credit queue 空）。
- **billing path B（TLS server emu, billing メモリ完全無改変）は保留**: 観測スパイク(`src/host/netobs.c`)で **billing は attract で TLS session を
  張らない**（getaddrinfo 後 DNS 失敗、redirect+8443 listener でも connect 無し）と判明＝起動目的に対し過剰。実 credit 計上を配線する段で再評価。
  netobs.c は passive 観測（connect/resolve を log）に戻して残置＝Phase B2 ネットワーク経路調査の診断に有用。

---

## フェーズ: ★パッチ監査の訂正 — 25→23（presence 2 のみ撤去可。region/storage/billing は必須）— 2026-06-30

**重要な訂正**: 先行監査で「25→8（17 個撤去）」としたのは**誤り**。撤去判定基準を「attract 到達」にしたため
**SYSTEM STARTUP 途中の "ERROR." を見落とした**（ユーザー報告で発覚: CHECKING NETWORK OK の直後に "ERROR."、attract には進むが不正）。
真に撤去可能なのは **presence 2 個のみ**（card/touch、実 device emu が置換）＝`patches.applied 25→23`。

**撤去可（presence 2）— 実 device emu が game に presence flag を立てさせる**:
- `0x4F6310`(IC Card ready=card_flags>>1&1) / `0x8B3B00`(Touch status=ctx+0x18)。"CHECKING … OK" 自然通過。boot は `!=0` 無期限ポーリング。

**保持必須（region/storage/billing/network/dongle/USB/action-block）— 撤去で startup に errCode カスケード**:
- これらは独立でなく**連鎖した error 抑止**。`amlib_master_errCode`(0x16f5af0)は**最初の error を latch**するので、撤去すると
  **region(4)→board-index(0xa)→billing(0x15)→… と次々 surface**（devices.md の latch race 警告どおり）。
  実証（計装 boot_diag）: region NOP 撤去→`amlib: Region error (00,01,05)`＝`PcbRegion(0x16014C4)=0`→errCode4。
  これを PcbRegion=1 供給で消すと board-index 0xa(`DAT_01601953`!=2, `amlib_storage_board_check` 0x679cb0)、それも消すと billing 0x15。
- **errCode は非致命**（boot は attract まで進む）が **SYSTEM STARTUP に "ERROR." を表示**＝startup が不正。

**エミュ化を試みた結果（教訓）**: 鉄則どおり「NOP でなくデータ供給」を狙い、`PcbRegion`(基板 region, ゲーム内 writer 無し)を
host から供給しようとしたが **CrackProof アンパックが .bss を再ゼロ化し bind 書込みを clobber**。runtime 供給を試すと
**amlib_master_init(region チェック)より前の決定的 hook 点が無く、on_create_file 供給はファイル open タイミング依存でレース**
（run ごとに errCode 0/4 が振れる）。⇒ 現状クリーンにエミュ化するには **amlib_master_init を gamehook で detour**（host 変更+restart）して
region チェック直前に PcbRegion/board-index を供給する必要がある。**= 別タスク**。それまでは region/storage/billing パッチを保持して startup を正常化。
注: `DAT_01696ad8` は **is-DVD だけでなく筐体ロール(1=SERVER)兼用**＝値変更は SERVER→SATELLITE 表示破壊。多目的 global を安易に書かない。

**教訓（恒久）**: パッチ撤去可否は **「attract 到達」では不十分**。**SYSTEM STARTUP 全 CHECKING 行＋"ERROR." 不在を毎回スクショ確認**する。
errCode latch のため**最初の error が後続を mask**し、attract だけ見ると複数の latch error を見逃す。`facts/workflow.md`「パッチ監査」に反映。

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
  - **scene_diag 計装で形状確定（2026-06-30, `api.c scene_diag/scene.list`）**: title("画面をタッチしてください")の active scene set=35 で安定、
    credit/card-auth は**未生成**。**touch すると `net_session_task_sm_on_touch`(0x6f42c0, network session SM)が spawn するが credit 不生成・
    画面は attract demo 別ページへ循環するのみ**（FREE PLAY でも開始しない）。⇒ 開始 gate は**上流の ALL.NET/MMGP ゲームサーバ接続**。
    attract 命名: `attract_scene_lifecycle`(0x7274d0)/`attract_demo_browser`(0x725fa0)/`attract_exit_input_trigger`(0x728700)。詳細 `facts/gameflow.md`。
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
