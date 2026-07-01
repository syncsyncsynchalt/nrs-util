# ゲーム flow FACTS — attract → credit → card-auth の scene 連鎖と gate

このサブシステムの事実（scene/task 機構・遷移 gate）。索引 `_index.md` / 横断 `workflow.md`。
confidence: [S]=静的解析 [L]=ライブ実走 [I]=推論

---

## 概要: 「attract から進まない」真の正体 = MMGP ネットワーク play-session [S+L]

boot は attract（FREE PLAY「画面をタッチしてください」）に到達するが、**タッチしても credit/card-auth へ進まない**。
touch device も card reader も完動（"touch panel ok" / "card slot ok"）。**真のブロッカーは MMGP ネットワーク・ハンドシェイク**
（matching/play-session）で、card でも alAbEx keychip auth でもない（2026-06-30 実機検証で確定）。

## scene/task 機構 [S]

- **task list `DAT_016db564`**（= `g_amTaskList_head`, device list と同一）: 各ノード 0x5c B（stride 0x17 int）。
  `+0`=tid / `+4`=uid(tag) / `+8`=flags(&3=active,&4=remove) / `+0x10`=per-task ctx / `+0x14`=ctxSize / `+0x3c`=next。
  registrar=**`amTaskOpen`(0x89dcb0)** `(tid,uid,ctxSize)`（逆コンパイルで裏取り: `*node=tid; node[1]=uid; node[2]=3`）。
  - **uid はゲーム公認の FourCC タグ [S]**: amTaskOpen の重複 open 警告が `amDebugOut("...uid=%08x(%s)...", uid, &str)` で
    uid を**4バイト ASCII（低位バイト順）として文字列化**（`DAT_02283014=uid&0xff`…）。∴「uid をタグ文字列で読む」のはゲーム本来の規約。
    tag 例: `0x50474d4d`="MMGP"（mmgp_diag がこの uid でライブ walk）/ `0x45`='E'=network-reception / `0x21`,`0x21`=card（tid==uid, devices.md）。
  - 計装 `api.c scene.delta` は uid を生 hex(`tag`)＋FourCC(`tag4`)の両方で出す（`scene_tag_fourcc`）。
    ※EntryMode scene 個々の uid は **未裏取り**（生成元コード未特定。実値は出るが意味付けは未確定）。
- **scene 選択は scene-id global ではない**（訂正・PROVEN）: `DAT_016b8b54` は **`amlib_subsystem_state`**（keychip/usbio 状態、
  `==8`=keychip-ready。`keychip_errCode1_latcher`0x6f0a80 / `usbio_errCode_mapper`0x6f0ae0 が同名で読む）であり requested_scene_id ではない。
  0xD4B000 は state-string jump table（3 slot のみ）で scene ctor 表ではない。
- scene 本体は **vtable/RTTI ベース**で、各 scene は **nrs.exe 埋め込みの実 C++ クラス（RTTI 有）**。
  task node の update slot(+0x24) に入る VA = その scene クラスの **vtable slot#2（仮想メソッド）の生アドレス**。
  ∴ update VA → vtbl base(=slot#2 addr − 8) → vtbl[-4]=COL → COL+0x0c=TypeDescriptor → TD+0x08=mangled name で実名確定。
  **entry flow scene の実クラス名（nrs.exe 直読で裏取り, [S]）**:
  | update VA(slot#2) | 実 RTTI class | COL | vtbl base | 旧RE名 |
  |---|---|---|---|---|
  | 0x5eaae0 | `EntryModeGamePoint` | 0xca9318 | 0xbb3584 | credit_touch_scene_update |
  | 0x5e6200 | `EntryModeCheckCard` | 0xca9538 | 0xbb34bc | cardauth_netentry_scene_update |
  | 0x5e90b0 | `EntryModeNameEntry` | 0xca94a0 | 0xbb34ec | — |
  | 0x5e8710 | `EntryModeSelectChara` | 0xca94ec | 0xbb34d4 | — |
  | 0x5eb000 | `EntryModeDotNetRegist` | 0xca92cc | 0xbb359c | — |
  | 0x5ec340 | `EntryModePassword` | 0xca9234 | 0xbb35cc | — |
  | 0x5eb6b0 | `EntryModeReIssue` | 0xca9280 | 0xbb35b4 | — |
  | 0x62fb50 | `EntryModeBase`(基底) | 0xca9584 | 0xbb34a4 | — |
  - ⚠️ **訂正**: 旧記述「card-auth=vtbl 0xbb34c4（RTTI@0xca9318）」は取り違え。0xbb34c4 は **vtbl base ではなく slot#2 のアドレス**
    （base 0xbb34bc + 8）。かつ 0xca9318 は **credit(EntryModeGamePoint) の COL**であり card-auth ではない。card-auth の COL は 0xca9538。
  - **継承の罠**: `EntryModeRegist/UpdateBase/UpdateCard/VersionUp` は slot#2 を override せず **0x5ea0a0 を共有**（基底の update）。
    ∴ update VA だけでは一意化不可。実行時 obj の vtable→RTTI 読みが要る。
  - `attract_scene_lifecycle`(0x7274d0) / `net_session_task_sm_on_touch`(0x6f42c0) は **C++ scene クラスでない素の task callback で RTTI 無し**
    ＝実名が存在しない（`api.c scene_va_name` は捏造せず生 VA で出す）。
  - `scene_list_lifecycle_update`(0x89d830)が node-id 0x21 の render-node リストを tick。**遷移は scene SM 内部**（下記 MMGP）＋
    `param_2` 出力構造体(`+0x134`=done)で駆動し、scene-id global の書込みでは起きない。
  - 計装: `api.c scene_diag` の **`scene.delta`** が active(va,tag) 集合を毎フレーム diff し、各 node を上表の実クラス名(`cls`)で出す
    （未解決 VA は `cls:null`＝生 VA で次の RTTI 解析対象）。
- ※dispatcher 領域 0x6f06e4–0x6f0a7f は Ghidra 未解析 raw（要 GUI force-disassemble、MCP 不可）。本 flow には不要。

## attract→credit 遷移 gate（PROVEN）

credit/touch scene = **`credit_touch_scene_update`(0x5eaae0)**。state1 で:
```
mmgp_request_start(0x6f3f20);        // subobj+0xd=1（start 要求）
if (mmgp_read_start_accepted(0x6f3f60) != 0) { credit_commit_pending(0x774f40); local_f=1; }  // advance
```
`mmgp_read_start_accepted` は MMGP タスク sub-object の `+0xc` を返す。これが 1 になるのは **`mmgp_task_update`(0x6f3b40)** が:
```
6f3bce: CALL mmgp_txn_result(0x562c80)   ; = msg+0x1ac（network txn 結果）
6f3bd6: if (result == 2) [subobj+0xc] = 1 ; ← play-start 受理エッジ（毎フレーム +0xc=0 クリア）
```
state0→2 へ進むには `mmgp_input_service_gate`(0x89e930) が true である必要。

### gate 一覧（すべて満たす必要）[S]

| gate | global(static_VA) | reader | 必要値 |
|---|---|---|---|
| 入力/サービス | **`DAT_0227fe6c`** (`g_jvsInputServiceBits`) | `mmgp_input_service_gate`(0x89e930) | **bit 0x400 SET**, bit 0x100/0x200 CLEAR ＋ (`DAT_0227fe70 & 4` or `DAT_02282a64+2 & 1`) |
| coin lockout | **`DAT_016b8b6b`** (`g_coinLockoutFlag`) | `credit_coin_accept_check`(0x50a2b0) | **0** |
| MMGP txn 結果 | message `+0x1ac` | `mmgp_txn_result`(0x562c80) | **== 2**（'E'/0x45 network-reception タスクが 0x2206 に応答）|
| 'E' net task | tag 0x45 ノード | `mmgp_net_task_ready`(0x562e70) | ノード present＋ctx 有効 |
| credit init | `DAT_01288550` (`g_amCreditInitFlag`) | `amCreditGetState`(0x97cf80) | 非0（free-play で OK）|
| free play | `DAT_0128855a` (`g_freePlayFlag`) | 同上 | 1=playable 返す（メッセージのみ・遷移は別）|

- `DAT_0227fe6c` は JVS 入力/sensor status 語（**"CARD IN"=&0x8000** と同じ語、JUMP/DASH/ACTION bit も同居。
  writer=mxsensor/JVS service-state 0x89b6bd/0x8a04b0 系）。bit 0x400 = サービス/入力 present 相当。
  → **touch device が known battle-start blocker だったのと整合**（touch/JVS がこの語を供給する）。
- MMGP cmd word: **0x2101**=idle/keep-alive open、**0x2206**=commit/start-with-credit（`mmgp_net_send_msg` 0x562aa0 経由で 'E' タスクへ）。

## credit→card-auth 連鎖（INFERRED, 強支持）

credit advance（`param_2+0x134=1`）→ dispatcher が次 `DAT_016b8b54` を書き factory が **`entry_card_auth_scene`(0x5e6200)** を生成。
card-auth は class(0x21,0x21) カードオブジェクトの flag(+4 bit10/bit11)＋`FUN_004f2d20`(seated) で駆動し、
`FUN_00562aa0(..,6,0x21101,10)`（cmd 0x21101=card search/read）で **card SEARCH(0x4D) を発火**。
`DAT_016b8b6b`(offline/maintenance) != 0 だと card-auth は short-circuit。

## alAbEx keychip auth は scene gate では「ない」[L]

boot network SM `hlsm_boot_network_sm`(0x457fe0) は alAbEx auth flags（`DAT_0210AED0/AED2/AED4`, `DAT_0210B508`,
`DAT_016019A5/A6`）を要求するが、これらは **credit/MMGP 遷移経路に一切現れない**（PROVEN by absence）。
実装 `api.c network_auth_force_ready` でこれらを強制→ **subsys `network:ok` にはなる（boot 前提条件）が、attract→credit は開通せず**
（2026-06-30 実機）。⇒ **真の gate は `DAT_0227fe6c & 0x400` ＋ MMGP txn 結果**であり alAbEx auth ではない。

## 経験的検証（2026-06-30, mmgp_diag 計装で確定）— **停止点は MMGP より上流**

⚠️ 当初「MMGP txn(0x2206→result2)＝matching サーバが壁」と推論したが、**診断計装(`api.c mmgp_diag`)で誤りと判明**。
`mmgp_diag` は task list を uid "MMGP"(0x50474d4d) で walk し subobj(`*(node+0x10)`)を読む（`mmgp_request_start`/`read` と同一 subobj、検証済）:
- 実機: `gate0x400=1`（**gate は開いている**, 0x100/0x200 clear）, `svc70_4=1`, `lockout=0`, `found=1`,
  **`state=0`, `sub=0`, `req=0`, `accept=0`, `msgres=-2`（txn メッセージ無し）— タッチ後も不変**。
- ⇒ MMGP は state0 で**動かない**。state0→2 は `mmgp_request_start`(0x6f3f20, credit scene が呼ぶ→subobj+0xd=1)が必要だが
  **req=0＝credit scene(`credit_touch_scene_update` 0x5eaae0)が呼んでいない**。state0→1 はタッチ event(mmgp_task_update の DL 引数)だが
  これも 0。`mmgp_net_task_ready`(0x562e70)は 'E' タスク不在なら **0 を返す＝state0 通過を許可**（塞いでいない）。
- ⇒ **真の停止点 = credit/entry scene が非 active**。ゲームは attract demo browser(`FUN_00725fa0`→`advertise_demo_controller`0x725d60)
  のままで、タッチは demo 循環に消費される（credit/card-auth scene に切替わらない）。MMGP txn も matching サーバも**まだ無関係**。
- alAbEx auth 強制は `network:ok` を出すが scene 遷移には無関係（既述）。MMGP gate 強制(`DAT_0227fe6c|0x400`)は gate を開くが
  state0 のまま無効＋「メンテ countdown」副作用を誘発したため**撤去**（credit scene 活性化後に再検討）。

## 経験的検証その2（2026-06-30, scene_diag 計装）— title scene は demo browser ではない・touch は attract 循環

`api.c scene_diag/scene.list`（task list `DAT_016db564` を walk し各 active node の update slot `+0x24` VA を集計）で実走観測:
- **title 画面("画面をタッチしてください", FREE PLAY)の active scene set ＝ 35 ノードで安定**。
  `attract_scene_lifecycle`(0x7274d0)は **active list に居ない**（attract=0）＝**title scene は demo browser(0x7274d0)とは別物**（当初仮説を訂正）。
  active list に同居: card `cardrw_ctx`(0x4f2930) / `touch_poll_update`(0x8b2750) / `mmgp_task_update`(0x6f3b40) /
  boot SM `amlib_init_sm`(0x89a010, attract 後も常駐) など。credit(0x5eaae0)/card-auth(0x5e6200)は **未生成（seen=0）**。
- **touch すると**（`touch.event active=1 status=1 edge=1 x234=507`＝押下完全到達）: active set が変化し
  **`net_session_task_sm_on_touch`(0x6f42c0, MMGP/network session を vtable 駆動する state0-5 SM)＋thunk 0x4026f0 が spawn**。
  だが **credit/card-auth は依然未生成**。画面は **attract demo の別ページへ循環するだけ**（背景変化, 「画面をタッチしてください」継続, スクショ実証）。
- ⇒ **FREE PLAY でも touch でゲーム開始しない**。touch は attract demo を循環させ network keep-alive task を起こすのみ。
  credit scene は生成されない＝**開始 gate は上流の ALL.NET/MMGP ゲームサーバ接続**（STATUS の「ALL.NET GAME SERVER 未完了・
  【全国対戦受付終了】」と整合）。matching/credit サーバが「セッション開始可」を返すまで title から進めない。

## ★EntryMode scene factory を特定（2026-07-01, gameflow フロンティア前進）[S]

credit/card-auth 等の EntryMode シーンを生成する factory ＝ **`entrymode_scene_factory`(0x5ec6e0)** `(mgr, sel)`:
- `sel`(0..10) でシーン選択生成: **0=card-auth(`EntryModeCheckCard_ctor` 0x5ec9b0)** / **1=credit(`EntryModeGamePoint_ctor` 0x5eca20)** /
  2=0x5eca80 / 3=0x5ecb00 / 4=EntryModeRegist / 5=EntryModeUpdateCard / 6=0x5ecba0 / 7=0x5ecc10 / 8=0x5ecc70 / 9=EntryModeVersionUp / 10=null(exit)。
- `param_1`=entry-mode マネージャ ctx（`+0x5c4`=現シーン状態 id、`DAT_00bb30e8[sel]` が state-id）。生成シーン `puVar4[1]=mgr`。
- **★呼び出し元が逆コンパイル C に一切現れない＝間接呼び出し**（マネージャの vtable slot 経由でポインタ格納。`get_xrefs_to`/`search_decompiled` とも 0）。
  ∴「上位 scene manager」＝この factory を持つ **entry-mode マネージャ**で、**sel を進める条件が attract→credit/card-auth の真の gate**。
- 次の一手: entry-mode マネージャ object の生成元と vtable を特定（factory ポインタ格納先）。マネージャの update が
  前シーンの done/next 出力で sel を進める SM のはず。**間接 dispatch ゆえ live トレース(cdb で 0x5ec6e0 に bp→戻り先 stack)が最短**だが、
  headless boot は ~50% で attract 手前停滞するフレークがあり（下記「headless 限界」）GUI/実機トレース向き。

## headless 自動テストの限界（2026-07-01 実測）[L]

attract→card-select の**自動到達**を headless で試みた際の実測制約（card 反映修正の検証とは別）:
- **boot フレーク ~50%**: host.ready 後 attract まで進む run と、tick ループに入らず停滞する run が混在（scene.diag=0・device read 0）。
  ゾンビ/ポート競合は無し。CREATE_NO_WINDOW で入力/レンダーループが GUI と等価に回らないのが疑い。
- **touch device が attract で未 poll**: headless では COM1 read が 0〜2 回に留まり touch handshake が mode1 に達しない run が多い
  （touch.diag present_18=0）。∴ `nrsedge.touch.json` タッチ注入(下記)は 'T' フレームを送出できてもゲームが消費しない場合がある。
- ⇒ **完全自動の attract→card-select 到達は現状不可**。card 反映の**機構**（presence/read/whitelist 受理）は headless で検証済みだが、
  **シーン到達**は GUI（実窓・実タッチ）が確実。

### headless タッチ注入ツール（`nrsedge.touch.json`, api.c touch_control_poll）[L]
`{"press":0|1,"xm":<0..1000>,"ym":<0..1000>}` を書くと logic が COM1 'T' 経路へ注入（前面窓/カーソル非依存）。
touch が poll される run では `touch.force`→'T' 送出まで動作。boot フレーク/touch 未 poll のため単体では自動到達を保証しない。

## 未解決（要 RE）= entry-mode マネージャの sel 進行 gate（factory は特定済・上記）

attract demo browser と credit/card-auth scene を切替える上位 = **entry-mode マネージャ**（`entrymode_scene_factory` 0x5ec6e0 を vtable slot に持つ）。これが credit scene を active にすれば
state1 で `mmgp_request_start`→MMGP→card-auth→card SEARCH と進む。次の一手:
- credit scene(0x5eaae0, vtbl 0xbb358c)/card-auth(0x5e6200, vtbl 0xbb34c4) を**生成・active 化する所有者**を特定
  （vtbl への DATA xref、ctor、scene 切替の条件）。これが network/service 状態にゲートされるかは**未確認**（推論しない）。
- ※「MMGP txn/matching サーバが壁」は撤回。停止点は scene 活性化であり、それが network 依存かは未証明。

## 参考: MMGP txn 詳細（credit scene が active になった後に関係する）= 未実装 P5 候補

attract→card-auth 開通には MMGP play-session を満たす必要:
1. **`DAT_0227fe6c |= 0x400`**（bit 0x100/0x200 clear）＋ `DAT_0227fe70 |= 4`（input/service gate を開く）
2. **`DAT_016b8b6b = 0`**（coin lockout 解除）
3. **MMGP txn を成功させる**: 'E'/0x45 network-reception タスクの 0x2206 応答 result=2 を供給（= mmgp_txn_result が 2 を返す）。
   実機相当のローカル matching/credit サーバ応答が要る（P5 network 層）。最小では txn message `+0x1ac=2` を runtime 強制も検討。
→ これが開通すれば credit→card-auth→card SEARCH(0x4D) が走り、Phase B（仮想カード present/read/write）を live 検証できる。
