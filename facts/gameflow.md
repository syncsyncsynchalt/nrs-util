# ゲーム flow FACTS — attract → credit → card-auth の scene 連鎖と gate

このサブシステムの事実（scene/task 機構・遷移 gate）。索引 `_index.md` / 横断 `workflow.md`。
confidence: [S]=静的解析 [L]=ライブ実走 [I]=推論

---

## 概要: 「attract から進まない」真の正体 = MMGP ネットワーク play-session [S+L]

boot は attract（FREE PLAY「画面をタッチしてください」）に到達するが、**タッチしても credit/card-auth へ進まない**。
touch device も card reader も完動（"touch panel ok" / "card slot ok"）。**真のブロッカーは MMGP ネットワーク・ハンドシェイク**
（matching/play-session）で、card でも alAbEx keychip auth でもない（2026-06-30 実機検証で確定）。

## scene/task 機構 [S]

- **task list `DAT_016db564`**（= `g_amTaskList_head`, device list と同一）: 各ノード 0x5c B。
  `+0`=tid / `+4`=uid(tag) / `+8`=flags(&3=active) / `+0x10`=per-task ctx / `+0x3c`=next。
  registrar=**`amTaskOpen`(0x89dcb0)** `(tid,uid,ctxSize)`。tag 例: 0x21=card / 0x45('E')=network-reception / 0x50474d4d("MMGP")。
- **scene 選択は scene-id global ではない**（訂正・PROVEN）: `DAT_016b8b54` は **`amlib_subsystem_state`**（keychip/usbio 状態、
  `==8`=keychip-ready。`keychip_errCode1_latcher`0x6f0a80 / `usbio_errCode_mapper`0x6f0ae0 が同名で読む）であり requested_scene_id ではない。
  0xD4B000 は state-string jump table（3 slot のみ）で scene ctor 表ではない。
- scene 本体は **vtable/RTTI ベース**: credit scene `credit_touch_scene_update`(0x5eaae0)=vtbl 0xbb358c /
  card-auth `cardauth_netentry_scene_update`(0x5e6200)=vtbl 0xbb34c4（RTTI@0xca9318）。`scene_list_lifecycle_update`(0x89d830)が
  node-id 0x21 の render-node リストを tick。**遷移は scene SM 内部**（下記 MMGP）＋ `param_2` 出力構造体(`+0x134`=done)で駆動し、
  scene-id global の書込みでは起きない。
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

## 未解決（要 RE）= attract demo → credit/entry scene の活性化

attract demo browser と credit/card-auth scene を切替える**上位 scene manager**が未特定。これが credit scene を active にすれば
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
