# ゲーム flow FACTS — attract → credit → card-auth の scene 連鎖と gate

scene/task 機構・遷移 gate。索引 `_index.md` / 横断 `workflow.md`。[S]静的 [L]ライブ [I]推論。
※ RE-label と Ghidra DB 名が食い違う箇所あり(下表 note)。**load-bearing は VA**。

---

## 真のブロッカー = MMGP ネットワーク play-session（card/keychip でない）[S+L]

boot は attract(FREE PLAY)到達、touch/card 完動("touch panel ok"/"card slot ok")だがタッチで進まない。
真因 = MMGP matching/play-session ハンドシェイク。alAbEx keychip auth は無関係（実機確定, 下記）。

## scene/task 機構 [S]

- task list **`DAT_016db564`**(=`g_amTaskList_head`, device list と同一): node 0x5c B。
  `+0`=tid `+4`=uid(tag) `+8`=flags(&3=active,&4=remove) `+0x10`=ctx `+0x14`=ctxSize `+0x24`=update(vtbl slot#2 VA) `+0x3c`=next。
  registrar **`amTaskOpen`(0x89dcb0)**`(tid,uid,ctxSize)`(`*node=tid;node[1]=uid;node[2]=3`)。
- **uid = FourCC タグ [S]**: amTaskOpen 重複警告 `amDebugOut("...uid=%08x(%s)...",uid,&str)` が uid を 4B ASCII 低位順で文字列化(`DAT_02283014=uid&0xff`…)。
  例 `0x50474d4d`="MMGP" / `0x45`='E'=network-reception / `0x21`=card(tid==uid, devices.md)。計装 `api.c scene.delta` は tag(hex)+tag4(FourCC)。EntryMode 個々の uid は未裏取り[I]。
- **scene 選択は scene-id global でない**(PROVEN): `DAT_016b8b54`=`amlib_subsystem_state`(keychip/usbio 状態, `==8`=keychip-ready; reader `keychip_errCode1_latcher`0x6f0a80/`usbio_errCode_mapper`0x6f0ae0)。0xD4B000 は state-string jump table(3 slot)で scene ctor 表でない。
- scene 本体 = vtable/RTTI ベース(nrs.exe 埋込 C++ クラス, RTTI 有)。update VA(node+0x24)=vtbl slot#2 生 addr → vtbl base(=slot#2−8) → vtbl[-4]=COL → COL+0x0c=TD → TD+0x08=mangled name。
  **entry flow scene 実クラス(直読, [S])**:
  | update VA(slot#2) | 実 RTTI class | COL | vtbl base |
  |---|---|---|---|
  | 0x5eaae0 | `EntryModeGamePoint` | 0xca9318 | 0xbb3584 |
  | 0x5e6200 | `EntryModeCheckCard` | 0xca9538 | 0xbb34bc |
  | 0x5e90b0 | `EntryModeNameEntry` | 0xca94a0 | 0xbb34ec |
  | 0x5e8710 | `EntryModeSelectChara` | 0xca94ec | 0xbb34d4 |
  | 0x5eb000 | `EntryModeDotNetRegist` | 0xca92cc | 0xbb359c |
  | 0x5ec340 | `EntryModePassword` | 0xca9234 | 0xbb35cc |
  | 0x5eb6b0 | `EntryModeReIssue` | 0xca9280 | 0xbb35b4 |
  | 0x62fb50 | `EntryModeBase`(基底) | 0xca9584 | 0xbb34a4 |
  - note: DB 名 0x5eaae0=`entry_credit_touch_scene` / 0x5e6200=`entry_card_auth_scene`(共に確認済)。
  - **継承の罠**: `EntryModeRegist/UpdateBase/UpdateCard/VersionUp` は slot#2 未 override→**0x5ea0a0 共有**(基底 update)。update VA だけで一意化不可、実行時 obj の vtable→RTTI 読みが要る。
  - `FUN_007274d0`(RE-label attract_scene_lifecycle) / `FUN_006f42c0`(net_session_task_sm_on_touch) は素の task callback で RTTI 無し=実名無し(`api.c scene_va_name` は生 VA 出力)。
  - `scene_list_lifecycle_update`(0x89d830) が node-id 0x21 render-node を tick。遷移は scene SM 内部(MMGP)＋出力構造体`param_2+0x134`=done 駆動。scene-id global 書込では起きない。
  - 未解決 VA は `scene.delta` が `cls:null`＋生 VA で出す(次の RTTI 解析対象)。
- dispatcher 0x6f06e4–0x6f0a7f は Ghidra 未解析 raw(GUI force-disasm 要, MCP 不可)。本 flow には不要。

## attract→credit 遷移 gate（PROVEN）

credit/touch scene = **0x5eaae0**(`entry_credit_touch_scene`)。state1:
```
mmgp_request_start(0x6f3f20);                              // subobj+0xd=1
if (mmgp_read_start_accepted(0x6f3f60) != 0)              // subobj+0xc
    { credit_commit_pending(0x774f40); local_f=1; }       // advance
```
`+0xc`=1 になるのは **`mmgp_task_update`(0x6f3b40)**:
```
6f3bce: CALL mmgp_txn_result(0x562c80)   ; = msg+0x1ac
6f3bd6: if (result==2) [subobj+0xc]=1    ; play-start 受理(毎フレーム +0xc=0 クリア)
```
state0→2 は `mmgp_input_service_gate`(0x89e930) true が必要。

### gate 一覧（全て満たす）[S]（gate 関数は decompile 実体裏取り済）
| gate | global(static_VA) | reader | 必要値 |
|---|---|---|---|
| 入力/サービス | `DAT_0227fe6c`(`g_jvsInputServiceBits`) | `mmgp_input_service_gate`(0x89e930) | **0x400 SET**, 0x100/0x200 CLEAR ＋(`DAT_0227fe70&4` or `DAT_02282a64+2&1`) |
| coin lockout | `DAT_016b8b6b`(`g_coinLockoutFlag`) | `credit_coin_accept_check`(0x50a2b0) | 0 |
| MMGP txn | msg`+0x1ac` | `mmgp_txn_result`(0x562c80) | ==2('E'/0x45 が 0x2206 応答) |
| 'E' net task | tag 0x45 node | `mmgp_net_task_ready`(0x562e70) | node present＋ctx 有効 |
| credit init | `DAT_01288550`(`g_amCreditInitFlag`) | `amCreditGetState`(0x97cf80) | 非0(free-play OK) |
| free play | `DAT_0128855a`(`g_freePlayFlag`) | 同上 | 1(msg のみ・遷移は別) |

- `DAT_0227fe6c` = JVS 入力/sensor status 語("CARD IN"=&0x8000, JUMP/DASH/ACTION bit 同居, writer=mxsensor/JVS service-state 0x89b6bd/0x8a04b0)。bit 0x400=サービス/入力 present。touch device が battle-start blocker だったのと整合。
- MMGP cmd word: **0x2101**=idle/keep-alive / **0x2206**=commit/start-with-credit(`mmgp_net_send_msg` 0x562aa0 経由 'E' へ)。

## credit→card-auth 連鎖 [I 強支持]

credit advance(`param_2+0x134=1`)→ dispatcher が `DAT_016b8b54` 書換 → factory が **0x5e6200**(`entry_card_auth_scene`) 生成。
card-auth = class(0x21,0x21) card obj flag(+4 bit10/11)＋`FUN_004f2d20`(seated) 駆動、`FUN_00562aa0(..,6,0x21101,10)`(cmd 0x21101=card search/read)で **card SEARCH(0x4D)** 発火。`DAT_016b8b6b`(offline)≠0 で short-circuit。

## alAbEx keychip auth は scene gate で「ない」[L]
boot net SM `hlsm_boot_network_sm`(0x457fe0) は alAbEx flags(`DAT_0210AED0/AED2/AED4`,`DAT_0210B508`,`DAT_016019A5/A6`)要求だが credit/MMGP 経路に不出現(PROVEN by absence)。`api.c network_auth_force_ready` 強制→`network:ok` にはなるが attract→credit 不開通(実機)。真の gate=`DAT_0227fe6c&0x400`＋MMGP txn。

## 停止点 = credit/entry scene が非 active [L]（mmgp_diag/scene_diag 計装で確定）
- **MMGP は state0 で不動**: `gate0x400=1`・`lockout=0`・`found=1` だが `state=0/sub=0/req=0/accept=0/msgres=-2`(タッチ後も不変)。state0→2 は `mmgp_request_start`(credit scene が呼ぶ)要だが **req=0=credit scene 未呼**。`mmgp_net_task_ready` は 'E' 不在なら 0 返し state0 通過許可(塞いでない)。
- title active set = **35 node で安定**。`FUN_007274d0` は active list に不在。同居: `cardrw_ctx`(0x4f2930)/`touch_poll_update`(0x8b2750)/`mmgp_task_update`(0x6f3b40)/`amlib_init_sm`(0x89a010)。**credit(0x5eaae0)/card-auth(0x5e6200) 未生成**。
- touch で `FUN_006f42c0`(state0-5 SM)＋thunk 0x4026f0 spawn するが credit/card-auth 依然未生成、attract demo 別ページ循環のみ。
- ⇒ 開始 gate = 上流 ALL.NET/MMGP ゲームサーバ接続(「GAME SERVER 未完了・全国対戦受付終了」と整合)。alAbEx 強制も MMGP gate 強制(`|0x400`)も state0 のまま無効。

## EntryMode scene factory [S]
factory = **`FUN_005ec6e0`**(RE-label entrymode_scene_factory)`(mgr,sel)`:
- sel(0..10): **0=card-auth(ctor 0x5ec9b0)** / **1=credit(ctor 0x5eca20)** / 2=0x5eca80 / 3=0x5ecb00 / 4=Regist / 5=UpdateCard / 6=0x5ecba0 / 7=0x5ecc10 / 8=0x5ecc70 / 9=VersionUp / 10=null(exit)。
- `param_1`=entry-mode mgr ctx(`+0x5c4`=現シーン state id, `DAT_00bb30e8[sel]`=state-id)。生成 scene `puVar4[1]=mgr`。
- **呼出元が decompile に不出現=間接呼(mgr vtable slot 経由)**(`get_xrefs_to`/`search_decompiled` 共 0)。⇒ sel を進める条件が真の gate。
- 次の一手: entry-mode mgr obj の生成元と vtable 特定(factory ptr 格納先)。間接 dispatch ゆえ **cdb で 0x5ec6e0 bp→戻り先 stack が最短**、ただし headless boot ~50% フレーク(下記)ゆえ GUI/実機トレース向き。

## headless 自動テストの限界 [L]
- **boot フレーク ~50%**: attract 到達 run と tick ループ未入 stall run が混在(scene.diag=0, device read 0)。ゾンビ/ポート競合無し。CREATE_NO_WINDOW で入力/レンダーループが GUI 等価に回らない疑い。
- **touch 未 poll**: COM1 read 0〜2 回止まりで handshake が mode1 未達 run 多い(touch.diag present_18=0)。
- ⇒ **完全自動の attract→card-select 到達は現状不可**。card 反映機構(presence/read/whitelist)は headless 検証済だがシーン到達は GUI(実窓・実タッチ)が確実。
- touch 注入ツール `nrsedge.touch.json`(api.c touch_control_poll): `{"press":0|1,"xm":0..1000,"ym":0..1000}` → logic が COM1 'T' 注入(窓/カーソル非依存)。touch poll される run のみ動作、単体では自動到達を保証しない。

## 次の一手 = entry-mode mgr の sel 進行 gate
credit(0x5eaae0,vtbl 0xbb358c)/card-auth(0x5e6200,vtbl 0xbb34c4) を生成・active 化する所有者(=`FUN_005ec6e0` を vtbl slot に持つ mgr)を特定: vtbl への DATA xref、ctor、scene 切替条件。network/service 状態にゲートされるかは未確認[I]。
これが active になれば state1 で `mmgp_request_start`→MMGP txn(msg`+0x1ac`==2)→card-auth→card SEARCH(0x4D) と進み Phase B(仮想カード)を live 検証可。MMGP 充足前提: `DAT_0227fe6c|=0x400`＋`DAT_0227fe70|=4`, `DAT_016b8b6b=0`, 'E'/0x45 の 0x2206 応答 result=2(P5 network 層; 最小は msg`+0x1ac=2` runtime 強制)。
