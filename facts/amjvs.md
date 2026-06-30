# amJvs / amJvsp FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。索引 `_index.md` / 横断知見 `workflow.md`。
confidence: [S]=静的解析 [L]=ライブ実走 [I]=推論 [F]=旧 Frida 計装(履歴・再取得は Ghidra/実走)

---

## ★現行方式 = native JVS over COM4（forgery/direct-write は撤去）[S+L, 2026-06-28 確定]

旧「JVS forgery patch ＋ node BSS direct-write(B 経路)」は**全撤去**。実機どおり nrs の native amJvst を
COM4 経由で駆動し、`src/logic/driver/mxjvs.c`（純正 `RingOSUpdate\common\segadriver\mxjvs\mxjvs.sys` を正本に、micetools mxjvs.c を補助 lift）が JVS ボードをエミュする。**実走で init clean
＋入力フロー確認済み**（`jvs_initialized_flag=1 / jvs_node_count=1 / jvs_p1_device_id=1 / jvs_error_state=0`、
START 押下で `node+0x643 bit7=0x80`）。

**transport 契約（amJvstThreadInit 0x989B10 で確定）**:
- `CreateFileA(port, GENERIC_RW, 0,0, OPEN_EXISTING, **0x40000000=FILE_FLAG_OVERLAPPED**, 0)`。
- `GetCommState→SetCommState(115200/8N1)→SetCommTimeouts(全0)→SetupComm(0x400,0x400)→PurgeComm(0xf)` が
  **全て成功(非0)必須**。host(`hook.c`)が COM 制御 API 群をフックし仮想ハンドルへ TRUE 化（`on_comm_control`）。
  overlapped は host が read/write 後に `ov->InternalHigh=k; SetEvent(ov->hEvent)` で完了シグナル（logic は同期）。
- **SENSE ライン = GetCommModemStatus の DSR(MS_DSR_ON=0x20)**（micetools `mxjvs_GetCommModemStatus` 準拠＝純正 mxjvs.sys で要裏取り）:
  sense=1(未割当)→0、sense=0(割当済=チェーン終端)→MS_DSR_ON。**欠落するとマスタが SETADDR を無限ループ**し
  node 確定しない（実走で確認）。`JvsBoard.sense` は init=1 / ASSIGN_ADDR 後=0。

**discovery シーケンス（poll スレッド 0x9896c0 + 列挙スレッド 0x9869f0, 実フレーム観測）**:
`RESET(e0ff03f0d9)×2[無応答] → SETADDR(e0ff03f1 01)[OK, sense→0] → READ_ID(10) → 版+features 結合フレーム
(11 12 13 14) → 毎フレーム polling: READ_SW(20 02 02)+READ_ANALOG(22 08)+READ_COIN(21 02)+**WRITE_GPIO2(37)×2**`。

**入出力ワイヤ仕様 — 送受信を逆コンパイルで byte 完全確定（2026-06-29, jvs_per_node_output 0x67b280 起点）[S]**:
poll フレームは `jvs_per_node_output` が 1 フレームに連結組立。組立/解析関数（known_names 反映済）:
- **送信(req)**: `amJvspReqSwInput`(0x988310→`20 players swbytes`=`20 02 02`) / `amJvspReqAnalogInput`(0x9885a0→`22 ch`=`22 08`)
  / `amJvspReqCoinInput`(0x9884b0→`21 slots`, slots=node+0x60c) / `amJvspReqGeneralOutput`(0x9886d0→`37 idx val`, idx=1,2 の2発)。
  低層 appender=`jvsp_append_command`(0x9875e0)。**出力は 0x37 のみ（0x38 は未送）**。
- **応答 layout（report code 先頭, 全 big-endian）**: READ_SW=`[01][sys][p0:2B][p1:2B]`（sys=idx0xff で 1B, player は 2B/各）
  → `amJvspAckSwInput`(0x988360) が node+0x642(sys)/+0x643(p0)/+0x645(p1) へ。 READ_ANALOG=`[01][ch×2B…]`
  → `amJvspGetAnalog`(0x9885e0) が `report[1+ch*2]` を BE16 で node+0x648.. へ。 READ_COIN=`[01][slot×2B…]`
  → `amJvspGetCoinCount`(0x9884f0) が BE16（上位2bit=condition, 0=normal）。
- **mxjvs.c との一致**: READ_SW は `WR(01)WR(sys)WR(p0hi,lo)WR(p1hi,lo)`、ANALOG は `WR(01)+8×(hi,lo)`、COIN は
  `WR(01)+slot×(hi&0x3F, lo)`、0x37 は `RD()RD()→WR(01)`。**全コマンド送受とも byte 単位で nrs の組立/解析に一致**＝
  入力(SW/analog/coin)・出力(GPIO ack)の仕様を満たす。出力 GPIO 値は物理ランプ/ソレノイド用で破棄して可（read-back 無し）。

**GET_FEATURES 申告の閾値（FUN_0067afa0 の node_count==1 経路, node_info_buf 直読みで確定）**:
buffer = `node_base(0x16B7860)+0x508` 付近。チェック: `+0x101 buttons/player ≥ 0x0e` / `+0x108 analog ch ≥ 0x02`
/ `+0x124 gpio出力数 ≥ 0x0d` / `+0x134 cmd_ver ≥ 0x13`。満たさないと `jvs_error_state=-102`。
→ mxjvs は **buttons=0x0e(JVS_FEAT_BTNS) / gpio=0x0d(JVS_FEAT_GPO)** を申告（sw ビット詰めは JVS_BTNS=13 で
START→byte0 bit7 を保持＝申告値とは分離）。**WRITE_GPIO2=0x37 / GPIO3=0x38**（各 index,value 2byte）も OK 応答必須
（未対応だと polling が STATUS=02 UKCOM → 実行時 jvs_error_state=-101）。

**spec-check 逆コンパイル全文（FUN_0067afa0, 2026-06-29 確定）[S]**: 受理ゲートは node_count==1 経路の単一述語
`(DAT_016b7e69<0x0e)||(DAT_016b7e70<2)||(DAT_016b7e8c<0xd)||(DAT_016b7e9c<0x13)` → 真で `error=-102`。
**比較されるのは buttons/analog/gpio/cmd_ver の 4 つのみ。JVS_VER(0x12)・COMM_VER(0x13)・READ_ID 文字列は
非検査**（nrs.exe に "837-"/"I/O BD" 文字列も無し＝ID は完全に cosmetic）。mxjvs 現値(btn=14/analog=8/gpio=13/
cmd=0x13)は全て閾値ちょうどで合致。`node_count!=1` 経路は **spec-check を丸ごとスキップ**し p1=count・p2=count-1 を割る。

**ボード ID = 実機型番 837-15067 に変更（2026-06-29）[S]**: 実 RingEdge の JVS I/O は FTDI USB 837-15067 系
（ftdibus.inf: VID_0CA3 PID_0010..0015=837-15067, PID_000F=837-15121）。旧 837-13551 は micetools 由来の別世代。
nrs は ID を読まないため機能影響ゼロ（Ver/日付サブフィールドは基板 ROM 値で未捕捉＝SEGA 標準書式での最良推定）。

**マルチノード非対応＝正しい（2026-06-29 結論）[S+L]**: BBS は 1 筐体=1 席、筐体間は ALL.Net(Ethernet)で JVS
デイジーチェーンではない＝JVS ノードは常に 1。SENSE 終端の単一ボードで `amJvspStatusCheck()→node_count=1`（実走確認)。
multi-node を実装して count≥2 を返すと nrs は spec-check を通らない異経路へ入り p1/p2 を別ノードに割る＝単一筐体で誤動作。
**single-board が唯一正。拡張不要。**

**COM 番号は設定可能**: `NrsConfig.jvs_com`（**既定 9**, nrsedge.cfg `jvs_com=N`, 単桁 1..9）。patches.c が
`"COM4"@0xAE11F0` を `"COMN"` にパッチ＋logic `is_jvs_com` も同番号でマッチ。**既定を 9 にしてゲームの COM マップ
（touch=COM1/COM3, card=COM2, 元 JVS=COM4）との重複を回避**（1..3 は touch/card と衝突するので避ける）。0xAE11F0 の
在地枠は "COM4\0\0\0\0"=5バイトのため単桁固定（CreateFileA は host フックが横取りするので \\.\ プレフィクス不要）。
COM5 で実走確認済み（既定 9 でも同様に init clean）。

**specCheck(0x987590) パッチ撤去の根拠**: `specCheck` は `*amJvs_sub1_ctx_ptr!=0` で成功。amJvspInit が最初に
呼ぶ `FUN_00987550` がその ctx[0]=1 を自前で立てる＝native 経路が走れば不要（forgery が殺していたから必要だった）。

**JVS I/O ログ**: `on_write_file` が 1 トランザクションごとに `{"ev":"jvs.io","cmd":<先頭cmd>,"wr":<req hex>,"rd":<resp hex>}`
を出力（`jvs_io_log`）。**連続同一フレームは dedup**（READ_SW poll が ~60Hz ゆえ idle は無音、入力/コマンド変化時のみ出る）。
discovery 全手順（f0/f1/11/10/20）が見え、START 押下で `rd` の P1 sw byte=0x80 が乗る＝実走の入出力確認に使える。

> ビット割当・node BSS レイアウト・入力消費経路は下記「Global Variables」「JVS Node Memory Layout」「Game Functions」を正とする。

## 入力ソースと配線

入力ソースはキーボード(`GetAsyncKeyState`)＋XInput(`XInputGetState`, pad0)。バインドは `nrsedge.cfg` の
`bind.<action>=<VK>`（host が読み logic へ。編集は loader GUI の「入力設定 / テスト」タブ→保存→再起動）。
実装 `src/logic/driver/input.c` ＋ `api.c`（Write 毎に poll→`mxjvs_set_input` で JVS フレームへ反映）。

**コイン/クレジットは billing にブロックされない**（旧「billing 衝突でクラッシュ→保留」はカテゴリ錯誤の誤りで訂正済＝`bugs.md` [RISK]）:
credit 経路の実体 amCredit（init=`amCreditInit` 0x97D320）は ALL.Net billing(alpbEx) と独立で、billing オフラインでも正常 init する。
コイン投入は `amCreditAddCoin`(0x97D780, __thiscall(chute, count)) で計上（ガードは free-play flag `DAT_0128855a` ＋ credit 設定のみ。
FreePlay=1 時は no-op）。詳細は下記「クレジット/コイン サブシステム」。

---


## Global Variables [S+F]

| static_VA | RVA | Name | Type | Notes |
|---|---|---|---|---|
| 0xCCF548 | 0x8CF548 | amJvs_main_ctx_ptr | U32* | pointer to amJvs main context |
| 0xCCF54C | 0x8CF54C | amJvs_sub1_ctx_ptr | U32* | pre-forced: [[ptr]][0]=1 at script load |
| 0x16B7858 | 0x12B7858 | jvs_initialized_flag | U8 | ≥1 = JVS init done |
| 0x16B785C | 0x12B785C | jvs_node_count | U32 | polling loop: `for(i=0;i<nodeCnt;i++)` — must be ≥1 |
| 0x16B7860 | 0x12B7860 | jvs_node0_base | - | stride 0x65C per node |
| 0x16B8668 | 0x12B8668 | jvs_p1_device_id | U32 | compared vs node[0] in credit handler |
| 0x16B866C | 0x12B866C | jvs_p2_device_id | U32 | |
| 0x16B8670 | 0x12B8670 | jvs_error_state | S32 | 0=OK, -101=err6401, -102=err6402 |
| 0x16B8674 | 0x12B8674 | jvs_error_counter | U32 | |

---


## JVS Node Memory Layout

Base: `nrsBase + 0x12B7860`, stride per node: `0x65C`

| offset | type | name | notes |
|---|---|---|---|
| +0x000 | U32 | node_id | compared vs jvs_p1_device_id |
| +0x004 | - | report_buf | passed as amJvspAckSwInput arg0 |
| +0x306 | - | node_0x306 | passed as amJvspAckSwInput arg1 |
| +0x640 | U8 | poll_state | ≥1 required for fn A to call amJvspAckSwInput |
| +0x641 | U8 | node_valid | |
| +0x642 | U8 | sys_switch | system byte。bit7=TEST（inner_input が playerIdx 0xff の結果 byte0 を格納） |
| +0x643 | U8 | p1_switch1 | bit7=START bit6=SERVICE bit5=UP bit4=DOWN bit3=LEFT bit2=RIGHT bit1=PUSH1 bit0=PUSH2 |
| +0x644 | U8 | p1_switch2 | bit7=PUSH3(Action) …（inner_input は player ごと count=2 byte を書く） |
| +0x645 | U8 | p2_switch1 | same layout as p1_switch1 |
| +0x646 | U8 | p2_switch2 | same layout as p1_switch2 |
| +0x648 | U16×8 | analog[0..7] | `inner_input` のアナログループ書込先（各 U16, big-endian 合成, 中心0x8000）。ch0=stickX(Analog0), ch2=stickY(Analog2 reverse) |

※ コインは node memory ではなく `amJvspGetCoinCount`(0x9884F0) の戻り値（累積カウント）を
credit_handler が差分してクレジット換算する（node+0x648 はアナログ領域）。

---


## Game Functions [S]

| static_VA | RVA | Name | Notes |
|---|---|---|---|
| 0x67B150 | 0x27B150 | jvs_update_main | called every frame; checks jvs_initialized_flag first |
| 0x67B280 | 0x27B280 | per_node_output_fn | edi=node_ptr; writes solenoid/JVS output |
| 0x67B330 | 0x27B330 | per_node_input_fn | esi=node_ptr; calls inner_input |
| 0x67B3A0 | 0x27B3A0 | inner_input | calls amJvspAckSwInput + amJvspGetCoinCount |
| 0x67B450 | 0x27B450 | credit_handler | requires node[0]==jvs_p1_device_id。coin 読取失敗で早期 return。FUN_0097db80(credit dispatch)はガード済で安全（旧「billing クラッシュ源」は誤り、`bugs.md` [RISK] 訂正） |
| 0x67B41E | 0x27B41E | device_id_check | `cmp node[0], [0x16B8668]`; branch to credit_handler |

### 入力消費経路（app 側・poll_state 非依存。direct-write はここへ効く）[S+F]

| static_VA | Name | Notes |
|---|---|---|
| 0x67B620 | switch_decoder | node+0x642..+0x646 を読み論理ボタン mask へ（sys bit7→TEST=2, +0x643 bit7→START=1, bit6→SERVICE=4 …） |
| 0x67B6E0 | input_snapshot | FUN_0067b620 で switch、node+0x648.. で analog 8ch を読み `(v-0x8000)*scale`（中心0x8000）で構造体化 |
| 0x67B860 | input_poll | input_snapshot の呼出元 |
| 0x679DF0 | usbio_jvs_io_update | input_poll を呼ぶ。root-scene(0x6C3F46) から毎フレーム |
| 0x8A04B0 | input_test_display | テストメニュー INPUT TEST 画面。JVS 入力の正準リスト。各項目のソース global は下表 |

### INPUT TEST 項目 → ソース global → node（実機計測で確定）[F]

`FUN_008a04b0` が表示する＝ゲームが要求する JVS 入力一覧:

| INPUT TEST 項目 | cooked global | node ソース | 状態 |
|---|---|---|---|
| MOVE STICK X | DAT_0227ecc0(hi byte) | **node analog ch1**(node+0x64a) | 対応済（旧 ch0 は誤り、ch1 が正） |
| MOVE STICK Y | DAT_0227ecc2 | **node analog ch0**(node+0x648) | 対応済（旧 ch2 は誤り、ch0 が正） |
| JUMP BUTTON | DAT_0227fe6c & 0x100 | node+0x643 bit1(PUSH1) | 対応済（Z）|
| DASH BUTTON | DAT_0227fe6c & 0x200 | node+0x643 bit0(PUSH2) | 対応済（X）|
| ACTION BUTTON | DAT_0227fe6c & 0x400 | node+0x644 bit7(PUSH3) | 対応済（C）|
| CARD IN | DAT_0227fe6c & 0x8000 | （IC カード）| 未対応 |
| R GRIP X/Y（照準）| DAT_0228082c / 2e（累積位置）| **相対/速度入力** DAT_02280830/34（rate）経由。node analog ch0-7 では駆動されない（要追加調査＋calibration）。`FUN_008a0200` が rate を積分 | **未対応** |
| A/B/C BUTTON | DAT_0228078c & 0x100/200/400 | （スイッチ。JUMP/DASH/ACTION とは別ソース）| 未対応 |
| TEST/SERVICE | DAT_0160194c bit0/1 | 筐体 dipsw（F1/F2 上書き）| 対応済 |

実機計測（node 各 ch を順に max → cooked global 観測。旧 Frida probe。再取得は Ghidra/実走）で確定。
**MOVE は ch1=X / ch0=Y**（TP プロファイルの Analog0/2 とは番号が異なる＝実機が正）。R GRIP（照準）は
node analog 直結ではなく rate 入力で、Border Break の照準操作。実装には rate ソースの特定が必要。

### 筐体 TEST/SERVICE ボタン（JVS とは別系統）[S+F]

筐体 TEST/SERVICE は **system switch register `0x160194c`**（bit0=TEST, bit1=SERVICE）で読む。書込みは
dipsw read `0x45A0E0`(FUN_0045a0e0): dipsw byte2 bit0/1→`0x160194c` bit0/1。**boot の board-index fix
（dipsw エミュの board index = dipsw byte2=3, `devices.md`）が bit0/1 を常時 ON にする**ため、無対策だとテスト
メニューが自走する。`api.c on_sys_override` が `0x160194c` bit0/1 を F1/F2 から上書き（毎フレーム＋`0x45A0E0` 後＋
system input processor `0x89B230`(sysinput_cook_test_service_edges, DAT_02282a64←0x160194c 直前) で確定）。
テストメニュー操作: SERVICE(F2)=カーソル移動、TEST(F1)=決定（実機検証済み）。

**メニュー系はレベルでなく「立ち上がりエッジ」を読む（ナビ用）[S, 2026-06-28 確定]**: `sysinput_cook_test_service_edges`
(0x89B230)末尾が `0x160194c`→`0x2282a64` を cook: `[+0]`=level(次フレ prev)、`[+2]`=**立上りエッジ `~prev & cur`**、
`[+4]`=立下り、`0x2282a6c`=hold counter。メニュー**内ナビ**(`testmenu_enter_combo` 0x89EAA0 / `testmenu_list_scroll`
0x89F5D0 / `testmenu_tick` 0x89E240)は **`DAT_02282a64._2_1_`(エッジ語)** を読む。→ TEST を常時 ON に固定すると
メニュー内のホールドカウンタ(testmenu_tick +0x74 等)が誤発火して即退出するので**保持してはいけない**。入場後の
操作は実機同様 F1=TEST / F2=SERVICE のエッジ（手動）。

**テストメニューの「入口」は 0x160194c ではなく scene システム [S+ランタイム実証, 2026-06-28 確定]**:
attract で 0x160194c(TEST) を握っても入れない（実機 RE＋ゲーム実走で確認。cooked TEST を読むのはメニュー
subsystem 内だけで attract 側に入口ゲートが無い）。実際の連鎖:
- `scene_request_consume`(0x6F0750, scene update cb・毎フレーム)が `requested_scene_id`(**DAT_016B8B54**)を読み、
  ≠-1 なら `scene_factory_table`(**0xD4B000**)`[id*16]` の ctor を呼んで scene 生成 → id を -1 に戻す（ワンショット）。
- **id=13** = `testmode_container_ctor`(0x6F1C50)。enter(+0x20)=`open_test_menu`(0x89DF80)→ `testmenu_scene_ctor`
  (0x89E7C0, タグ "TMNU")で `testmenu_tick` scene を生成 ＝ オペレータ/テストメニュー本体。
- 通常は scene-init `scene_init_request_testmode`(0x6F06F0)が **`testmode_request_flag`(DAT_016F5A9C)!=0** のとき
  id=13 を要求する。**standalone はこのフラグが立たない**ため入らない（旧 Frida 実装でも本来の入口は別系）。

native の修正（`src/logic/api.c` on_sys_override）: `test_mode` のとき main ループ安定後(sys_tick>20)に
**`DAT_016B8B54`=13 を一度だけ書く**＝テストメニューに入場。TEST は保持しない（ナビは F1/F2）。
ランタイム実証: `testmenu.enter`→ scene-list に `testmode container(0x89e030)+testmenu_tick(0x89e240)` が出現し
**滞在し続ける**ことを scene-list 走査で確認（クラッシュ無し・breadcrumb 全 OK）。

### クレジット/コイン サブシステム [S]

| static_VA | Name | Notes |
|---|---|---|
| 0x97D320 | amCreditInit | `DAT_01288550=1` にして coin/credit rate を設定（amlib boot で実行）。引数: coinCfg/creditCfg/bookCfg/numChutes/?/numSlots |
| 0x97D900 | coin_add | コイン差分→クレジット換算。_DAT_01288588(coin総)/_DAT_0128858c(coin credit)/_DAT_01288594(total)/DAT_0128859c(変化flag) |
| 0x97DA50 | service_credit_add | サービスクレジット加算 → _DAT_01288590 / _DAT_01288594 |
| 0x97D170 | credit_get_settings | DAT_01288568.. を返す（DAT_01288550==0 で -3） |
| 0x1288550 | credit_init_flag | ≠0 で credit subsystem 有効。0 だと全 credit 関数が早期 return |
| 0x1288594 | total_credits | TOTAL CREDITS（BOOKKEEPING 表示） |
| 0x128855A | free_play_flag | coin-config(0x1288558) byte[2]。1 で amCreditCheck(0x97CF80) が常に startable、amCreditConsume(0x97CFF0) 非減算、amCreditAddCoin(0x97D780) no-op = **FREE PLAY**（コイン不要）。amCreditInit が coinCfg からロードする値 |

**フリープレイ** [S+L, 部分検証]: `src/logic/api.c`(on_jvs_tick, FreePlay 有効時 per-frame)が
amCreditInit 済(`DAT_01288550`!=0)のとき `0x128855A=1` を強制する。flag のセマンティクスは静的に確定（上記
4 関数が `DAT_0128855a!=1` を分岐条件にする）。runtime 裏取り: amCreditInit 後に flag 書込み＋read-back=1 を
確認、credit init=1 のままクラッシュ無し（旧 Frida 計装で確認）。ただし attract→ゲーム開始まで通すかは billing
オフライン環境で未検証（開始手順は下記「コイン+タッチ」も関与しうる）。

コイン注入: credit subsystem は init 済み(DAT_01288550=1, runtime 確認)。_DAT_01288594=N を強制しても
**START でゲーム開始しない**（HLSM が ATTRACT のまま）＝**実機の開始手順は「コイン投入＋画面タッチ」**
（ユーザー情報）。START ボタンでは始まらない。

### ゲーム開始手順 = コイン + タッチパネル [S+ユーザー]

実バトル開始は **credit + 画面の特定位置タッチ**。タッチ処理:
| static_VA | 役割 |
|---|---|
| 0x755280 | タッチ UI イベント処理。FUN_008b3b90(raw touch)→FUN_004f9e20(hit-test 要素id)→画面 state 別 dispatch |
| 0x4F9E20 | タッチされた UI 要素 id を返す（touch state struct +0x1c index→+0x98 table。-1=未タッチ）|
| 0x8B3B90 | タッチ生データ読取（device ctx +0x210 から 21 dword） |
| 0x8B3B00 | touchpanel_status（present。boot で =1 patch 済）|
| 0x16D8690 / 0x16DB564 | タッチ device context ポインタ（linked-list id 0x22,0x22）|

**ブロッカー**: タッチ device context(`DAT_016d8690`/`DAT_016db564`)が boot に**存在しない**ため、
touchpanel_status は present(=1 patch)だが touch データ getter(FUN_008b3b90 等)は全て 0 を返す＝
ゲームはタッチを一切受け取れない。**タッチパネルは独立した device emulation サブシステム**（JVS と同規模）で、
偽 touch device context ＋ 座標レポート（開始ボタン位置）＋ calibration の実装が必要。これが「コイン+タッチで
開始」の未実装部分。R GRIP(照準)・ALL.Net も実バトルには関連。

（筐体 TEST/SERVICE ボタンの詳細は上記「筐体 TEST/SERVICE ボタン（JVS とは別系統）」を参照。）

---


## JVS I/O Subsystem [F+S]

**JVS transport = `CreateFileA("COM4")`（ハードコード）[S]**。amlib の amJvst が開く。逆アセンブルで確定:
- `amJvspInit`(0x986720) → `FUN_00988eb0(&"COM4")` → `amJvstThreadInit`(0x989B10) が
  `CreateFileA(DAT_00AE11F0, ...)`。`DAT_00AE11F0` の実体は静的文字列 **`"COM4"`**(43 4F 4D 34 00, @0xAE11F0,
  reader は amJvspInit のみ・writer 無し＝完全ハードコード)。設定 `SetCommState` **115200 baud / 8N1**、
  通信スレッド `FUN_009896c0`。→ **「別の調査で JVS=COM4」はこのハードコードが正体**（micetools mxjvs
  `new_com_hook(4)` もこれに一致）。
- **現行 native**: COM4 を素のまま開かせ、host が `CreateFileA("COM4")` を仮想ハンドル化（logic `is_jvs_com`）して
  `src/logic/driver/mxjvs.c` が JVS ボードをエミュ。COM 番号は `nrsedge.cfg jvs_com`（既定 9）で touch/card と衝突回避（上記）。
- **TeknoParrot 下（参考）**: TP が `CreateFileA` を MinHook で横取りし COM4 を SHM `TeknoParrot_JvsState`(8B, byte0=JVS-present 固定)
  へリダイレクト（TP.dll は VMProtect で静的不可＝挙動観測で裏取り。`ref.md`）。native 実装には不要。

> シリアル device 全容（COM1=touch / COM2=card / COM4=JVS）と touch/card の transport 詳細は **`devices.md`
> §周辺シリアル I/O デバイス（COM map）が正本**。

IOCTL codes (columba driver compatible):
- `JVS_IOCTL_HELLO    = 0x80006004`
- `JVS_IOCTL_SENSE    = 0x8000600C`
- `JVS_IOCTL_TRANSACT = 0x8000E008`

JVS frame format (segatools, Unlicense):
```
byte 0:    0xE0 (SYNC)
byte 1:    dest addr (0xFF=broadcast)
byte 2:    payload length + 1
byte 3..n: command bytes
byte n+1:  checksum (sum of addr+cmd bytes, LSB + 1)
escape:    0xD0/0xE0 in payload → 0xD0 + (byte XOR 0xFF)
```
JVS commands: 0x10=IOIDENT 0x11=GET_CMD_VER 0x12=GET_JVS_VER 0x13=GET_COMM_VER 0x14=GET_FEATURES
0x20=READ_SWITCHES 0x21=READ_COIN 0x22=READ_ANALOGS 0x32=WRITE_GPIO 0xF0=RESET 0xF1=ASSIGN_ADDR

---
