# 周辺デバイス presence 連鎖 FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。索引 `_index.md` / 横断知見 `workflow.md`。
confidence: [S]=静的解析 [L]=ライブ実走 [I]=推論 [F]=旧 Frida 計装(履歴・再取得は Ghidra/実走)

---

## Error Scene System & Device-Presence Chain [S+F]

boot 後に居座る「Error NNNN」は**ゲームアプリのエラーシーン**（amlib 09xx 表示とは別経路）。
レンダラ `error_scene_render`(0x6f2730 / RVA 0x2f2730) が記述子を毎フレーム描画。記述子レイアウト:
`+0x00`=amlib errCode / `+0x04`=detail / `+0x0c`=msgPtr / `+0x10`=errNo(表示番号) / `+0x16`=flags(&4=Caution)。

**device-presence 連鎖**: errCode→errNo→fix の対応は `src/logic/patches.c`。発生源関数は
`amlib_init_sm_SYSTEM_STARTUP`(0x89a010) state2(IC Card)/state3(Touch)/state6(Network)＝`mxsegaboot.md`。1つ満たすと次の
デバイスエラーへ前進（実証順 1000→5101→951→5501→8005）。HLSM は全工程 attract 到達済み。
ネットワークメッセージ: `0xbd02c4` "Network timeout error (DNS-WAN)" / `0xbd0304` "Network type error (WAN)"。

**エラーメッセージテーブル**(連続, pointer table 経由で直接 xref 不可):
`0xbd0374` IC Card R/W / `0xbd038c` Touch Panel / `0xbd03a4` USB Device / `0xbd041c` Keychip /
`0xbd0464` Game Program on Storage / `0xbd0518` Sound Function / `0xbd0534` Graphic Function。

### USB Device (951, errCode 0xf) = keychip_ctx+0xc 欠落 [S+L cdb]

「USB Device」表示だが真因は keychip ctx。usbio チェックは SysMouse(`device2`, GUID_SysMouse) を count=1 で genuine 検出済み（マウスは正常）で、951 の gate ではない。連鎖:
- `input_update_merge_dinput_jvs`(0x679de0) 末尾: count>=1 枝の条件 `(1<DAT_016b88e0) || (DAT_016b88e4!=1)`。**`DAT_016b88e4` は writer 不在で常に 0** ＝ `(e4!=1)` 恒真 → `usbio_io_status=-0x70`。
- `usbio_errCode_mapper`(0x6F0AD0): `switch(usbio_io_status)` default → `if(amlib_subsystem_state!=8) amlib_master_errCode=0xf`(=951)。
- 唯一の escape = `DAT_016014a3 != 0` = `FUN_0096c5f0()=(keychip_ctx+4 && keychip_ctx+0xc)`。keychip_ctx は +4/+8/+0x10=1 だが **+0xc のみ 0** → escape 不成立 → 951。実機は実 keychip で +0xc が立ち回避。
- **解決**: keychip_server の `appboot.systemflag` 応答 bit0 を立てると（KC_SYSFLAG=01）`amDongleSetupKeychip` case5 が keychip_ctx+0xc=1 を設定 → DAT_016014a3=1 → 951 未然防止（`mxkeychip.md`）。error scene は latch 後 errCode クリアでは消えないため未然防止が必須。
- 参考: `usbio_board_count` を +1 するのは `dinput_create_device`(0x67CBE0) の `CreateDevice(GUID_SysMouse)+SetDataFormat(c_dfDIMouse2 @0xaf48ac)+SetCooperativeLevel(hwnd@0x1696e0c)` 成功のみ。joystick 列挙(`dinput_enum_gamectrl`)は count に触らない（joystick は別系統の主操作系＝`amjvs.md`）。真のヘッドレス/マウス無し環境では count=0 になりうる（`dinput_diag` を canary として残置）。

### Dipsw / board index = board-table check (errCode 0xa / 0xb) [S+F]
- **dipsw read** `amDipswRead`(0x45a0e0, 唯一の writer): `amDipswReadByte`(0x983bb0) 経由で byte2/byte3 を読み、
  そこから派生:
  - `byte2` ← `FUN_00984190`（成功時 `*p=3` とハードコード）。`DAT_01601951`＋flag bit 0x1/0x2。
  - `byte3` ← `FUN_00984130`→`amDipswReadByte(0)`→`FUN_009836e0`（実 dipsw バイト）。`DAT_01601950`＋
    `index = (byte3>>4)&7`（`0x45A18E SHR AL,4; AND AL,7`）＋flag bits（test/service スイッチ群）。
  - flag `DAT_0160194c` bit↔reader: 0x1/0x2=`FUN_0089b230`(入力カウンタ) / 0x4=`FUN_006c3730`(log level) /
    0x8=`FUN_0045a4c0`(タイマ) / **0x20=`amlib_storage_board_check`(errCode 0xb)**。0x80 は unread。
- **board index reader は2つ** — `amlib_storage_board_check`(`FUN_00679cb0`) と `FUN_006c5470`。
- **board-table** `DAT_00b84554` はバイナリ内の静的定数（writer 無し、8×u32）:
  `[FFFFFFFF, 01, 08, 03, 0F, 04, 0A, 10]`。**index 2 のみ値 8（=有効基板コード）**。
- `amlib_storage_board_check`（`FUN_006c3730` が amlib_master_init 後に**無条件呼び出し**、amHm フラグ非依存）:
  `table[index]!=8 && errCode==0` → `DAT_016f5af0=10`(0xa) を `0x00679dae`／
  `DAT_0160194c&0x20 && errCode==0` → `=0xb` を `0x00679dc1`。errCode 0xa を消すと latch race で 0xb が surface。
- `FUN_006c5470`: 同テーブルを `switch`、case 8 以外で `DAT_016f5ac0=0x11/0x1e`。
- スタンドアロンは dipsw ドライバ不在で読み失敗 → bytes garbage → index/flag が不定 → errCode 0xa/0xb が
  画面ラッチ race の種になる。
- **errNo 対応 [L cdb]**: errCode **0xa → 画面 errNo 910 "Wrong Resolution Setting"**（解像度ではなく board-table 誤判定。SEGA カタログの文言割当）。error_scene_render(0x6f2730) の descriptor `+0x00=errCode 0xa / +0x10=errNo 0x38e(910) / +0x0c=msgPtr 0xbd04b4`。同様に errCode 0xf→951, 0x4→903。
- **dipsw read タイミングの罠 [L cdb]**: dipsw ctx provisioning（`dipsw_force_ready` / amDipswInit 0x9842a0 detour / dipsw read 0x45a0e0 PRE）では **board_index を確定する最初の `amDipswRead` に間に合わない**（その read は amlib_reset_init 経由で provisioning より前）。`FUN_009836e0` は handle 無効で書込まず byte3=stack garbage(0x5x)→index 5。
- **確実な解 = consumer hook**: `amlib_storage_board_check`(0x679cb0) を **PRE hook**（`src/host/gamehook.c` d_board_check）し判定直前に **board_index=2 + DAT_0160194c bit0x20=0** を供給。dipsw read タイミング非依存で errCode 0xa/0xb を断つ。
- **dipsw device の provisioning**（read が実 dipsw を要する場合）: `amDipswCreateDeviceFile`(0x983430) は `amEepromCreateDeviceFile`(0x984910) と同型の **SetupDi(PnP GUID 列挙)+CreateFileA** で開くため standalone では列挙失敗（名前ベース mxsmbus フックに乗らない）。EEPROM と同じ **ctx force-provision** で解決（`api.c dipsw_force_ready`）: dipsw ctx（base 0xccf488: +4 mutex / +8 handle / +0xc addr=0x20 / +0x38 busy / +0x50 event / +0 initFlag）に handle=H_MXSMBUS を入れると、read fn(`amDipswReadByteInternal` 0x9836e0)の `DeviceIoControl(0x9c402004, cmd=5)` が mxsmbus エミュへ流れ、`mxdev_ioctl` が cmd5(dipsw read, off3=index)に index0→0x20 を返す → 素の `FUN_0045a0e0` が `(0x20>>4)&7=2` で board index 2 を算出。ただし board_check の最初の read には間に合わないため 0xa/0xb の恒久解は上記 consumer hook。

---

## 周辺シリアル I/O デバイス（COM map）[S+F]

nrs.exe の I/O 周辺は **amlib device list `DAT_016db564`**（linked-list, next=`[+0x3c]`）にオブジェクトとして
登録され、各オブジェクトは `[+0x00],[+0x04]` の **class ペア**で識別される。3 系統が**シリアル(COM)**を開く。

| COM | 用途 | amlib class | open 元（static_VA） | 設定 | 本 boot での状態 |
|---|---|---|---|---|---|
| **COM1** | タッチパネル | 0x22,0x22 | `FUN_008b2450`（touch driver init） | — | open 失敗 `0xc0000034`（未エミュレート） |
| **COM2** | IC Card R/W（SEGA独自, **Aime非該当**） | 0x21,0x21 | `cardrw_object_dispatch`(0x4f2990)→`serial_dev2_init_wrapper`(0x674ad0)→`serial_dev2_init`(0x884e80) | 8E1 / 9600 | open 失敗 `0xc0000034`（未エミュレート） |
| **COM4** | JVS I/O | amJvst（別系統） | `amJvspInit`(0x986720)→`amJvstThreadInit`(0x989B10) `CreateFileA("COM4")` | 115200 / 8N1 | **開く**＝host が仮想ハンドル化し `src/logic/driver/mxjvs.c` が JVS ボードをエミュ（`amjvs.md`） |

- ポート名はいずれもハードコード。**JVS = 静的文字列 `"COM4"`**(`43 4F 4D 34 00` @ static_VA `0xAE11F0`,
  reader=amJvspInit のみ・writer 無し)。詳細 transport は `amjvs.md` §JVS I/O Subsystem。
- COM1/COM2 は汎用シリアルラッパ `serial_port_setup`(0x67c3c0, ≤3ch) の **2 呼出元**。JVS(COM4) はこれを使わず amJvst 独自スレッド。
- **ポート選択** `serial_select_com_index`(0x67C360, 暗黙 EAX 引数): touch は `-2`→COM1、card は `-3`→COM2。port 名表 `serial_com_name_table`(0xD4B440)[0..2]={COM1,COM2,COM3}。
  **kdserial（`debug_serial_flags` 0x1696AD4 bit1）有効 & index0(COM1) のとき COM3 へ remap**（カーネルデバッガが COM1 を占有→touch を退避）。retail/standalone は kdserial=OFF＝touch は COM1 固定。これが「環境により COM 番号が違う」報告の正体（COM1↔COM3）。

### タッチパネル（COM1 / class 0x22）[S]
| static_VA | 名前 | 役割 |
|---|---|---|
| `0x8B2A60` | `touch_device_factory` | class(0x22,0x22)取得→vtable 据付(+0x20=init,+0x24=poll,+0x28=shutdown)→init 呼出 |
| `0x8B2450` | `touch_panel_init` | driver init（`serial_port_setup` で COM1 を開き device 構造体を構築） |
| `0x8B2750` | `touch_poll_update` | 毎フレーム: `rx_parse`→state machine(+0x3c)→`report_promote`→座標デコード。押下=`+0x210[0]≠0`→押下音`FUN_0088dd20(0x100e2)` |
| `0x8B2E40` | `touch_serial_rx_parse` | COM 受信→256B リング(`+0x50`,size`+0x150`=0x100,head`+0x154`,tail`+0x158`)→10B フレーム解析（下記） |
| `0x8B31E0` | `touch_decode_T_coord` | 'T' パケット→X/Y/Z(下記) |
| `0x8B37F0` | `touch_report_promote` | dirty(`+0x30c`)立てば受信バッファ`+0x2b8`→確定`+0x210`へ昇格、x=`+0x2dc`→`+0x234`,y=`+0x2e0`→`+0x238` |
| `0x8B3BF0` | `touch_report_push` | 21dword を `+0x2b8` へ書込み `+0x30c=1`（外部 inject 経路） |
| `0x8B3B90` | — | 確定 report 取出し（`+0x210` から 21 dword=84B コピー） |
| `0x8B3B00` | `touchpanel_status` | present 判定（`+0x18`）。handshake 完走で game 自身が `touch_init_sm`(0x8b2ad0) default case で `ctx+0x18=1`("touch panel ok.")を立て boot state3 "CHECKING TOUCH PANEL … OK" が自然通過（詐称不要） |
| `0x8B3D60` | `touch_set_calib_window` | calib 窓設定（`+0x19c/+0x1a4`=X範囲, `+0x1a0/+0x1a8`=Y範囲） |
| `0x755280` | — | タッチ UI イベント処理（raw→hit-test→画面 state 別 dispatch） |
| `0x4F9E20` | — | hit-test：タッチ座標→UI 要素 id（state 構造体 `+0x1c` index→`+0x98` table。-1=未タッチ） |
| `0x16D8690` / `0x16DB564` | — | touch device context ポインタ / device list（class 0x22,0x22） |

**transport（`serial_open_comport` 0x67BE20 の DCB）= COM1, 9600 8N1**（baud=`baud_table_00B40714[0]`=0x2580=9600,
ByteSize=8, Parity=NONE, 1 stop）。default DCB は 9600/8/EVEN/1 だが touch の config が parity を NONE 上書き。
純正側はこの COM を **SEGA カスタム VID `0CA3` の FTDI USB-シリアル**として汎用ドライバで吸収（ringedge イメージに
touch 専用ドライバ/COM/baud のソース無し。FTDIBUS が COM 番号を動的割当）。micetools の touch は **maimai 専用(maitouch)**
で BBS には無関係＝**BBS touch の正は nrs.exe のみ**。

**ワイヤプロトコル = 10 バイト固定長フレーム**（`touch_serial_rx_parse` 0x8B2E40）:
```
[0] 0x55 'U'  同期ヘッダ
[1] cmd       'T'=タッチ座標 / 'A'=ack(byte1==ctx+0x3a で ctx+0x3b=1) / 'P'=param(byte3:5→ctx+0x28=0, 6→=1)
[2..8]        data 7B（'T' 時の意味は下記）
[9] checksum  (Σ byte[0..8] − 0x56) & 0xff == byte[9]
```
**'T' 座標ペイロード**（`touch_decode_T_coord` 0x8B31E0, リトルエンディアン16bit枠）:
```
byte[2]      status/id          → ctx+0x166
byte[3:4]    X  12-bit(0..0xFFF) → ctx+0x160（軸反転 +0x21c = 0xFFF − X）
byte[5:6]    Y  12-bit(0..0xFFF) → ctx+0x162（軸反転 +0x220 = 0xFFF − Y）
byte[7:8]    Z/筆圧 8-bit(0..0xFF)→ ctx+0x164
```
正規化 float: `+0x228`=Xn, `+0x22c`=Yn, `+0x230`=Zn（係数 `DAT_00c916d0`/`DAT_00c91068`）。確定座標は `+0x234`(x),`+0x238`(y)。

**入力経路は 3 系統**（report_push 0x8B3BF0 の呼び元を確認）: ①COM1 シリアル(実機) ②replay(`DAT_02281d58`
配列→`FUN_0089c250`→report_push) ③**デバッグマウス**(`FUN_0089c550`, `amDebug_flag_hi&1` ゲート→report_push)。
②③は `report_push→+0x2b8→promote(+0x30c dirty)→+0x210` を通る。SEGA 自身が③でマウス→タッチを注入している。

**実装（COM1 シリアルエミュ, `src/logic/driver/touch.c` + api.c 配線）**: COM1 を仮想シリアルとして open/comm_control 成功化し、ReadFile で現マウス座標の `'U' T ..` 10B フレームをストリーム、WriteFile の `'p'/'P'` コマンドへ `'P'`(byte3=6→+0x28=1) ack を返す。pseudo handle `0xC0114001`。座標は GetForegroundWindow の client rect に対しマウス位置を 0..0xFFF へ正規化。

⚠️ **落とし穴1 = ClearCommError cbInQue**: serial RX ポンプ `serial_rx_pump`(0x67c0c0) は `ClearCommError` → **`comstat.cbInQue!=0` のときだけ ReadFile** する。touch はストリーミング型（host が write せず panel が 'T' を常時送出）でこのポンプ依存。`on_comm_control` の CLEAR_ERROR で COMSTAT をゼロ化すると ReadFile が来ず touch.read=0。**修正＝touch handle の CLEAR_ERROR で `cbInQue=TOUCH_FRAME_LEN`（常に1フレーム受信待ち）を申告**。JVS は write→read 同期でこのポンプを使わない（master 駆動 req/resp）ため cbInQue 不要＝両者の決定的な差。

⚠️ **落とし穴2 = TX フラッシュは 1 バイトずつ WriteFile**: serial TX フラッシュ `serial_tx_flush`(0x67c070)（TX ワーカースレッド `serial_tx_thread`(0x67c1a0)→`serial_tx_thread_entry`(0x67c1f0)）は **TX リングを 1 バイトずつ WriteFile** する。`touch_on_write` を 10B 一括フレーム前提で書くと n=1 で一生処理されず ack ゼロ → handshake('p'/'P')無応答で +0x28=0 のまま timeout → state 0x32(50) 固着。**修正＝バイト蓄積→'U' 始まり 10B フレーム組立**（`TouchPanel.rx[]`/`rx_len`）、完成フレームの byte1='p'/'P' に 'P'(byte3=6) ack。handshake 完走で「touch panel ok.」発火、以降 mode1 で実 serial 経路（on_read_file の 'T' フレーム→rx_parse→`decode_T_coord`）が座標を流す。

**touch-active 判定**（`touch_state_proc`(0x8b3310), mode1 処理）: status byte `+0x166` の下位2bit (`+0x166 & 3`) で touch-active。'T' フレーム byte[2]=status。active→`+0x211`=1、押下エッジ→`+0x210[0]`=1（1フレームのみ）、離し→`+0x212`=1。build_T は byte[2]=pressed?1:0 / Z(byte7:8)=pressed?0xFF:0 を送る。押下・座標・離しは正しく消費側へ到達する。

touch device は完動だが attract でタッチしてもゲーム flow は進まない（`advertise_demo_controller` 0x725d60 がデモページを切替えるのみで「画面をタッチしてください」は開始トリガでない）。真のゲートは ALL.Net/MMGP ゲームサーバ接続＝`facts/gameflow.md`。

### カードリーダー（COM2 / class 0x21）= SEGA 独自 IC Card R/W [S+F]

**素性**: nrs.exe に `Aime`/`felica`/`IDm`/vendor バナー文字列は**ゼロ**。ゲーム自称は **"IC Card R/W"** のみ
（`"IC Card R/W Not Found"`@0xbd0374, `"CHECKING IC CARD R/W"`@0xc811a0）。`JcvCard`(.?AVJcvCard@@) はゲームデータ class（HW 無関係）。
→ **Aime/FeliCa リーダではない**。bare-byte command/ACK プロトコルの **SEGA 独自 IC カード R/W ファミリ**。エミュ対象は class 0x21 のシリアル I/O。
**物理リーダーの vendor/型番は全オラクル sweep 済で判定不能（二度解かない）**: nrs.exe は vendor/model 文字列ゼロ・照会コマンドも送らず、純正 segadriver に card 専用 .sys 無し（COM2 は汎用シリアル）。プロトコル形状は multi-slot(最大7) addressing の card dispenser + 種別バイト→容量マップ。旧磁気 Sanwa 系（8N1・STX/ETX ASCII フレーム）は本機（IC・8E1・裸バイト・checksum無）と全不一致で除外。

**Transport**（`serial_open_comport` 0x67be20 の DCB / `serial_dev2_init` 0x884e80 の config）:
**9600 baud / 8 data / EVEN parity / 1 stop（8E1）**、XON/XOFF、0x200B リングバッファ×2。
baud は `baud_table_00B40714[1]`（raw 未読、fallback 9600。我々は OS 境界で仮想化ゆえ baud は物理無関係）。

**Framing**: **裸のコマンドバイト**（length field 無し・**checksum/CRC 無し**）。
各 opcode に固定 1 バイトの期待 ACK（`card_cmd_ack_expected` 0x8850c0）。
レスポンスは**ステータスバイト** `*`(0x2a)→3 / `:`(0x3a)→4 / `J`(0x4a)→5 / `Z`(0x5a)→6 / `0xcb`→7 / `0x1a`→busy を
`card_rx_status_decode`(0x66f8a0) でデコード（内部 0=pending, 1=OK）。多バイトは `card_frame_append2`(0x884bb0,+2B)/
`card_frame_append4_be`(0x884c00,+4B BE)。送信は `card_serial_send_frame`(0x884c60)→`card_serial_write`(0x884b50)→
`serial_write_txring`(0x67c210)。**注**: `_DAT_01265714=0x46('F')` はフレーム同期バイトではなく**タイムアウトカウンタ**（直後 0x884b50 で 10000 上書き）。

**コマンド体系**（opcode→ACK/wire 完全表は下「operational プロトコル（実体確定）」）。builder(static_VA):
F7=`card_cmd_reset_0xF7`0x66fb80 / 28=`card_cmd_sense_0x28`0x66fcc0 / 4D=`card_cmd_poll_0x4D`0x670040 /
0D=`card_cmd_read_attr_0x0D`0x6704e0 / 2D=`card_cmd_read_data_0x2D`0x670300 / 8D=`card_cmd_read_data_0x8D`0x6708e0 /
AD=`card_cmd_commit_0xAD`0x670dd0 / 38=`card_cmd_halt_0x38`0x66fe60 / 68=`card_send_addressed_cmd_0x68`0x884f40 /
B8=`card_cmd_setspeed_0xB8`0x884ff0 / ED=`card_cmd_capacity_0xED`0x6706d0。ACK 表=`card_cmd_ack_expected`0x8850c0。
低ニブル=操作種別（`0x?D`=read/write）。0x6D=スロット選択(ACK 'K'0x4b)、予約 0x1D/0x88/0x58/0xCD。
**最大 7 スロット** addressing（`slot_addr_table_00b40bf4[0..6]`, `card_slot_next`0x66f7d0/`card_slot_cycle`0x66f800 で 0→6 巡回）。

**デバイス識別（核心）**: ファームウェア/バージョン照会も vendor バナーも**送らない**。
カード種別は**リーダーが返す 1 バイト**で判定 → 容量にマップ（`card_type_to_datalen` 0x66f690）:
**`0x36`→0x7c0(1984B) / `0xc9`→0x3c0(960B) / `0xff`→0xfc0(4032B)**。同バイト 0x36/0xff が RX callback `card_rx_status_callback`(0x674a70) をゲート。
カードヘッダは **64B(16dword) を BE byte-swap**（`card_header_byteswap_be` 0x66f6d0）→ UID/属性取得 → whitelist(`DAT_016a55b0[]`,count`DAT_016a55ad`)照合。

**状態機械**:
- transport pump `card_transport_pump`(0x674530): sub-state `DAT_016ae53c` 0/1=init, 2/3=enum+read, 4/5=write, 10=READY/idle。`DAT_016ae538=1`=device found。
- op dispatcher `card_op_dispatch`(0x674b30): `DAT_016ae5c8` cmd class 2=poll/read(len 0xfc0), 3=write(0x1008B image), 0=idle。
- high-level FSM `cardrw_highlevel_fsm`(0x4f2d40): state3 0=wait-slot("card slot ok" when `016ae5c8==1 && 016ae5cc==-1`), 3/4=read, 5=write→成功で image コピー＋callback。
- object update `cardrw_object_update_sm`(0x4f2ad0): state2 0=poll→1=detect/read(`cardrw_advance_to_present`0x4f6810)→2=hold/present(hold-timer `[0x1588]`減算→0復帰)。
- **ready bit** `cardrw_ready_bit1`(0x4f6310): `card_flags>>1 &1`。boot "CHECKING IC CARD R/W"(state2, amlib_init_sm 0x89a010)が `!=0` を無期限ポーリング。err bit `cardrw_rw_error_bit4`(0x4f6330): `>>4 &1`。
  card serial emu(card.c)が実 handshake を完走させると game 自身が card_flags bit1 を立て boot "CHECKING IC CARD R/W … OK" が自然通過（詐称不要）。
- context getter `cardrw_device_status_ptr`(0x4f3e30): device list を class(0x21,0x21) で検索。約100関数が参照する大サブシステム 0x4f3-0x4f8。

カードコンテキストは **0x6720B/device, ストライド 0x6714**（`cardrw_ctx_init` 0x4f2910 が memset）。

**実装**（`src/logic/driver/card.{h,c}` + `api.c` 配線・動作検証済み）: 方針 = 仮想カード永続 R/W（UID+データブロック, card.bin 永続化, TeknoParrot 流）。
COM2 を pseudo handle `0xC0114003` で仮想化し byte-exact handshake を実装。フレーム=`[ACK b0][status b1][payload]`（再同期なし・半二重 turnaround を opcode 長テーブルで実装）、CLEAR_ERROR の `cbInQue=card_rx_pending()`。
TX framing: 0xF7=1B(trailer無)・0x68=3B(`FUN_00884f40`)・0x48=1B。init 完走で "card slot ok" 発火（touch「touch panel ok」相当）。
- init SM=`card_init_sm`(0x670f70): case10→f7 / case0xC→68 06 40 / case0x10→48、成功で `DAT_016ae538=1` device-found→substate10。init 最終段 `b8 cf`(0xB8 SET COMM SPEED)→ACK 0a。
- transport pump=`card_transport_pump`(0x674530): case1=init / case3=poll-read(`card_read_sm` 0x671470) / case5=write(`card_write_sm` 0x671de0)。

**operational プロトコル（実体確定）**:
- **コマンド体系**（`card_read_sm` 0x671470 / `card_write_sm` 0x671de0）:

  | opcode | 機能 | 送信 wire | 期待ACK byte0 / frame len | result getter |
  |---|---|---|---|---|
  | `0xF7` | reset/open | `F7`(1B) | 0x0A / 1 | — |
  | `0x68` | init set-param | `68 p1 p2`(3B, `card_send_68` 0x884f40) | 0x0A / 1 | — |
  | `0x48` | get FW/status | `48`(1B) | 0x0A / 1 | `FUN_0066f940`(byte&0x40 等) |
  | `0xB8` | **SET COMM SPEED** | `B8 CF`(2B, 0x884ff0) | **0x0A / 1** | →SetCommState(0x67c4c0) |
  | `0x28` | sense | `28`(1B) | 0x0A / 1 | status |
  | `0x4D` | **SEARCH(UID read)** | `4D`(1B) | 0x0B / 9 | `card_get_uid_record`(0x885260, 8B byteswap) |
  | `0x2D` | select(UID) | `2D`+8B(2×append4_be) | 0x8B / 1 | — |
  | `0x0D` | read block | `0D`(1B, index は DAT_016a0396 事前設定) | 0x2B / 129 | `card_get_read128`(0x8852f0, 128B) |
  | `0xED` | capacity/free | `ED`(1B) | 0x8B / 3 | `card_get_status2`(0x885350, 2B) |
  | `0x8D` | read ptr/compare | `8D`(1B) | 0x8B / 3 | `card_get_status2` |
  | `0xAD` | commit/write | `AD`+4B(append4_be) | 0x8B / 1 | — |
  | `0x38` | halt/deselect | `38`(1B) | 0x0A / 1 | status |

- **present/absent 極性**（`card_rx_status_decode` 0x66f8a0 + `card_cmd_ack_expected` 0x8850c0）: **received byte0 == 期待ACK → decode 1 = present**（byte1 無視）。
  **nocard = 単バイト `5A`('Z')**（byte0=0x5A は ACK と不一致→cVar1=0、DL に残る 0x5A='Z'→decode 6）。`0B 5A…` は ACK 一致で present 誤認になるので不可。
- **frame 長則**（`card_frame_len_for` 0x8848d0, **再同期なし**）: byte0 で完成長確定 — 0x0A→{送信0x58:2/0x88:19/他:1}, 0x5A→1, 0x0B→9, 0x2B→129, 0x8B→{0x2D/0xAD:1, 0x8D/0xED:3}。emit は期待ACK 先頭＋表通りちょうど。
- **read SM フロー**: reset(F7)→sense(28)→`card_read_setup`(0066fff0)→search(4D)[ret6=nocard→halt / ret1=present→UID抽出(`DAT_0169e314`=UID,`DAT_0169e31c`=type)]→select(2D)→read(0D×N: 128B/回, header byteswap 0066f6d0, image=`&DAT_0169f338+slot*0x1008`)→commit(AD)→halt(38)。UID whitelist=`DAT_016a55b0[]`(count `DAT_016a55ad`)。容量=`card_type_to_datalen`(0x66f690)。card image 0x1008B=64Bヘッダ+~4032Bデータ。

**Phase B2（仮想カード挿入＋データ R/W＋永続化）配線済み**（attract 中は能動 poll しない＝SEARCH(0x4D) は coin/touch→card-login で走る。データ授受の一部は live 未確証）:
- **IPC**: loader が `nrsedge.card.json`（present/image/type/gen）を書き、logic の `card_control_poll`(on_jvs_tick)が last-write 変化時に `host->orig(CreateFileW/ReadFile)`（フック迂回）で読み image を `st->card.image[0x1008]` へ反映。insert/eject/UID-load は検証済み。card.bin 永続化=eject 時 dirty 保存。
- **card.c build_response**: 0x4D present=`[0B][1A][type][UID 4B BE][pad]` / 0x2D=4B addr+4B len BE→read_cursor / 0x0D=`2B`+image[cursor..+128]（card.bin=純ワイヤ image・swap 無し）/ 0xED/0x8D=`8B`+容量2B / 0xAD=4B addr→write_addr。
- **残（live 確証要）**: 8B UID record の正確な byte 順と 0xAD 後続 write データのフレーミング。`coin/touch→card-login` で 0x4D/0x2D/0x0D/0xAD を駆動して確定する。

**ゲーム側カード認識の機構（SEARCH→select→read flow 完走）**:
- **カード挿入の out-of-band 検出信号供給**: `api.c card_force_present` が present 時に `device_status+0x5628`(presence/read-trigger)=1 を供給 → `FUN_004f6a30` present 化＋read シーケンサ `FUN_004f30a0` がキックされ SEARCH(0x4D) 発火（attract でも背景検出が走る）。presence フィールドのみ in-band 供給する（flags/state2 の直接 poke は生 SM を撹乱しクラッシュ）。
- **SEARCH 応答のフレーム長**: 0x4D present 応答は **0x0B→9B**（payload 8B, `card_get_uid_record` 0x885260 が payload を `DAT_01265722..29` に取込）。`0B 1A type UID[4] 00 00`。1B 不足で re-sync 崩壊→read SM が -0x61→クラッシュ。
- **read/write**: `0x0D` read block は **3 バイト `0d HH LL`**（1B 扱いだと続く `00 00` が 0x2B+128B 応答を tx リセットで消去し「データ読み込み中…」停止）。`0x2D` は **select-by-UID**（read addr ではない）。SEARCH→select(0x2D)→read(0x0D×N, 128B/回)→commit(0xAD)→halt(0x38) が完走。read config は `FUN_00674800` が設定（read 中 `DAT_016a55ba`=bypass=1 / maxlen=0xFC0 / whitelist count=0）＝**whitelist は照合されない**。

**「このカードは使用できません」の真因 = ALL.Net カード情報ネットワーク（カードデータ形式ではない）**:
card-auth scene(0x5e6200) は読んだ UID で `RequestSendAdapter<NetDataCardinfoRequest>`(FUN_007203e0) をサーバ送信し `ResponseRecvAdapter<NetDataCardinfoResponse>`(FUN_007205b0) を受信してプレイヤープロフィールを得る。プロフィールはサーバ側で、カード(4032B)は ID に過ぎない。standalone は応答が得られず「使用できません」。net.connect 先 = `127.0.0.1:40080`（ALLNET_PORT, naominet.jp:80 振替。cardinfo は NUPL POST タスクとして `allnet.c build_nupl_inner` が応答。PCP 40113 ではない）。
シリアライザ = `NetDataCardinfoRequest/Response::class2Binary/Binary2Class`(0x90f2b0/0x90f3e0/0x913460/0x913590, 非パック RE 可)。→ カード使用化 = ALL.Net カード情報応答のエミュレート（PCP/network 層）。カードデータ形式の forge では解決しない。
- **チェックの精密な所在（逆算用）**: 3 段すべて NUPL ネットワークタスク依存:
  1. `FUN_00717da0`: task list(DAT_016db564) を uid=`0x4c50554e`("NUPL"=ALL.Net session task)で探し、ctx=`*(node+0x10)` の **+0xd8（応答ステータス）** を返す。`FUN_007205b0` はこれ==0（応答受信済）のときだけ処理。standalone は NUPL 応答が来ず ≠0 → カード情報パース不能。
  2. `FUN_007205b0`: NUPL ctx の応答 binary を `NetDataCardinfoResponse::Binary2Class`(0x913590) でパースし scene card-data(*(scene+0x56c))へ格納。
  3. card-auth scene(0x5e6200) case3: `local_1204`(=card-data +0x3c, 応答のカードステータス)で分岐。**==1=有効カード**（使用可）/ default=無効。
  → 注入点 = **NUPL task ctx**（+0xd8=0 にし、応答 binary 域に status=1＋profile の `NetDataCardinfoResponse` を置く）。

- **【解決済】ALL.Net NUPL セッション init ハンドシェイクの応答書式（S+L 実証）**: cardinfo 以前に NUPL セッションが `init` で確立する必要がある。standalone は init 応答が拒否され `NUPL obj+0xd8: 1→-1` で 60s 毎に無限リトライ＝session 未確立＝cardinfo が飛ばず「使用できません」。真因は応答の `command` field 書式:
  - **二段階で消費される**: ① 封筒パーサ `nupl_recv_envelope_parse`(0x712710, __thiscall(obj,body,len)) が body を '&'(`DAT_00bb39dc`)/'='(`DAT_00ba4d88`) で分割し `command_common` id 一致＋`response_header` status0 で **obj+0xd8=0**（成功）。② その後 NUPL SM が **init 専用パーサ `nupl_init_response_parse`(0x92bb10)** で同 body を再パース、失敗時 obj+0xd8=-1。
  - **init パーサの必須 gate**: `command` field 値が `DAT_0126728c="init_response"`(0xc8df04, 静的初期化 0xad8a62) と **strcmp 一致必須**（不一致で即 -1）。以降 `protocol_version`/`command_common`/`response_header`/`local_uid`/`db_start_time`/`db_stop_time` が全て present かつ各 parse OK で成功（map lookup ゆえ順序非依存）。
  - **正しい init 応答**（`src/host/allnet.c build_nupl_inner` init 枝・実装済）: `command=init_response&protocol_version=92b2d258&command_common=<echo>&response_header=0del&local_uid=0000000000000000&db_start_time=2000-01-01 00:00:00.0&db_stop_time=2030-01-01 00:00:00.0&`（zlib STORED+base64+`Pragma:DFI`）。
  - **確証（headless）**: 修正後 `nupl.state d8:0 sm:2`＝init 受理・session SM 前進、`alabex.diag authok:1 lan:1`。診断は host hook `d_recv_parse`(0x712710 PRE/POST, `recv.parse.pre/post`) と `nupl_diag`（`api.c`）。req(`init_request`)/応答(`init_response`)は動詞ペア名（応答値は request に現れず binary の parser のみが正）。
  - **write-back**: 上記関数名は Ghidra DB に永続化済（`nupl_recv_envelope_parse`/`nupl_init_response_parse`/`nupl_init_response_serialize`(0x92c3b0)/`nupl_init_response_cmdname_getter`(0x92cd30)）。
  - **残**: cardinfo 応答（5611B binary, 別 consumer `FUN_00717cb0`/Binary2Class 0x913590）は card-select 到達＝GUI+実タッチが要り headless 未確証。init 確立でその経路は unblock 済。

- **【GUI 実写確認 2026-07-12】init 修正後の card-select 到達と card-auth 未遷移（capture.png + touch 注入で実証）**: init 修正で boot 完走（SYSTEM STARTUP 全 OK・**SERVER:01**・ALL.NET AUTH/UPLOAD/GAME SERVER OK）→ attract「画面をタッチしてください」到達。touch 注入(`nrsedge.touch.json` press/xm/ym)で attract→**カード選択**画面（EntryModeGamePoint 系）到達。`nrsedge.card.json` present 0→1 を card-select active 中に行うと card read 発火（`card.sm` sub:5 cls:3→sub:10 req:1、UID=`3a2a2d9d` で loop せず完走）。**ただし card-auth scene `EntryModeCheckCard`(0x5e6200) は活性化せず**（`scene.diag cardauth_active` 常に 0）、cardinfo POST も飛ばず、数十秒で attract へ復帰。**「このカードは使用できません」は再現しない**（card-auth 未到達ゆえ）。
  - **card-select→card-auth の gate が次の壁**: card.bin `cards/TA-29.bin` は UID(offset4=`3a2a2d9d`)以外ほぼ全 zero＝未登録カード。blank card が有効カードとして受理されない／card 使用選択が要る可能性。entry-mode sel 進行 gate（`STATUS.md` フロンティア #1）＝ card-select scene が card-auth へ遷移する条件が未証明。

- **【GUI 実写 + 診断 2026-07-12】cardinfo 未発火の真因 = NUPL session SM が state 3 に到達しない（S+L 実証）**:
  - **カードは ID に過ぎず内容検証は無い（RE 確定）**: read SM `card_read_sm`(0x671470) は `DAT_016a55ba` bypass=1 で内容非検証、UID(header offset4 BE, `card_header_byteswap_be` 0x66f6d0 が in_EAX[1]=UID として読む)だけ抽出。magic/checksum 無し。write SM(0x671de0)も diff-based block write で content-magic 無し。**カードデータ forge は解決策でない**（既存事実と一致）。card 生成 = `tools/make_card.py`（UID を offset4 BE, 残 0 の 4104B）。**落とし穴**: `nrsedge.card.json` の image パスは forward slash（single backslash は `cj_str` が `\s`→`s` で破壊しロード失敗→UID=0→無効カード扱いで read loop）。
  - **cardinfo(card-auth) 送信ゲート = `FUN_00717620`(0x717620) が `NUPL_obj+0x200fc == 3` を要求**。card-auth scene(0x5e6200) case2 が `FUN_00717620` true のとき `RequestSendAdapter<NetDataCardinfoRequest>`(0x7203e0) を送る。診断 host hook `d_cardinfo_send`(0x7203e0, `cardinfo.send`) は GUI で card 挿入→read 完走しても**一度も発火せず**＝cardinfo は送られていない。
  - **NUPL SM は state 2 で停滞**（`nupl.state d8:0 sm:2`）。init envelope 修正で sm 1→2 は達成、しかし 2→3 が起きない。card-auth scene 案 case2 `if (FUN_00717620()) send cardinfo` の gate が false のまま。
  - **SM 駆動機構が静的 dispatcher と食い違う（要深掘り）**: `FUN_00712600`(0x200fc dispatch tick, state1→`FUN_007136d0` / state2→`FUN_007137a0`/state3→handler chain) を hook しても**発火せず**（`gamehooks.ok` 確認済）。だが `FUN_007136d0`(唯一の 1→2 advancer, xref は `FUN_00712600` のみ)経由で sm は 1→2 前進している。⇒ nupl.state が読む NUPL task obj(node tag "NUPL", node+0x10 double-deref) と `FUN_00712600` が操作する obj が別、または SM は htmg client/別スレッド経路で駆動される。**sm 2→3 の実駆動関数の特定が未達**。state2 深部パーサ `FUN_00714230`(0x714230, `FUN_00902040` deserialize + 4 date/array parse) も未発火＝到達していない。
  - **⇒ 残作業 = ALL.Net game-backend session 完走**（`真のブロッカー = ALL.Net/MMGP play-session` の本体）: (1) NUPL session SM を state 3 へ進める実駆動経路の特定＋その条件充足（完全な init/session 応答が要る可能性大）、(2) sm=3 で cardinfo 発火後の 5611B 応答検証。これは複数セッション規模の深い network protocol RE。

- **【SM deadlock 精密解剖 2026-07-12】NUPL SM が state 2 で構造的にデッドロック（L 実証・診断 `nupl.s2`）**:
  - SM tick は生きている: 診断 `nupl.s2`（`api.c nupl_diag`, obj+0x2012c/20124/20120/20128 を記録）で state2 handler `FUN_007137a0`(0x7137a0)が毎 tick 走り tnow(=clock, obj+0x20128)が進む（elapsed 増加）ことを確認。**だが sm は 2 のまま前進しない。**
  - **デッドロック機構**: `FUN_007137a0` は先頭で timeout 分岐 `if (tflag(0x2012c)!=0 && tdur(0x20124) <= elapsed)`。**state1 handler `FUN_007136d0`(0x7136d0) が 1→2 遷移時に tdur=0 をセット**するため（`obj+0x20124=0`）、state2 では `tdur(0) <= elapsed` が常時真→timeout 分岐へ。そこで `if (FUN_00713550()) return;`。**`FUN_00713550`(0x713550) は retail(kdserial `DAT_01696ac8` bit1=0)で常に true を返す**（先頭 `if((DAT_01696ac8>>1&1)!=0 && …)` が false → default `return true`）→ handler が return。⇒ その後の advance 分岐 `if(d8==0){ if(FUN_00714230()==0) 2→3前進 }` に**到達しない**。
  - 対照: state1 の timeout 分岐は gate 無しの `FUN_00713d30()`（無条件 re-send）＋tdur=60000 設定ゆえ deadlock しない。state2 だけが `FUN_00713550` gate で re-send を抑止し deadlock。
  - `DAT_01696ac8` = **game config/DIPSW block**（test-menu editor `FUN_008a0ed0`(0x8a0ed0) の case2 が bit1 を toggle、writer `FUN_004fd440`(0x4fd440) が backup config から copy、`DAT_01696ab0..ad0` の一部）。**実測 orig=15 ＝ bit1 は既に 1**（実験 poke は冗長で sm は 2 停滞のまま）。⇒ **bit1 は原因でない。仮説 refute 済**。
  - **【cdb 動的確定 2026-07-12】state2 deadlock の真因 = time-schedule gate `FUN_0076de00`（cdb 実測）**:
    - 前回「obj+0xd4 が関数途中」は **hex 誤算**（5371520 = 0x51F680, 0x51F400 でない）。obj+0xd4=`0x51F680` は正当な callback。obj は正当 heap obj（cdb: esi=`0x1d2ca0d0`, sm=2）。
    - **cdb 実測**（`nrs` ASLR base 0x210000, VA-0x400000 offset で bp）: state2 handler `FUN_007137a0` の `CALL FUN_00713550`(0x7137cd)直後 `al=01`(true) を連続観測。advance-block `CALL FUN_00714230`(0x713826) は**一度も hit せず**＝2→3 前進不能を動的確定。
    - **`FUN_00713550` 分岐 trace**: bit1=1✓/sm=2✓/callback `[obj+0xd4]=0x51F680` 呼→**return 1**(≠0)→ `[obj+0x20185]=0`,`[obj+0x20187]=0`(cdb db 実測,両>=0)→ `FUN_0076ddd0`+`FUN_0076de00` path → `SETGE AL`。
    - **`FUN_0076de00`(0x76de00) = time-of-day 差分計算**（分, ×0x3c=60）。param_1=obj+0x20185, param_2=obj+0x20187(scheduled time {hour,min}), param_3=`FUN_0076ddd0` の変換時刻。obj times=0 だと `(24-cur_hour)*60 - cur_min` ≈ 720〜780(常時>=0)→ `FUN_00713550` true → **session が時刻ゲートで待機継続**。
    - **⇒ 真のブロッカー = session の time-schedule window**。obj+0x20185/0x20187(scheduled time, standalone=0)が適切非0値なら `FUN_0076de00`<0 → false → re-send(tdur=60000)→ advance-block 到達 → sm 2→3 → cardinfo の道が開く。`FUN_00713550` は enqueue/cardinfo gate/state handler 共通の time-gate。
    - **【解決・cdb 実証 2026-07-12】obj+0x20185/0x20187 の writer = `FUN_00713eb0`(0x713eb0, state1 advance gate)**: init 応答を `nupl_init_response_parse` でパースし、**db_start_time/db_stop_time の {hour,min}** を FUN_007230f0(日付parser)で obj+0x20187(start)/obj+0x20185(stop) へ格納。⇒ init 応答の db 時刻がこの gate を制御。
    - **fix（実装済・実証）**: `allnet.c` init 応答の **db_stop_time を "23:59:00" に変更**（db_start=00:00 のまま）。cdb で `FUN_0076de00` の実測入力 p1_185={23,59}/p2_187={0,0}/p3_cur={0,1} → **戻り -1（<0）** → `FUN_00713550` false → **deadlock 解消**。nupl.state で req_id が増加＝session が re-send を開始し、**game が次コマンド `attend_request` を送出**（init → attend へ前進）。
  - **【進行中】ALL.Net session コマンド連鎖: init✓ → attend → …→ sm=3 → cardinfo**。各コマンドは strict parser（init=`nupl_init_response_parse` 0x92bb10 "init_response" / ping=`FUN_00939b50` "ping_response" / attend 等= unified parser `FUN_00902040` が `FUN_00404b20("field")`+`FUN_0040b190` presence check で全 field 必須）を持ち、`command="<cmd>_response"` 固定＋全 field present が要る。attend serializer=`FUN_00906d60`(ms_url/ms_port/gp_by_Ncredit/map_id/rules/event_*/… ~70 field)。`allnet.c build_nupl_inner` に attend 枝を追加したが、複合 field(map_id/rules/event_*)を空にしており deep parse が d8=-1（複合 field の format 要特定）。**残: attend 応答の全 field(特に複合構造)を valid 化 → 後続コマンド → sm=3 → cardinfo。これは MMGP session config 層の実装。**

- **【パッチ再評価 2026-07-12】genuine ALL.Net 成立後、network/region cluster 3 パッチは冗長（撤去済・boot 完走確認）**:
  - 撤去: `0x6FF1B3`(LAN flag→1)/`0x45A846`(errCode=4 store nop)/`0x6FF980`(hlsm_region_check→1)。genuine ALL.Net auth(authok=1,lanflag=1)供給で boot は region error 無く attract 完走（GUI 実写確認）。`patches.applied` 15→12。
  - **ただし session deadlock の原因ではない**: 撤去後も NUPL sm は 2 停滞のまま（患部は上記 SM deadlock で patch と無関係）。ユーザー疑義（patch が悪影響）への回答＝network/region patch は「今や冗長」だが「session block の原因ではない」。
  - **落とし穴（テスト手順）**: `nrsedge.card.json` の image パスは **forward slash 推奨**（`C:/src/bbs/...`）。single backslash JSON は `cj_str`(api.c)が `\s`→`s` と escape 誤処理しパス破壊→image ロード失敗→UID=0→game が read loop（無効カード扱い）。loader.exe はダブル backslash で書くので正。card 挿入検出は **card-select active 中の present 0→1 遷移**が確実（attract 中挿入は background read になり scene 未反映）。screenshot は cwd に `capture.req` を置くと次フレーム `capture.png` 保存。

**cardrw object SM の memory-state 経路（認識はシリアル経由でない）**: card-select 画面でもゲームは serial SEARCH(0x4D) を撃たない（撃つのは handshake の f7/68/48/b8 のみ）。認識は cardrw object SM の memory state 経由で、present 詐称＝serial emu を ready にするだけでは届かない。
- **scene の present ゲート（全 case 共通）**: `obj=node[4]`（class 0x21,0x21 ノード, `cardrw_device_status_ptr` 0x4f3e30）、`device_status=obj+4`。判定 = `*(int*)(device_status+0x5628)!=0`（presence/read-seq state）かつ `flags(+0)&0x10(error)==0`、または `FUN_004f2d20()`。
- **cardrw_object_update_sm(0x4f2ad0) 検出鎖**: case0 state2(=`device_status+8`) 0→1 は `flags&0xc0` / case1 `advance_to_present`(0x4f6810, state2 1→2＋flags|0x1000) 呼出は `(flags&0x400)==0 && bit7 clear` / case2 は presence query `FUN_004f6a30`(=`device_status+0x5628!=0`)が真でないと hold せず state2→0 へ revert。
- **read シーケンサ `FUN_004f30a0`** は `device_status+0x5628` を state とする（case0 が zero にするのは隣の `+0x562c`）。`advance_to_present` が呼ぶ `FUN_004f3c80` は buffer memset のみ。
- 診断 `card.sm`（`api.c card_sm_diag`: devf/sub/cls/req + dsflags/state2/presence）を温存。card-select 画面でしか最終確証できない（attract では scene 非活性）。

amlib エラーメッセージテーブルでは `0xbd0374` IC Card R/W。

- **【ALL.Net game-backend session 全体像 2026-07-12】** nrs.exe の NUPL(ALL.Net game server)コマンド全集（strings 抽出, `*_request`/`*_response`）:
  init / attend / ping / start / end / netentry / matchingstat / modein / cardinfo / carddata / reissued /
  eventinfo / event_rank / places / rank / ngword / nickname / seal / replay_u / replay_d / cap / params /
  image / imginfo / file / delivinst / delivreport / advertiseinfo / selecterinfo / invalid。
  各コマンドは strict parser（`command="<cmd>_response"` 固定 + 全 field present + 各 field の型別 parse）を持つ。
  **臨界パス（カード認識まで）**: init✓ → attend → …(session establish, sm=3) → cardinfo/carddata（カード auth）。残りは gameplay 系（カード auth 後）。
  - **transport**: base64(zlib deflate) + envelope `command=..&command_common=..&response_header=..&` + `Pragma:DFI`。allnet.c が naominet.jp→loopback:40080 で応答。envelope parser=`nupl_recv_envelope_parse`(0x712710, MinHook 済ゆえ cdb bp 不可)。
  - **各 response は独自 parser**（init=`nupl_init_response_parse` 0x92bb10 / ping=`ping_response_parse` 0x939b50）。attend の deep parser は `FUN_00714230`/`FUN_00902040` では**ない**（cdb で未 hit 確認）＝コマンド別 dispatch。attend serializer `FUN_00906d60` は ms_url/ms_port/gp_by_Ncredit/**map_id/rules/event_attr/event_param/event_result/ranking(複合バイナリ構造, FUN_008f0130/FUN_00908c80/cf0/d60/dd0/e40)** 等 ~70 field。複合 field は空だと deep parse が d8=-1（要 per-field format RE）。
  - **cdb 注意**: MinHook 済関数(0x712710 等)への bp は hook と衝突。非 hook 関数(0x713550/0x76de00/0x714230)は bp 可。session 再送は tdur=60000（60s 周期）ゆえ短時間 window だと miss する。
  - **残作業（大）= 各コマンドの response を実装**（strict parser を 1つずつ RE→valid response→session 前進）。init 済、attend WIP（複合 field 要 RE）、以降 ~48 コマンド。MMGP session config + matching + card data 層＝複数セッション規模。

- **【並列 RE 2026-07-12: 全 ALL.Net 応答パーサ・フィールド仕様】**（workflow allnet-cmd-re, 27 agent）。各 command の strict parser（`command="<cmd>_response"` 定数 strcmp + 全 field presence check `FUN_0040b190`, 欠落で obj+0xd8=-1）:
  - **envelope 共通 4 field**: command / protocol_version / command_common(`FUN_008e5390`) / response_header(`FUN_0094a9b0`)。allnet.c が top-level で供給。
  - **session-config（attend`FUN_00902040`=旧誤名 nupl_session_response_parse_unified を訂正・attend_response_parse へ / start / netentry / matchingstat）= 68 field**。複合配列 field は固定/最小数の comma レコード必須: **map_id=int×40 / rules=×16(`FUN_008fa2e0`, ~0x2bc B/record) / event_attr=×3(`FUN_0094ac80`) / event_param=×3(`FUN_008f33e0`, 0x2c0 B) / event_result=×3(`FUN_008f70f0`) / ranking=×4+(`FUN_008f0220`, 0x64 B) / ranking_coefficient(`FUN_008f8a50`)**。leaf format は record workflow で確定中。
  - **cardinfo（card-auth 応答）= TEXT 45 field, parser `cardinfo_response_parse`(0x90fed0)**（**旧 fact の 5611B binary/Binary2Class は cache/save 経路で、NUPL wire は text が正**）。**`card_status`(int) が有効カード判定**（=1 で使用可）。profile field: card_id/launch_code/access_code/name/custom(>=40 sub, 未解決)/event_id[3]/dotnet_*/clan_*/clangroup_*/dotnet_custom[4]/chip_reserv[10]/boostticket[30]/event_stat[3]/…/mattrans_*。card 挿入で送出。
  - **小 command（envelope 以外に複合無し=即実装可）**: end(ms_stop_flag/card_id/dotnet_flag) / rank(7) / ngword(ng_word) / cap(5) / image(3) / selecterinfo(2)。実装済み（allnet.c NUPL_TEXT テーブル）。
  - **binary payload**: places / nickname / imginfo。**未発見**（要再RE）: reissued / event_rank / replay_u / replay_d / delivreport。
  - **実装**: `allnet.c build_nupl_inner` を table 駆動へ refactor。command 名は 0x30 挿入除去（`'0'` 全除去）+`_request` 剥がしで判定。

- **【cdb 実測確定 2026-07-12: ALL.Net 複合フィールドの配列/要素セパレータ = リテラル "del"】**（3 byte: 0x64 0x65 0x6c）。全複合フィールド共通の唯一のトークン区切り。tokenizer `FUN_008e57d0` が global std::string `DAT_01266f60`（SSO: buf@0x1266f60 / size@0x1266f70=3 / cap@0x1266f74=0xf, runtime nrs+0xe66f60 で `64 65 6c 00`/size 3 を実測）を `std::string::find`（`FUN_0055a2a0`）し、毎マッチ +3 で前進。**並列 agent の推測 `","`/`%2C` は誤り**、runtime dump が正。CRT `_initterm` 初期化（image は zero・静的 xref 無し）ゆえ**実行中プロセスの dump のみが正**。rules 値 = 16 record×161 token = 2576 token を "del" で連結した 1 本の flat stream（record 境界は 161-token 定間隔・位置のみ、専用区切り無し）。

- **【ALL.Net session sm=2→3 確立の全要件（cdb 実証 2026-07-12）】** attend_response(FUN_00902040)を通し state handler FUN_007137a0 が `iVar2=FUN_00714230(); if(iVar2==0){ obj+0x200fc=次state(DAT_00b3bbe4 table) }` で SM 前進。attend 応答が満たすべき条件（順に判明）:
  1. **区切り = リテラル "del"**（3B、cdb 実測 DAT_01266f60）。全複合配列共通。
  2. **recv 前段 FUN_00712710 + deep parse FUN_00902040 冒頭の pre-split 検証**: 応答を "&" 分割→各フィールドを "=" 分割し **厳密に 2 要素(key=value)必須**。**空値 `key=` は count1 で C++例外→-1**。→全フィールド非空値。
  3. **複合配列は各 record が sub-parser 込みで多め token 消費**（flat field 数≠token 数）。caller の record 境界 stride が record parser 消費より大きい。実測: **rules=16rec×~188 境界→4000 token / ranking=4rec×25→240 / map_id=40(==0x28 厳密)/ event_param=600 / event_attr=24 / event_result=36 / rcoef=15**。caller は N record 読んで停止＝overshoot 無害（map_id 除く）。
  4. **state handler FUN_00714230 が一部フィールドを datetime 再パース**（FUN_007230f0→__mkgmtime64、format `YYYY-MM-DD HH:MM:SS`（len>18）、obj+0x2045c..+0x2047c 格納）。→ ms_close/ms_open/ms_maintenance_time/全 *_update を `2000-01-01 00:00:00.0` に。
  5. **FUN_00722f20 = base64 デコーダ**（len<4 で 0 返し失敗）。**book_keep_flg は base64 blob 必須**（len≥ ~12、"0" 不可）。これが最後の gate＝sm=3 到達の決め手。
  - 実装 `allnet.c build_session_config`（attend/start/netentry/matchingstat 共通）。**sm=3 到達で game は cap/params/seal/… command を送出開始**。

- **【card-auth「このカードは使用できません」= res:-97 の真因（RE 2026-07-12）】** card-select scene で仮想カードは card 読取まで到達（`card_read_sm` 0x671470, req:1→res:1 で UID 読取成功）するが **UID whitelist 不一致で拒否**。機構: bypass `DAT_016a55ba`==0 かつ whitelist(`DAT_016a55b0[]`, count `DAT_016a55ad`)に読取 UID(`DAT_0169e314`)が無い → data block を読まず → halt 再照合(count!=0 path)で `DAT_0169e368=1` → default case `local_9c=(-(DAT_0169e368!=0)&3)-100 = -97`（=SM result `DAT_016ae540`）。config globals: bypass=`0x16a55ba` / count=`0x16a55ad` / UID配列=`0x16a55b0` / 必要block数=`0x16a55ac` / maxlen=`0x16a55b8`（standalone では未populate＝boot 時 count:0 だが card-select 時には populate 済＝要実測）。**fix 候補: (a) bypass=1 を logic で供給（全 card 受理）/ (b) 読取 UID を whitelist へ追加**。card_force_present と同流儀の runtime global 供給。cardinfo(ALL.Net) はこの受理ゲートの後段。
- **【crash 注意】** card-select で res:-97 拒否が続くと game が access violation で crash（host crash handler が bt 記録し terminate）。card 受理を通せば回避見込み。

- **【res:-97 解消 = card_read_sm(0x671470) host hook で UID whitelist を確定 bypass】** logic per-frame の global 供給（bypass=0x16a55ba=1 / count=0x16a55ad=0）は card_read_sm が別スレッドで走り game が count を周期再populate するため **race で漏れ res:-97 残存**。**host gamehook で card_read_sm 入口に detour(`d_card_read_sm`)を置き、同スレッドで毎回 bypass=1/count=0 を設定** → 確定受理（res:1・-97 皆無を実測）。gamehook.c 追加、要 host 再ビルド+restart。所有カード受理 policy（standalone は正規 whitelist 無し）。

- **【card 受理: ~13s 再強制で fix が無効化される未解決事象】** card_read_sm(0x671470) の whitelist を (a) logic per-frame global 供給 (b) host gamehook 入口 (c) static code patch(0x6717d5 JNZ→nop / 0x671aac JLE→JMP) のいずれでも、起動後 **~13s まで res:1（受理）→ 以降 res:-97（拒否）に戻る**。3 手法とも同時刻で無効化＝config global(count) の周期再populate か CrackProof のコード整合性復元が疑わしい（boot patch 12 個は無事＝card_read_sm 領域固有の可能性）。res(DAT_016ae540) は card_transport_pump が card_read_sm の戻り値(EBP=local_9c、default case で -97)を書く。**次の一手候補: ~13s イベント特定（card reader 再init / CrackProof scan の trigger）／ card UID を game の whitelist entry に一致させる（whitelist source 特定）／ CrackProof 領域を継続再patch。** card 読取(UID)自体は成功。cardinfo(ALL.Net) は本受理ゲートの後段で未到達。

- **【SYSTEM STARTUP CHECKING CONNECTION チェックの機構（ALL.Net パッチ撤去 2026-07-12）】** boot SM `amlib_init_sm_SYSTEM_STARTUP`(0x89a2xx)。case4=NETWORK, case6=ALL.NET AUTH/UPLOAD/GAME SERVER/LOCAL 各項目を `amlib_device_status_getter`(0x72dce0, device manager+0x1d4+idx*4) で読み **status==2 で OK・非2 で NG**（device manager = class0x20/0x20 タスクの *(node[4])）。実測 status=[2,2,3,3,1,1]（AUTH=2 OK / UPLOAD・GAME SERVER=3=error / LOCAL=1=in-progress）。撤去した device_status パッチ(0x72dce0→ret 2)はこれを全部 2 にマスクしていた。**正しくエミュレート = 各 ALL.Net デバイス操作を成功させ status を 2 にする**。
  - **network フラグ**（同 check の error 条件, uVar5&0x5f3）: `0x210b50a/b/c`。setter(0x6ff140) は NIC ディスクリプタ `[0x210b5bc]/[0x210b5c4]/[0x210b5cc]`（`*(ptr)==2`=接続, `+4`=IP）から算出。b50c(LAN)=b50b かつ 2nd NIC IP==1st NIC IP。**撤去した LAN パッチ 0x6FF1B3 は `MOV [0x210b50c],0` の即値を 1 に書換え強制していた**（NIC が条件未達のため）。→ 正しくは NIC 状態を接続==2・IP 一致で供給。
  - region パッチ(0x986A66/74/92, Err0x381/387/38D)も撤去対象。**残作業 = NIC 状態供給(OS境界) + UPLOAD/GAME SERVER/LOCAL デバイス操作 emulation + region**。診断 `amlib.devstat`(logic) 設置済（network フラグの実アドレスは 0x210b50a/b/c に要修正）。

- **【CHECKING CONNECTION 各デバイス = 独立 ALL.Net サービスの PCP 応答（genuine 化スコープ 2026-07-13）】** boot SM の CONNECTION 項目(AUTH/UPLOAD/GAME SERVER/LOCAL, device manager+0x1d4+idx status 2=OK/3=err/1=wait)は、それぞれ loopback PCP ポートの ALL.Net サービスに依存。実測 status=[2,2,3,3,1,1]（AUTH ok, UPLOAD/GAME SERVER=3 err, LOCAL=1 wait）。**NIC/network フラグ(b50a/b50b/LAN=1)は genuine に OK＝LAN パッチ撤去は問題なし**。
  - **ポート↔サービス（kc.exchange 実測）**: 40100=mxmaster / 40102=amInstall(check_appdata/query_*_status) / 40106=keychip(appboot/decrypt/ds.compute=code54 bypass/ssd.proof=code54 bypass/setiv/version) / 40110=amNet(stopcatcher) / 40113=amGfetcher(get_status/isrelease/pause/resume/set_auth_params)（cardinfo は PCP でなく NUPL 40080） / **40114=amStorage(query_storage_status)** / 30000=?。**未 listen だと接続拒否→device err**。keychip_server PORTS に 40103/40108/40112/40114/40115/30000 を追加済。
  - **query_storage_status(40114)** = amStorage タスク(FUN_0097b300 amStorageTaskRequest)。応答から `check`/`format` フィールドを読む独自 SM。現状 kc_respond 未処理(code=0)。**要: 正しい storage 応答実装**。
  - **残 genuine 化 = UPLOAD/GAME SERVER/LOCAL/storage 各デバイスの ALL.Net サービス応答を 1つずつ RE→実装（device status を 2 に）+ region チェック(0x986A66)**。device_status パッチ(0x72dce0)撤去でこれら全露出。マルチサービス規模。診断 `amlib.devstat`(logic) + `kc.exchange`(keychip_server ポート別) 設置済。

- **【amStorage SM = 多状態 storage protocol（RE 2026-07-13, port 40114）】** `amStorageWaitReady`(FUN_0097b440)は state(`PTR_DAT_00ccf0f0+0x14`)駆動の SM: state2=query_storage_status（ready 待ち・8回まで retry(counter puVar3[0x24])→query_storage_count）/3=query_storage_info /4=check /5=format /6=get_volume /7=set_volume /8=mount /9,10=umount /0xb=query_drive_letter /0xc-0x11=backup storage 系。**state は応答パーサが設定**（FUN_0097b300 amStorageTaskRequest が応答 field 名 check/format/query_storage_status を読む）。現状 check=0/format=0 応答では storage が ready 判定されず **state2 で query_storage_status を 56回ループ**（実測）。genuine 化には **query_storage_status 応答の正しい status field（storage ready/mounted）を応答パーサ RE で確定**する必要。UPLOAD(idx2) がこれに依存（storage 応答追加で一度 2 到達）。**GAME SERVER(idx3)/LOCAL(idx4) も同様に各サービス SM の response parser RE が要る＝ALL.Net system 層の複数サービス emulation（大規模）**。HW write-break(cdb `ba w4`)は頻繁書込みでブート激遅化＋不発火で本環境では非実用。

- **【boot SM CHECKING CONNECTION の真のゲート = manager+0x1ec エラー累積器（RE 2026-07-13, amlib_init_sm_SYSTEM_STARTUP 0x89a010）】**
  - **case6(CHECKING CONNECTION) の device status 配列(manager+0x1d4)は表示専用**：sub-state3 のループが getter で idx1-4 の status を読むが、0/2/3 いずれも印字して次へ進むだけ。**status=1 のときだけ待機、3(error)でも fail しない**。∴ idx2/3/4 が 3 でもここは通る。
  - **真の合否**: case6 sub-state100 = `uVar5 = param+0x1c | *(manager+0x1ec); if(!b50a)|=0x800; if(!b50b)|=0x1000; if(!LAN)|=0x100; if((uVar5 & 0x5f3)==0) → state7/8(成功) else state9(err 0x14)`。**マスク 0x5f3 = bits{0,1,4,5,6,7,8,10}**。b50a/b50b(0x800/0x1000)はマスク外で無関係、LAN(0x100=bit8)のみ関与（確認済OK）。param+0x1c は case6 で 0 のまま。**∴ ゲート = `*(manager+0x1ec) & 0x5f3 == 0`**。
  - **case4(NETWORK)は別ゲート**: sub-state2 が getter で特定1デバイスの status を見て、==2 なら OK、非2なら param+0x1c=0x80(g_net_link_up&&FUN_0045ab40 成立時 0x400) を立て sub-state100 の同 `&0x5f3` で fail。**case4 は device status==2 を要求**（idx は EAX 依存＝要特定）。
  - **∴ 本命 RE 対象 = manager+0x1ec に bit{0,1,4,5,6,7,8,10} を立てる書込み箇所**（各 ALL.Net サービスのエラー累積）。0x1d4 setter は case4 の 1 デバイス用に副次的に必要。
  - case5=extend_image_install（extend_image_install_status<4 待ち, DVD時 0xc)、case7=pras_billing_ready_check、case8=billing無効時skip。

- **【runtime 実測で真ブロッカー確定＝LOCAL GAME SERVER(idx4) が status 1 のまま（2026-07-13）】** amlib.devstat 診断ログ実測: **m1ec(manager+0x1ec) はブート全体で常に 0** ＝ CHECKING CONNECTION ゲート `&0x5f3==0` は既に満たされる。デバイス status 推移の最終 = **[2,2,3,3,1,1]**（idx1 AUTH=2 通過, idx2 UPLOAD=3 通過, idx3 GAME SERVER=3 通過, **idx4 LOCAL=1 で停止**, idx5=1）。case6 sub-state3 は `status!=1` でのみ前進するため **idx4 が in-progress(1) のまま＝表示ループがここで無限待機**。**idx4 が 0/2/3 いずれかの終端に達すれば boot は state7/8 へ抜ける**（3=error 表示でも可）。∴ 残作業は単一: **LOCAL GAME SERVER(idx4) デバイスタスクを終端させる**（何を待って in-progress のままかを RE）。UPLOAD/GAME SERVER の genuine 化は boot 通過には不要（既に terminal 3 で通過）。

- **【device-status SETTER と idx4 停止機構 完全解明（RE 2026-07-14, Ghidra DB 命名済）】** device status 配列(manager+0x1d4[idx0..5]) の**唯一の writer** = `amlib_conn_check_status_sm`(**0x72a6a0**, 旧 FUN_0072a6a0)。呼出元 = `amlib_device_manager_tick`(0x72bc30) が `EAX=manager+0x1c8` で毎フレーム call。SM object(ESI=manager+0x1c8) レイアウト: `[0]`=SM state / `+8`=timer / `+0xc..+0x20`=**manager+0x1d4..0x1e8=status idx0..5** / `+0x24`=manager+0x1ec=error累積。per-service check（各 case が status を 1(kick)→2(ok)/3(err) にセット）: case1→idx0(net link) / case3→idx1 AUTH(`amlib_auth_ready_check` 0x72dcb0) / case5→idx2 UPLOAD(`FUN_007175e0`) / case7→idx3 GAMESERVER(`amlib_gameserver_ready_check` 0x72df40) / **case9→idx4 LOCAL GAME SERVER**。case10 = 非2 の service を周期 retry（state0/2/4/6/8 へ戻す）。
  - **idx4(LOCAL) ゲート = manager+0x204**: case9 は `ESI+0x3c`(=manager+0x204) を読む。`==2`→idx4=2(OK)、`==3`→idx4=3、`0/1` かつ case9 timer(`DAT_00c916c8` 由来, ESI+8)が生存中→**break（idx4=1 のまま保持）**、timer 満了→idx4=3。∴ **manager+0x204 が 2 に到達しない限り idx4 は 1(大半)↔3(瞬間) を周回** → 表示ループ(0x89a6e0)が status!=1 の瞬間を捉えられず実質停止。
  - **manager+0x204 の writer** = `amlib_conn_exec_sm`(**0x72a200**, 旧 FUN_0072a200)。conn_check_sm が各 case 末尾で `ESI+0x2c`(=manager+0x1f4) を渡し call。exec SM の status field `ESI+0x10`=**manager+0x204**、own state `ESI+4`=manager+0x1f8。stage: init(0-1)→prepare(2-3, +0x10=1)→connect/auth(4-5, DAT_020f493c で +0x10=2/3)→**data-exchange(6-7)**→done(8)。case6=`FUN_006a4340` が非同期 request を queue `DAT_020f4970` へ enqueue(handle=ESI+0x28=manager+0x218)、case7=`FUN_006a5ee0`(→`FUN_006a2f00` で queue から結果 dequeue)。**応答が 0x14(20)byte で期待データと一致した時のみ +0x10=2**、それ以外 3。standalone では此の request/response 交換が成立せず manager+0x204 が 2 に到達しない＝idx4 未終端。
  - **∴ boot 通過の最小要件 = manager+0x204 を 2 にする**（clean には idx1-4 全 2 で overall idx5=2 も 2 化）。手段候補: (a) ALL.Net 非同期 queue(DAT_020f4970) の LOCAL GAME SERVER request に valid 20B 一致応答を供給（`FUN_006a4340`/`FUN_006a2cd0` enqueue と `FUN_006a2f00` dequeue のペイロード RE 要）、(b) OS 境界/logic で manager+0x204=2 を out-of-band 供給（card_force_present 流儀）。**getter 0x72dce0 パッチ撤去後の残ブロッカーはこの 1 点**。

- **【UPLOAD(idx2)/GAMESERVER(idx3) を OK にする genuine 要件＝ALL.Net ゲームサーバ接続 emulation（RE+実測 2026-07-15）】** boot 通過は非致命だが「画面で OK 表示」には両 ready-check を窓内で成立させる要。**UPLOAD が最有望・GAMESERVER は新規サブシステム規模**。
  - **UPLOAD ready = `FUN_007175e0`**（check SM case5, timer≈AUTH から ~15s）: device list(`DAT_016db564`)から `node+4=="NUPL"`(0x4c50554e) を探し、`node+8 & 3`・`*(node+0x10)!=0`・`FUN_00712d40()!=0` で ready。`FUN_00712d40` gate = `nupl_session_wait_gate(0x713550)==0`(db_stop_time=23:59 で成立済) かつ NUPL `node+0x200fc==3`(session cmd 状態) かつ `node+0xdc==0`(=time_now-node+0xe4≈0, 応答直後) かつ `node+0xe0<30000`。**実測: ret 0→3 に到達する＝gate は通せる。但し attend_response 到達時**。
  - **真ブロッカー = init→attend の固定 ~60s 待機**（実測: init 02:27:13→attend 02:28:13, リトライ無しの純待機）。UPLOAD の attend 依存 readiness が case5 の ~15s 窓に間に合わず timeout→3(NG)。この 60s は session 送信スケジューラのクライアント側サイクル（`f20120`=NUPL obj+0x20120=60000ms、init パーサ 0x92bb10 でも recv envelope パーサ 0x712710 でも書かれない＝応答フィールドで直接制御不可）。delivinst も ~61s 周期。**genuine 加速 = 送信スケジューラ(未特定)が窓を早める条件を RE、または attend を早送りする ALL.Net 応答挙動を発見する必要**。
  - **GAMESERVER ready = `amlib_gameserver_ready_check`(0x72df40)**: `deviceMgr+0x7c`(=`ncli::NetCli` ゲームサーバ client, ctor `FUN_00702640`/vtable 0xc42d74)の vtable[+0x24] メソッド戻り。**実測: netcli obj 存在するが ready() は最後まで 0**。attend_response の `ms_url=0&ms_port=0`（matching server 未提供）で NetCli が接続先を持たず未接続。**genuine 化 = attend で valid ms_url/ms_port を返し、その matching/game サーバ TCP 接続プロトコルを emulate（LFS 同様の新規サブシステム規模）**。
  - **∴ 全 OK は「ALL.Net matching/game-server 層の実 emulation（送信間隔短縮＋NetCli 接続）」= 大規模**。standalone(offline) では NG が実機同等の真値でもある。cosmetic 即時策は device_status パッチ(0x72dce0→ret2, 撤去済)復活だが非 genuine。診断は gamehook `d_upload_ready`/`d_gsvr_ready`(READ ONLY・用済み撤去、再取得は再設置)。

- **【★UPLOAD(idx2) genuine 化 完了＝実時刻 PowerOn で 60s init→attend gap 解消（RE+実測 2026-07-16）】** ※下段「決定的制約」は**誤り**だったので訂正。60s は不可避でなく、我々の PowerOn 応答が現在時刻を **00:00 固定**で返し db_start_time(00:00) と一致していたための time-window gate 境界待ちだった。
  - **セッションフェーズ駆動 `FUN_00712600`(NUPL obj)**: `obj+0x200fc`=phase（1=init `FUN_007136d0` / 2=attend `FUN_007137a0` / 3=定常 params/seal/cap/ping）。**UPLOAD gate `FUN_00712d40` は phase==3 を要求**。
  - **phase1(init)→2 の前進条件**: init 応答受理後 `nupl_state1_advance_parse_dbtime`(0x713eb0) が **0 を返せば即前進(interval=0)**、非0 で 60000ms リトライ。この関数は db_start_time/db_stop_time を `FUN_007230f0` で 2 回パース（両成功で 0）＋ obj+0x20185-88 に {hour,min} 格納。**実測: datetime パースは成功**（診断 `diag.dtparse` ret AL≠0）。
  - **真の 60s = phase2(attend)送信を `nupl_session_wait_gate`(0x713550)→`nupl_session_time_window_gate`(0x76de00) がブロック**。gate 戻り = **(db_start{hh:mm} − current{hh:mm}) 分**、`>=0` で wait / `<0` で proceed。現在時刻は session 時計 `obj+0xd4()`（PowerOn 応答の year..second 基準＋実経過）。**db_start=00:00 かつ PowerOn=00:00 → 差=0 で境界待ち → 時計が次分(00:01)に進むまで最大60s ブロック**（分 granularity）。
  - **genuine fix（allnet.c PowerOn 応答）**: `year..second` を **GetLocalTime の実時刻**にする（実機 ALL.Net サーバ挙動）。current > db_start(00:00) で gate 即 proceed → attend 即送信 → phase3 到達 → **UPLOAD…OK を実測**（AUTH/UPLOAD/LOCAL=OK）。真夜中の 00:00 分のみ差=0 なので `wHour==0&&wMinute==0→wMinute=1` で丸め。ゲームメモリ無改変。
  - **残: GAME SERVER(idx3)** = NetCli(deviceMgr+0x7c, vtable[9]=`FUN_007032a0`) readiness = `*(char*)(netcli+0x11b4)!=0`。attend の ms_url/ms_port(現状=0) で game server へ接続確立が要る（別サブシステム）。

- **【★ GAME SERVER(idx3) readiness の実体＝sphingo spPing UDP 8B エコー（RE 確定 2026-07-16, 未実装）】** 当初「LFS 同等の TCP 新規サブシステム規模」と見積もったが**誤り＝実体は 8B UDP ping エコー**。GAME SERVER readiness は TCP 接続でも受信メッセージ解析でもなく、**マッチサーバへの sphingo(spPing) UDP ping が応答を返したか**。ネイティブ ICMP でなく **UDP** ゆえ OS 自動応答は効かず host responder 必須。
  - **アドレスの機微（重要）**: readiness getter `FUN_007032a0`(0x7032a0) の this = `deviceMgr+0x7c = NetCli+4`。ゆえに getter 相対の「netcli+0x11b4」は**絶対 `NetCli+0x11b8`**（slot0 要素 @NetCli+0x11b0 の +8 byte）。getter/reset(`FUN_00703d42` が両 slot をクリア)/setter 全経路この絶対アドレスで整合。
  - **readiness setter = `netcli_on_ping_result_set_ready`(0x7025d0)**（NetCli vtable の CallbackIF +0x64 メソッド, `(this=NetCli base, slot, status)`）: slot を[0,1]クランプ。`status==1`(ALIVE)→ `*(char*)(NetCli+slot*0x40+0x11b8)=1`＋`+0x11ba=1`(変化flag)。`status==2/3`(unreachable/timeout)→ 0。
  - **poll = `netcli_sphingo_poll_results`(0x8928b0)**: ping対象ベクタ(NetCli+0x1144, 12B/entry: +0=handle/+4=slot/+8=pending)を毎tick走査し `sp_ping_get_result`(0x9f0370) 結果で `this->vt[+0x64](slot,status)` 発火。`sp_ping_get_result`: sphingo内部status→ case3→1(ALIVE)/case2→2/case1→3/case0→0(pending)、RTT=`FUN_009f2d70`。
  - **connect/ping 経路（gethostbyname 不使用）**: slot要素SM `netcli_slot_ping_setup_sm`(0x7021a0) が `inet_addr((char*)(element+7))`(対象IP文字列), `htons(element+0x20)`(対象port) で sockaddr を作り `netcli_sphingo_pingms_add_target`(0x891750) へ。ping開始 `netcli_sphingo_pingstart`(0x891320)→`sp_ping_start`(0x9f0450)→`sp_sif_init_ping_udp_bind`(0x9fb670)＝`socket(AF_INET,SOCK_DGRAM,0)`+bind **ローカルport 23456(0x5ba0)**。ms_url ホスト名→IP は別途 alDns resolver(`FUN_0070de50`)が担うと推定。
  - **★ワイヤ書式（確定）**: `sp_sif_send_ping_8b`(0x9fb8f0) = `sendto(sock, buf, 8, 0, target, 0x10)`。**8B UDP ペイロード**: `[0..3]=htonl(seq/id)`(`*(u32*)(target+0x50)`), `[4..7]=htonl(timestamp)`(`FUN_009f2ca0`)。宛先=対象IP:ms_port、送信元= :23456。
  - **★host responder 最小契約**: 対象IP:ms_port で UDP 待受け、受信 8B をそのまま（少なくとも先頭 id/timestamp 保持）ゲームの :23456 へエコー返信 → `sp_ping_get_result` ALIVE → 0x7025d0 が readiness=1 → check SM `amlib_conn_check_status_sm`(0x72a6a0) case7 GAMESERVER 突破。allnet.c に UDP エコースレッド1本追加で完結見込み（LFS の TCP responder より単純）。
  - **config 構造体レイアウト**（serializer `FUN_00904bd0`/`FUN_00906d60` で裏取り, config base=param_1）: `ms_url`=std::string@`config+0x4c` / `ms_port`=int@`config+0x68` / ms_ping int@+0x6c / ms_close str@+0x70 / ms_open str@+0x8c / ms_maintenance_time str@+0xa8 / ms_maintenance_week int@+0xc4 / ms_match_flag int@+0xc8。ms_port は attend の10進文字列を `FUN_00405020` で数値化。ms_url は生ホスト名/IP（`inet_addr` 経路ゆえ最終 IP、http:// 形式ではない）。
  - **未確定（明日の RE 起点）**: (a) config(ms_url/ms_port)→element+7(IP文字列)/element+0x20(port) を書く「arm」関数（0x11b7 の書き手はリテラル検索に出ず未特定。次に見る: alDns resolver 完了 cb `FUN_0070dd60`(0x70dd60) 経由の書込み、`netcli_slot_ping_setup_sm` の呼出文脈）。(b) 返信パケットの厳密照合条件（seq一致必須か/送信元照合か/長さ）。次に見る: ping受信スレッド `FUN_009fbcc0`(結果取得)/recvfrom `FUN_009ff120`/`FUN_00a052f0`。(c) attend_response_parse(0x902040) 内 ms_url が URL 全体かホスト名のみか。
  - **Ghidra DB 書き戻し済み（この RE セッションで永続化）**: 0x7025d0=`netcli_on_ping_result_set_ready` / 0x8928b0=`netcli_sphingo_poll_results` / 0x7021a0=`netcli_slot_ping_setup_sm` / 0x702340=`netcli_slots_tick` / 0x7028e0=`netcli_tick_vt50` / 0x891320=`netcli_sphingo_pingstart` / 0x891750=`netcli_sphingo_pingms_add_target` / 0x9fb8f0=`sp_sif_send_ping_8b` / 0x9fb670=`sp_sif_init_ping_udp_bind` / 0x9f0370=`sp_ping_get_result` / 0x9f0450=`sp_ping_start` / 0x9f01a0=`sp_ping_set_target_wrap`。コメント: 0x7025d0/0x7032a0(this=NetCli+4 注記)/0x9fb8f0(8B仕様)。

- **【※訂正済み・誤りだった注意書き】決定的制約(UPLOAD/GAMESERVER boot 窓内 OK は genuine 不可)】** ↑上段で覆した。以下は当時の（PowerOn=00:00 前提の）誤った分析。NUPL 送信スケジューラ `FUN_007137a0`(session obj=in_EAX) を完全解析:
  - 各送信後 interval `obj+0x20124` を **60000ms(60s) 固定リテラル**にセット。fast-path（`obj+0xd8==0` 応答成功 かつ `FUN_00714230()==0`）のみ interval=0（即次送信）。**`FUN_00714230`=attend_response 専用パーサ**ゆえ **attend_response 到達時だけ** fast-advance が効く。∴ init→attend は fast-path 不成立で **必ず 60s interval 待ち**（attend→params→seal→cap→ping はその後 fast-path で 1 秒内連続）。sender=`FUN_00714050`(obj+0xfc memset, obj+0xd8=1 inflight, request build)。slow-path=`FUN_00712280`(obj+0xd8=1/obj+0xd4=-1 再arm)。状態=obj+0x200fc（DAT_00b3bbe4 table で advance、attend 処理後のみ 3 到達）。
  - **UPLOAD ready は obj+0x200fc==3（=attend 処理後）依存 → init+60s 以降**。boot の case5(UPLOAD)判定窓は **~15s**（AUTH OK 02:27:28→NG 02:27:43 実測、timer `DAT_016d829c*DAT_00aeb4c4`）。display ループ(0x89a6e0)は idx2 の**初回解決を1度だけ読む**（case10 retry で後に idx2=2 になっても display は再読しない）。∴ **60s>15s ゆえ UPLOAD は必ず初回 NG**。session 開始を最早(host.ready 直後)にしても attend=init+60s は窓を超える。
  - **GAMESERVER も同構造**: NetCli 接続先 ms_url/ms_port は attend_response 由来（init+60s）ゆえ readiness も窓外。
  - **根本**: 実機は ALL.Net セッションを OS デーモン(mxmaster/mxnetwork)が電源投入時から常時維持し、game の CHECKING CONNECTION 時には既に確立済 → OK。本 emu は session が **nrs.exe 内部状態**で game boot と同時開始ゆえ 60s poll を先取りできない。**60000/case5-timeout は game 定数＝genuine(無改変)では短縮不可**。∴ 全 OK 表示には (a) game 定数 patch（60000 interval or case5 timer or device_status 0x72dce0→2 mask, 非 genuine）か (b) NG を offline 真値として受容、の二択。

- **【idx4 LOCAL GAME SERVER 詰まりの確定診断＝LfsClient 接続失敗・空 URI（runtime+RE 2026-07-13）】**
  - exec SM(amlib_conn_exec_sm 0x72a200) 実測: **state5(connect/auth ポーリング)で停止**、manager+0x204(=ESI+0x10)=1 のまま。runtime globals: **connres(DAT_020f493c)=2**（connect 失敗コード2）, **ready(DAT_020f4934)=0**（async client 未接続）, armed(DAT_020f4940)=1, **uri(DAT_0126591c)=""（空）**, **ctype(ESI+0x1c)=1**。
  - case5 の connres switch: `case0→+0x10=2(成功)`, **`case2→+0x14|=0x20 で return（前進せず）`**, case3→+0x40, case6→+0x10=2。∴ connres=2 で永久 state5。
  - **ctype==1 が効く**: connres==0 なら `if(ESI+0x1c!=1)`=偽ゆえデータ交換(case6/7 の20バイト応答)を**スキップして即 +0x10=2＝idx4=2 完了**。∴ **唯一の要件 = connres(DAT_020f493c)==0**。
  - connres の書込みは FUN_006a3550(**LfsClient=Local game server client コンストラクタ**, DAT_020f47e0=LfsClient vftable, base+0x15c=connres)の init(=0)のみが静的 xref。値2は client メソッドが this+0x15c へ書く。
  - **根本原因 = URI(DAT_0126591c) が空** → LfsClient が接続先を持たず connres=2、winsock connect も飛ばない（40080 以外の connect ログ無し）。URI は FUN_0089cdc0/cfd0/d090/d210/d430 クラスタが文字列リテラルから組む。
  - **genuine fix = (1) URI を正規機構で設定 + (2) LfsClient のローカルゲームサーバ接続プロトコルを emulate して connres=0**。= 新規サブシステム（規模中〜大）。timeout 経路(+0x10=3)は存在するが case10 retry で idx4=1 に戻り、boot 表示ループ(0x89a6e0)と timing race で 3 を捕捉できず hang。

- **【LFS(LOCAL GAME SERVER/idx4) genuine 化 完了＝CHECKING CONNECTION 突破（実装+実測 2026-07-13）】**
  - LFS は実 Winsock プロトコル: client が UDP :30002 bind→"LFSS"(0x5353464c) hello を broadcast(:30001)→応答で TCP server IP:port 取得→TCP :30000 connect→**サーバの accept push を passive 待機**（client は TCP で何も送らない）。in-process サーバ(0.0.0.0:30001/30000)は稼働するが standalone で TCP accept 直後に close し client send 失敗(linkresult=6→connres=5)。
  - **接続完了契約**: `lfs_link_tcp_recv_parse`(0x6b12b0) が 4B BE length prefix + body{[0]magic"LFSS", [4]msgtype=4(u16), [6]ver=0x0405, [8]self_len==prefix, [0xC]id, [0x10]flags(bit0=1 accept/bit1=0), [0x14]aux} を検証→state8/linkresult=0→**connres(DAT_020f493c)=0**→exec SM case5 が manager+0x204=2→check SM case9 が idx4=2。ctype==1 ゆえデータ交換不要。
  - **genuine 実装（host/allnet.c・ゲームメモリ無改変・OS 境界のみ）**: (1) h_sendto が探索 broadcast の宛先 0.0.0.0/255.255.255.255/LAN-bcast :30001 を 127.0.0.1:30001 へ振替（in-process UDP サーバが応答）。(2) h_connect が client の TCP :30000 connect を自前 responder `lfs_listen`(127.0.0.1:LFS_TCP_PORT=40130)へ振替。(3) `lfs_client` が accept 直後に 28B accept `00 00 00 18 | 4C 46 53 53 | 04 00 | 05 04 | 18 00 00 00 | id | 01 00 00 00 | aux` を push、parse 完了まで接続維持。
  - **実測結果**: connres=0, ready=1, device status に idx4=2 出現。scene sig 993ee090(停止)→ゲーム本体シーン群へ遷移、device manager 破棄([-1..])＝**amlib boot フェーズ完了**。エラー無し・描画継続。
  - 注: idx3(GAME SERVER)/idx5 は 3(error)のまま循環するが case6 表示ループ非致命(status≠1で前進)・m1ec=0 ゆえ boot 通過に無関係。LFS 応答内容は不問（flags bit0 のみ必須）。
  - **【筐体ロール依存の再解釈（2026-07-15）】** 上記 LFS 突破は **SERVER ロール時の挙動**。LOCAL GAME SERVER(idx4) の要否は role global `DAT_01696ad8`(0=SATELLITE/1=SERVER, id は +ad9。TEST メニューで選ぶ永続設定＝backup 保存、writer は PUST 周期タスク `FUN_008a2210`)に依存する。**SATELLITE は店内 LAN の SERVER 筐体を UDP 探索(:30001 LFSS)で探す前提**で、standalone には SERVER 筐体が無く探索応答が返らず LOCAL GAME SERVER が status1(進行中)のまま無限待機する。allnet.c の LFS は TCP responder(:40130)のみで **UDP :30001 探索応答サーバは未実装**。**SERVER ロールに戻すと LOCAL GAME SERVER の項目自体が消え（自ホスト）**、CHECKING CONNECTION 通過→attract 完走（実写確認）。SATELLITE を genuine 対応するなら UDP :30001 探索応答の実装が要る。is-DVD 兼用(`FUN_004fda50`=role∈{1,2})は patch 0x4FDA50 RET0 で脱結合済ゆえ SERVER でも Error 913 は出ない。

- **【★ genuine ブート完走達成: boot→ALL.Net セッション完走→前面メニュー(2026-07-13)】**
  - LFS(idx4) genuine fix で CHECKING CONNECTION 突破後、ゲームは **完全な NUPL play-session ハンドシェイクを完走**: init→attend→params→seal→cap→advertiseinfo→ping→**delivinst**（各1回・retry無し）。
  - **delivinst(配信インストール)** = boot 通過後 MMNW シーンの関門。応答実装(host/allnet.c build_nupl_inner): parser delivinst_response_parse(0x916150) の全必須 field を最小値で。**instruction_interval=厳密4個・instruction_cloud=厳密48個の int-list（区切り DAT_01266f5c=","、"del"ではない）**、instruction_id/order_time/release_time/part_size/report_interval/flag/partition。全0=配信指示なし。実測 req 1回のみ＝受理。
  - 結果: ゲームは前面メニューシーン(sig 5e43c280, タスク "TMNU")に到達し安定・描画継続・エラー無し。amlib device manager 破棄済＝boot フェーズ完了。**genuine（ゲームメモリ無改変・OS境界のみ）でブート完走。**
  - 残: 前面メニュー→カード挿入→card auth→card select("このカードは使用できません")の元来の目的。card.sm は依然 res:-97(whitelist gate, present:1)。params/ping は空応答だが retry せず（非必須）。

- **【card_read_sm(0x671470) whitelist ゲート = res:-97 "このカードは使用できません"（RE 2026-07-13）】**
  - FeliCa/Mifara 系リーダ SM: reset(0xF7)→sense(0x28)→poll(0x4D)→read_data(0x2D)→read_attr(0x0D)→commit(0xAD)→halt(0x38)。読取 UID = `DAT_0169e314`(case0x15 card_get_uid_record)、読取カード UID 配列 `DAT_0169e370`(stride 0x402, count `DAT_0169e36c`)。
  - **whitelist 照合**: case0x19 で bypass(`DAT_016a55ba`)==0 なら UID を whitelist 配列 `DAT_016a55b0`(count `DAT_016a55ad`)と線形照合。case5(halt後)の最終チェックは**各 whitelist エントリが読取カードのいずれかと一致するかを検証**、未一致エントリがあれば `DAT_0169e368=1`→state6→**res:-97**（default case `(-(DAT_0169e368!=0)&3)-100`）。DAT_0169e36c==0(未読)でも失敗。
  - **受理条件**: bypass!=0 / whitelist count==0 / 全 whitelist エントリが読取カードと一致、のいずれか。state9=res:1(成功)。
  - **genuine 解決の方向**: エミュレートカード(logic/card.c)が提示する UID を whitelist(`DAT_016a55b0`)の期待値に合わせる。whitelist の出所（config/keychip 由来）を要 RE。次段=runtime で count/whitelist値/我々の UID を diag し突合。ゲームメモリ書込は不要（カードデータ側で整合可能）。

- **【card res:-97 は whitelist bypass 後も持続＝別要因（runtime 2026-07-13）】** card_accept_gate が whitelist を bypass=1/count=0 に強制済み（card.whitelist diag 実測 count:0,bypass:1）にも関わらず card.sm res(DAT_016ae540):-97 が持続。∴ res:-97 は whitelist 最終照合ではなく: (a) `DAT_0169e368` が bypass 有効化前(~13s)に 1 化し持続（card_read_sm は clear 経路が乏しい）、または (b) リーダ層(reset0xF7/sense0x28/poll0x4D)の read 失敗→default case の retry 枯渇(DAT_016ae54d>=4)→`(-(DAT_0169e368!=0)&3)-100`。card_read_sm は FeliCa 系コマンドで COM2 SEGA IC R/W とは別レイヤの可能性。次段の card 認識調査（独立フェーズ）: DAT_0169e368 の set/clear 追跡＋リーダ層が実際に read 成功しているか（card_cmd_* 戻り値）を runtime 追跡し、我々の card.c emulation が card_read_sm の期待に応えているか確認。
