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
- **read SM フロー**: reset(F7)→sense(28)→`card_read_setup`(0066fff0)→search(4D)[ret6=nocard→halt / ret1=present→UID抽出(`DAT_0169e314`=UID,`DAT_0169e31c`=type)]→select(2D)→read(0D×N: 128B/回, header byteswap 0066f6d0, image=`&DAT_0169f338+slot*0x1008`)→commit(AD)→halt(38)。UID whitelist=`DAT_016a55b0[]`(count `DAT_016a55ad`)。容量=`card_capacity_by_type`(0x66f690)。card image 0x1008B=64Bヘッダ+~4032Bデータ。

**Phase B2（仮想カード挿入＋データ R/W＋永続化）配線済み**（attract 中は能動 poll しない＝SEARCH(0x4D) は coin/touch→card-login で走る。データ授受の一部は live 未確証）:
- **IPC**: loader が `nrsedge.card.json`（present/image/type/gen）を書き、logic の `card_control_poll`(on_jvs_tick)が last-write 変化時に `host->orig(CreateFileW/ReadFile)`（フック迂回）で読み image を `st->card.image[0x1008]` へ反映。insert/eject/UID-load は検証済み。card.bin 永続化=eject 時 dirty 保存。
- **card.c build_response**: 0x4D present=`[0B][1A][type][UID 4B BE][pad]` / 0x2D=4B addr+4B len BE→read_cursor / 0x0D=`2B`+image[cursor..+128]（card.bin=純ワイヤ image・swap 無し）/ 0xED/0x8D=`8B`+容量2B / 0xAD=4B addr→write_addr。
- **残（live 確証要）**: 8B UID record の正確な byte 順と 0xAD 後続 write データのフレーミング。`coin/touch→card-login` で 0x4D/0x2D/0x0D/0xAD を駆動して確定する。

**ゲーム側カード認識の機構（SEARCH→select→read flow 完走）**:
- **カード挿入の out-of-band 検出信号供給**: `api.c card_force_present` が present 時に `device_status+0x5628`(presence/read-trigger)=1 を供給 → `FUN_004f6a30` present 化＋read シーケンサ `FUN_004f30a0` がキックされ SEARCH(0x4D) 発火（attract でも背景検出が走る）。presence フィールドのみ in-band 供給する（flags/state2 の直接 poke は生 SM を撹乱しクラッシュ）。
- **SEARCH 応答のフレーム長**: 0x4D present 応答は **0x0B→9B**（payload 8B, `card_get_uid_record` 0x885260 が payload を `DAT_01265722..29` に取込）。`0B 1A type UID[4] 00 00`。1B 不足で re-sync 崩壊→read SM が -0x61→クラッシュ。
- **read/write**: `0x0D` read block は **3 バイト `0d HH LL`**（1B 扱いだと続く `00 00` が 0x2B+128B 応答を tx リセットで消去し「データ読み込み中…」停止）。`0x2D` は **select-by-UID**（read addr ではない）。SEARCH→select(0x2D)→read(0x0D×N, 128B/回)→commit(0xAD)→halt(0x38) が完走。read config は `FUN_00674800` が設定（read 中 `DAT_016a55ba`=bypass=1 / maxlen=0xFC0 / whitelist count=0）＝**whitelist は照合されない**。

**「このカードは使用できません」の真因 = ALL.Net カード情報ネットワーク（カードデータ形式ではない）**:
card-auth scene(0x5e6200) は読んだ UID で `RequestSendAdapter<NetDataCardinfoRequest>`(FUN_007203e0) をサーバ送信し `ResponseRecvAdapter<NetDataCardinfoResponse>`(FUN_007205b0) を受信してプレイヤープロフィールを得る。プロフィールはサーバ側で、カード(4032B)は ID に過ぎない。standalone は応答が得られず「使用できません」。net.connect 先 = `127.0.0.1:40113`。
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

**cardrw object SM の memory-state 経路（認識はシリアル経由でない）**: card-select 画面でもゲームは serial SEARCH(0x4D) を撃たない（撃つのは handshake の f7/68/48/b8 のみ）。認識は cardrw object SM の memory state 経由で、present 詐称＝serial emu を ready にするだけでは届かない。
- **scene の present ゲート（全 case 共通）**: `obj=node[4]`（class 0x21,0x21 ノード, `cardrw_device_status_ptr` 0x4f3e30）、`device_status=obj+4`。判定 = `*(int*)(device_status+0x5628)!=0`（presence/read-seq state）かつ `flags(+0)&0x10(error)==0`、または `FUN_004f2d20()`。
- **cardrw_object_update_sm(0x4f2ad0) 検出鎖**: case0 state2(=`device_status+8`) 0→1 は `flags&0xc0` / case1 `advance_to_present`(0x4f6810, state2 1→2＋flags|0x1000) 呼出は `(flags&0x400)==0 && bit7 clear` / case2 は presence query `FUN_004f6a30`(=`device_status+0x5628!=0`)が真でないと hold せず state2→0 へ revert。
- **read シーケンサ `FUN_004f30a0`** は `device_status+0x5628` を state とする（case0 が zero にするのは隣の `+0x562c`）。`advance_to_present` が呼ぶ `FUN_004f3c80` は buffer memset のみ。
- 診断 `card.sm`（`api.c card_sm_diag`: devf/sub/cls/req + dsflags/state2/presence）を温存。card-select 画面でしか最終確証できない（attract では scene 非活性）。

amlib エラーメッセージテーブルでは `0xbd0374` IC Card R/W。
