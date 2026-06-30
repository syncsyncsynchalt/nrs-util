# 周辺デバイス presence 連鎖 FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。索引 `_index.md` / 横断知見 `workflow.md`。
confidence: [S]=静的解析 [L]=ライブ実走 [I]=推論 [F]=旧 Frida 計装(履歴・再取得は Ghidra/実走)

---

## Error Scene System & Device-Presence Chain [S+F]

boot 後に居座る「Error NNNN」は**ゲームアプリのエラーシーン**（amlib 09xx 表示とは別経路）。
レンダラ `FUN_006f2730`(RVA 0x2f2730) が記述子を毎フレーム描画。記述子レイアウト:
`+0x00`=amlib errCode / `+0x04`=detail / `+0x0c`=msgPtr / `+0x10`=errNo(表示番号) / `+0x16`=flags(&4=Caution)。

**device-presence 連鎖**: errCode→errNo→fix の対応は `src/logic/patches.c`。発生源関数は
`FUN_0089a010` state2(IC Card)/state3(Touch)/state6(Network)＝`mxsegaboot.md`。1つ満たすと次の
デバイスエラーへ前進（実証順 1000→5101→951→5501→8005）。HLSM は全工程 attract 到達済み。
ネットワークメッセージ: `0xbd02c4` "Network timeout error (DNS-WAN)" / `0xbd0304` "Network type error (WAN)"。

**エラーメッセージテーブル**(連続, pointer table 経由で直接 xref 不可):
`0xbd0374` IC Card R/W / `0xbd038c` Touch Panel / `0xbd03a4` USB Device / `0xbd041c` Keychip /
`0xbd0464` Game Program on Storage / `0xbd0518` Sound Function / `0xbd0534` Graphic Function。

### USB Device (951) = DirectInput SysMouse の連鎖 [S+L]
> **訂正(2026-06-30, 二段)**: ①旧「USB JVS I/Oボード」は誤称。②951 ゲートの対象は **DirectInput の SysMouse**（`device2`, GUID_SysMouse `{6F1D2B60-...}`）。`usbio_board_count` を +1 するのは `dinput_create_device`(0x67CBE0) ＝**マウス作成**のみで、joystick 列挙(`dinput_enum_gamectrl`)は count に触らない。joystick(dev0/dev1)は別系統の主操作系（facts/amjvs.md「DirectInput 入力系」）。
- `FUN_00679de0`(input_update_merge_dinput_jvs) 末尾: `usbio_board_count < 1`→ `iVar2=-0x70(-112)` →
  `if(1<DAT_016b6ffc && usbio_io_status==0) usbio_io_status=iVar2` / `if(jvs_error_state!=0 && usbio_io_status==0) usbio_io_status=jvs_error_state`。
- `usbio_errCode_mapper`(0x6F0AD0): `switch(usbio_io_status)` default → `if(amlib_subsystem_state!=8) amlib_master_errCode=0xf`(=951)。
- **回避条件**: `usbio_board_count>=1`(+ `DAT_016b88e0<=1 && DAT_016b88e4==1`) かつ `jvs_error_state==0`、または `amlib_subsystem_state==8`。
- **純正化済・撤去（2026-06-30, ライブ実証）**: device2 = OS の **システムマウス**。`dinput_create_device` が
  `CreateDevice(GUID_SysMouse)+SetDataFormat(c_dfDIMouse2 @0xaf48ac)+SetCooperativeLevel(hwnd@0x1696e0c)` 成功で count++。
  **dinput.diag(api.c) で実測: 実マウス＋WGL ウィンドウ下で `count=1`・`mouse`非null・`hwnd==FindWindow("WGL")`** →
  素の usbio_errCode_mapper が 951 経路に入らない。**`0x6F0B80` byte patch を撤去しても restart 後 phase=ready・951 不在を確認**
  （patches.applied count 21→20）。touch/card と同じ「詐称→純正供給」格上げ。
- **fallback**: 真のヘッドレス/マウス無し or ウィンドウ未生成環境では count=0 で 951 再発しうる。その場合は
  `0x6F0B80` 復活ではなく「前景ウィンドウ＋システムマウスの供給」で解く（OS 境界仮想化の原則）。
- 旧「撤去不可・0910 停滞」は **マウス不在(count=0)前提**の旧実測で、本実証により覆った。
  `DAT_016014a3!=0` でも skip するが mxkeychip/dongle 派生(`FUN_00459220/459460`)なので force 非推奨。

### Dipsw / board index = board-table check (errCode 0xa / 0xb) [S+F]
- **dipsw read** `FUN_0045a0e0`（唯一の writer）: `amDipswReadByte` 経由で byte2/byte3 を読み、
  そこから派生:
  - `byte2` ← `FUN_00984190`（成功時 `*p=3` とハードコード）。`DAT_01601951`＋flag bit 0x1/0x2。
  - `byte3` ← `FUN_00984130`→`FUN_00983bb0(0)`→`FUN_009836e0`（実 dipsw バイト）。`DAT_01601950`＋
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
- **適用 patch**（実基板の clean 値を源流供給）: `0x45A0F5`（byte2 ロード→`MOV CL,3`）＋
  `0x45A0F9`（byte3 ロード→`MOV AL,0x20`）。byte3=0x20 で既存 `SHR/AND` が index 2 を自然算出し
  table[2]=8 を満たす（0xa 解消）＋ bit 0x8(=flag 0x20)=0（0xb 解消）。byte2=3 は実基板値で
  bit 0x1/0x2 を実機同様に供給。両 reader（0xa / 0xb / FUN_006c5470 の 0x11/0x1e）を源流で恒久解消。
  実装 `src/logic/patches.c`（後述のとおり 2026-06-29 に dipsw エミュへ移行済み）。
- **byte patch 撤去・デバイスエミュ置換済み（2026-06-29, ライブ確認）**: 0x45A0F5/F9 の byte patch は撤去し、
  OS 境界エミュへ移行。dipsw デバイスは `amDipswCreateDeviceFile`(0x983430) が **SetupDi(PnP GUID 列挙)+CreateFileA**
  で開くため standalone では列挙失敗（名前ベース mxsmbus フックには乗らない）。`amEepromCreateDeviceFile`(0x984910) と
  同型なので、EEPROM と同じ **ctx force-provision** で解決した（`api.c dipsw_force_ready`）:
  dipsw ctx（base 0xccf488: +4 mutex / +8 handle / +0xc addr=0x20 / +0x38 busy / +0x50 event / +0 initFlag）に
  handle=H_MXSMBUS を入れると、read fn(`amDipswReadByteInternal` 0x9836e0)の `DeviceIoControl(0x9c402004, cmd=5)` が
  既存 mxsmbus エミュへ流れる。`mxdev_ioctl` は cmd==5（dipsw read, off3=index）に対し **index0→0x20** を返し、
  素の `FUN_0045a0e0` が `(0x20>>4)&7=2` で board index 2 を算出（patch と同結果）。ライブ: patches.applied count=26、
  `dipsw.force_ready` 発火後 host.ready→安定 attract、**errCode 0xa/0xb 0件**で恒久解消を確認。

---

## 周辺シリアル I/O デバイス（COM map）[S+F]

nrs.exe の I/O 周辺は **amlib device list `DAT_016db564`**（linked-list, next=`[+0x3c]`）にオブジェクトとして
登録され、各オブジェクトは `[+0x00],[+0x04]` の **class ペア**で識別される。3 系統が**シリアル(COM)**を開く。
裏取り = runtime `NtCreateFile` バックトレース（旧 Frida probe で取得）＋静的解析（呼出元関数の逆コンパイル。再取得は Ghidra/実走）。

| COM | 用途 | amlib class | open 元（static_VA） | 設定 | 本 boot での状態 |
|---|---|---|---|---|---|
| **COM1** | タッチパネル | 0x22,0x22 | `FUN_008b2450`（touch driver init） | — | open 失敗 `0xc0000034`（未エミュレート） |
| **COM2** | IC Card R/W（SEGA独自, **Aime非該当**） | 0x21,0x21 | `cardrw_object_dispatch`(0x4f2990)→`serial_dev2_init_wrapper`(0x674ad0)→`serial_dev2_init`(0x884e80) | 8E1 / 9600 | open 失敗 `0xc0000034`（未エミュレート） |
| **COM4** | JVS I/O | amJvst（別系統） | `amJvspInit`(0x986720)→`amJvstThreadInit`(0x989B10) `CreateFileA("COM4")` | 115200 / 8N1 | **開く**＝host が仮想ハンドル化し `src/logic/driver/mxjvs.c` が JVS ボードをエミュ（旧 forgery+node 直書きは撤去。`amjvs.md`） |

- ポート名はいずれもハードコード。**JVS = 静的文字列 `"COM4"`**(`43 4F 4D 34 00` @ static_VA `0xAE11F0`,
  reader=amJvspInit のみ・writer 無し)。詳細 transport は `amjvs.md` §JVS I/O Subsystem。
- COM1/COM2 は汎用シリアルラッパ `FUN_0067c3c0`(≤3ch) の **2 呼出元**。JVS(COM4) はこれを使わず amJvst 独自スレッド。
- **ポート選択** `serial_select_com_index`(0x67C360, 暗黙 EAX 引数): touch は `-2`→COM1、card は `-3`→COM2。port 名表 `serial_com_name_table`(0xD4B440)[0..2]={COM1,COM2,COM3}。
  **kdserial（`debug_serial_flags` 0x1696AD4 bit1）有効 & index0(COM1) のとき COM3 へ remap**（カーネルデバッガが COM1 を占有→touch を退避）。retail/standalone は kdserial=OFF＝touch は COM1 固定。これが「環境により COM 番号が違う」報告の正体（COM1↔COM3）。
- **「別の調査で JVS=COM4」の正体**＝この `"COM4"` ハードコード（micetools mxjvs `new_com_hook(4)` も一致）。
  TeknoParrot 下では TP が `CreateFileA` を MinHook で横取りし COM4／pipe `\\.\pipe\teknoparrot_jvs` を
  SHM `TeknoParrot_JvsState` へリダイレクトする（pipe は TP 固有経路、nrs native は COM4）。

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
| `0x8B3B00` | `touchpanel_status` | present 判定（`+0x18`）。**RET1 patch は撤去済（2026-06-30）**: handshake 完走で game 自身が `FUN_008b2ad0` default case で `ctx+0x18=1`("touch panel ok.")を立てる→boot state3 が "CHECKING TOUCH PANEL … OK" で自然通過。詐称不要 |
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

**実装済み・動作検証済み（COM1 シリアルエミュ, `src/logic/driver/touch.c` + api.c 配線）**: COM1 を仮想シリアルとして
open/comm_control 成功化し、ReadFile で現マウス座標の `'U' T ..` 10B フレームをストリーム、WriteFile の
`'p'/'P'` コマンドへ `'P'`(byte3=6→+0x28=1) ack を返す。pseudo handle `0xC0114001`。座標は GetForegroundWindow の
client rect に対しマウス位置を 0..0xFFF へ正規化（実プレイ時はゲーム窓が前面ゆえ正しくマップ）。

⚠️ **核心の落とし穴 = ClearCommError cbInQue（2026-06-29 実体特定）**: serial RX ポンプ **`FUN_0067c0c0`** は
`ClearCommError(handle,&err,&comstat)` → **`comstat.cbInQue != 0` のときだけ ReadFile** する。touch は
ストリーミング型（host が write せず panel が 'T' を常時送出）でこのポンプ依存。`on_comm_control` の
COMCTL_CLEAR_ERROR で COMSTAT をゼロ化（cbInQue=0）すると **ReadFile が一度も来ず touch.read=0**。
**修正＝touch handle の CLEAR_ERROR で `cbInQue=TOUCH_FRAME_LEN`（常に1フレーム受信待ち）を申告**し、ポンプに
ReadFile を発行させる。JVS は write→read 同期でこのポンプを使わない（master 駆動 req/resp）ため cbInQue 不要＝
両者の決定的な差。

- **live 検証(2026-06-29, 段階的に解決して到達)**:
  1. **eeprom 修正**(`bugs.md` EEPROM SetupDi)で `amBackupRecordWriteDup -3` 洪水(14044件)が停止し boot が
     **attract 画面へ到達**（実写確認: 「BB.NETのメリットをご紹介！」）。region/amHm エラーは既存 errCode NOP
     パッチ(0x459109/0x45A846)で抑止され非致命。
  2. コイン投入(JVS key'5')で **mech 画面へ遷移**（`put_obj_blend_immediate: cha_rba_handr_grip` 描画）。
  3. **cbInQue 修正で touch.read が連続発火**（reads 9000+/streaming, `bytes:10`, 座標 0..0xFFF, `press` 追従）
     ＝**touch device パイプライン完全動作**（poll→'T'ストリーム→座標→押下検出）。
⚠️⚠️ **2つ目の核心 = TX フラッシュは 1 バイトずつ WriteFile（2026-06-30 解決, handshake 完了）**:
serial TX フラッシュ `FUN_0067c070`（TX ワーカースレッド `FUN_0067c1a0`→`FUN_0067c1f0`, SerialThread 経由）は
**TX リングを 1 バイトずつ WriteFile** する（touch.write が `55`/`70`/`52`/`30`… の単バイト連発で実証）。
当初 `touch_on_write` は 10B 一括フレーム前提（`for i+10<=n`）だったので **n=1 では一生処理されず ack ゼロ** →
device の handshake コマンド('p'/'P')に応答できず +0x28=0 のまま timeout → state 0x32(50) で固着（mode0/present0）。
**修正＝`touch_on_write` をバイト蓄積→'U' 始まり 10B フレーム組立に変更**（`TouchPanel.rx[]`/`rx_len`）。
完成フレームの byte1='p'/'P' に 'P'(byte3=6) ack を返す。
**live 検証(2026-06-30)**: handshake 進行 `hs 10→22(p28=1)→25→**present=1/mode=1/conn=0/hs=0**` で完了、
**「touch panel ok.」発火**。以降 device は mode1 動作し **実 serial 経路**（on_read_file の 'T' フレーム→rx_parse→
`decode_T_coord`）で座標が流れる（`rawX_216` がマウス追従, 中央で 2049/2050）。bypass の `+0x2b8` 注入は**不要化**
（撤去, `touch_inject` 無効）。

**touch-active 判定**（`FUN_008b3310`, mode1 処理）: **status byte `+0x166` の下位2bit (`+0x166 & 3`)** で touch-active。
'T' フレーム byte[2]=status。active→`+0x211`=1、**押下エッジ→`+0x210[0]`=1（1フレームのみ）**、離し→`+0x212`=1。
build_T は byte[2]=pressed?1:0 / Z(byte7:8)=pressed?0xFF:0 を送る。**live 検証: タッチで `touch.event`
`active=1 status=1 edge=1 x234=507(中央)` の完全シーケンス取得＝押下・座標・離しすべて正しく消費側へ到達**。

- **touch device は完動だが、ゲーム flow が進まない理由＝RE+実走で確定（2026-06-30, 詳細は下記カードリーダー節
  「ゲーム開始フローのゲート」）**: attract で touch すると `advertise_demo_controller`(0x725d60)がデモページを切替えるのみ
  ＝「画面をタッチしてください」はデモのプロンプトで開始トリガではない。ゲーム実起動は **① カード(class 0x21, entry scene
  0x5e6200 の card[4] bit10 ゲート・コード確定) ＋ ② ALL.Net ゲームサーバー(起動 `ALL.NET GAME SERVER` 未完了・
  【全国対戦受付終了】・実走観察)** の両方が前提。touch・クレジット(21, `amCredit_check_enough` 0x97cf80)は満たす。

**前提ブロッカー（解消済）**: touch device context は COM1 open で生成。serial handshake は上記フレーム組立修正で完了し
device は operational(mode1)。**ゲーム実バトル開始 = コイン + 画面タッチ + (推定)Aime カード**。

### カードリーダー（COM2 / class 0x21）= SEGA 独自 IC Card R/W [S+F]

**素性の確定（2026-06-30, Ghidra 実体 sweep）**: nrs.exe に `Aime`/`felica`/`IDm`/vendor バナー文字列は**ゼロ**。
ゲーム自称は **"IC Card R/W"** のみ（`"IC Card R/W Not Found"`@0xbd0374, `"CHECKING IC CARD R/W"`@0xc811a0）。
`JcvCard`(.?AVJcvCard@@) は**ゲームデータ class**（`Jcv*` 接頭辞群の一員、HW 無関係）。
→ **Aime/FeliCa リーダではない**。bare-byte command/ACK プロトコルの **SEGA 独自 IC カード R/W ファミリ**（RingEdge 筐体世代）。
エミュ対象は「ブランド」ではなく **class 0x21 のシリアル I/O**。

**Transport**（`serial_open_comport` 0x67be20 の DCB / `serial_dev2_init` 0x884e80 の config）:
**9600 baud / 8 data / EVEN parity / 1 stop（8E1）**、XON/XOFF、0x200B リングバッファ×2。
baud は `baud_table_00B40714[1]`（raw 未読、fallback 9600。我々は OS 境界で仮想化ゆえ baud は物理無関係）。

**Framing**: **裸のコマンドバイト**（length field 無し・**checksum/CRC 無し**）。
各 opcode に固定 1 バイトの期待 ACK（`card_cmd_ack_expected` 0x8850c0）。
レスポンスは**ステータスバイト** `*`(0x2a)→3 / `:`(0x3a)→4 / `J`(0x4a)→5 / `Z`(0x5a)→6 / `0xcb`→7 / `0x1a`→busy を
`card_rx_status_decode`(0x66f8a0) でデコード（内部 0=pending, 1=OK）。多バイトは `card_frame_append2`(0x884bb0,+2B)/
`card_frame_append4_be`(0x884c00,+4B BE)。送信は `card_serial_send_frame`(0x884c60)→`card_serial_write`(0x884b50)→
`serial_write_txring`(0x67c210)。**注**: `_DAT_01265714=0x46('F')` はフレーム同期バイトではなく**タイムアウトカウンタ**（直後 0x884b50 で 10000 上書き）。

**コマンド体系**（証明済みバイト定数）:

| Code | 機能(文脈推定) | 期待ACK | Builder(static_VA) |
|---|---|---|---|
| `0xF7` | Reset / open | — | `card_cmd_reset_0xF7` 0x66fb80 |
| `0x28` | Init / session 開始 | `\n`(0x0a) | `card_cmd_init_0x28` 0x66fcc0（→0xF7 finalize） |
| `0x4D` | Poll / カード検出 | `\v`(0x0b) | `card_cmd_poll_0x4D` 0x670040 |
| `0x0D` | 属性ブロック read(+2B addr) | `+`(0x2b) | `card_cmd_read_attr_0x0D` 0x6704e0 |
| `0x2D` | データブロック read(+8B addr/len BE) | `0x8b` | `card_cmd_read_data_0x2D` 0x670300 |
| `0x8D` | データブロック read(variant,+2B) | `0x8b` | `card_cmd_read_data_0x8D` 0x6708e0 |
| `0xAD` | データブロック write(+4B BE) | `0x8b` | `card_cmd_write_0xAD` 0x670dd0 |
| `0x38` | Status / verify | `\n`(0x0a) | `card_cmd_status_0x38` 0x66fe60（→0xF7 finalize） |
| `0x68` | スロット addressed cmd(`0x68,1,slot`) | `\n`(0x0a) | `card_send_addressed_cmd_0x68` 0x884f40 |
| `0x6D` | スロット選択 | `K`(0x4b) | (ACK表のみ) |
| `0x1D,0x88,0xB8,0x48,0x58,0xCD,0xED` | 予約/他 | 各 | (0x8850c0 ACK表) |

低ニブルが操作種別を符号化（`0x?D` 系=read/write）。**最大 7 スロット** addressing（`slot_addr_table_00b40bf4[0..6]`、
`card_slot_next`0x66f7d0/`card_slot_cycle`0x66f800 で 0→6 巡回）。

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
  **RET1 patch は撤去済（2026-06-30, 差分ライブテスト）**: card serial emu(card.c)が実 handshake を完走させると game 自身が card_flags bit1 を立てる→boot が "CHECKING IC CARD R/W … OK"→attract 到達(5101 不在)。詐称不要。
- context getter `cardrw_device_status_ptr`(0x4f3e30): device list を class(0x21,0x21) で検索。約100関数が参照する大サブシステム 0x4f3-0x4f8。

カードコンテキストは **0x6720B/device, ストライド 0x6714**（`cardrw_ctx_init` 0x4f2910 が memset）。

**実装状況**（2026-06-30）:
- 旧: presence のみ詐称（`cardrw_ready_bit1` を `RET1` patch＝Error 5101／state2 解消）で実 I/O 未実装。
- **方針確定 = 仮想カード永続 R/W**（UID+データブロックを持つ仮想 Aime 相当カード, card.bin 永続化。TeknoParrot 流）。
- **Phase A done + live 検証成功（`src/logic/driver/card.{h,c}` + `api.c` 配線）**: COM2 を `0xC0114003` で仮想化し
  byte-exact handshake を実装。`loader.exe restart --wait` で実走 → **handshake 完全動作**（`f7→0a`/`68 06 40→0a`/
  `68 01 dc→0a`/`48→0a`）、**phase=ready・subsys.card=ok・card.read 発火**＝COM2 が実プロトコルで認識され boot 通過。
  フレーム=`[ACK b0][status b1][payload]` 再同期なし、半二重 turnaround を opcode 長テーブルで実装。CLEAR_ERROR の
  `cbInQue=card_rx_pending()`。**TX framing 実測確証: 0xF7=1B(trailer無)・0x68=3B(`FUN_00884f40`)・0x48=1B**。
  init SM=`card_init_handshake_sm`(0x670f70, case10→f7/case0xC→68 06 40/case0x10→48、成功で `DAT_016ae538=1` device-found→substate10)。
  transport pump=`card_transport_pump`(0x674530: case1=init/case3=poll-read `FUN_00671470`/case5=write `FUN_00671de0`)。
- **Phase B1 done + live 検証成功（operational init 完走）**: init 最終段 `b8 cf`（0xB8 SET COMM SPEED）を ACK `0a` →
  **`[game] card slot ok` 発火**＝カードリーダー init が実プロトコルで完全完了（touch「touch panel ok」相当）。

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

- **present/absent 極性**（`card_status_decode` 0x66f8a0 + `FUN_008850c0`）: **received byte0 == 期待ACK → decode 1 = present**（byte1 無視）。
  **nocard = 単バイト `5A`('Z')**（byte0=0x5A は ACK と不一致→cVar1=0、DL に残る 0x5A='Z'→decode 6）。`0B 5A…` は ACK 一致で present 誤認になるので不可。
- **frame 長則**（`card_frame_len_for` 0x8848d0, **再同期なし**）: byte0 で完成長確定 — 0x0A→{送信0x58:2/0x88:19/他:1}, 0x5A→1, 0x0B→9, 0x2B→129, 0x8B→{0x2D/0xAD:1, 0x8D/0xED:3}。emit は期待ACK 先頭＋表通りちょうど。
- **read SM フロー**: reset(F7)→sense(28)→`card_read_setup`(0066fff0)→search(4D)[ret6=nocard→halt / ret1=present→UID抽出(`DAT_0169e314`=UID,`DAT_0169e31c`=type)]→select(2D)→read(0D×N: 128B/回, header byteswap 0066f6d0, image=`&DAT_0169f338+slot*0x1008`)→commit(AD)→halt(38)。UID whitelist=`DAT_016a55b0[]`(count `DAT_016a55ad`)。容量=`card_capacity_by_type`(0x66f690)。card image 0x1008B=64Bヘッダ+~4032Bデータ。

- **Phase B2（次・仮想カード挿入＋データ R/W＋永続化）**: attract 中は card を能動 poll しない。SEARCH(0x4D) はゲーム flow が
  カードを要求した時（coin/touch→card-login）に走る。→ ①ゲームを card-search まで進める ②present=1 で poll に `0B`+8B UID record
  （**byteswap 順を live 確証**）③0D ヘッダ(2B+128B,UID@+0x04 BE)＋容量分 data ④0xAD write ⑤`card.bin` 永続化（logic 直接 Win32 file I/O, abi 不変）。

amlib エラーメッセージテーブルでは `0xbd0374` IC Card R/W。

> ⚠️ 既知の誤記訂正（2026-06-30）: ready/err/getter を以前 `0x8f6310/0x8f6330/0x8f3e30` と記したのは **4↔8 transposition**。
> 正は `0x4f...`。`0x8f63xx` は無関係な JcvCard デシリアライザ（`FUN_008f33e0`）。`data/known_names.json` 訂正済み。
