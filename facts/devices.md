# 周辺デバイス presence 連鎖 FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。横断定数は `../ARCH.md`、索引は repo ルート `FACTS.md`。
confidence: [F]=Frida確認 [S]=静的解析 [I]=推論

---

## Error Scene System & Device-Presence Chain [S+F]

boot 後に居座る「Error NNNN」は**ゲームアプリのエラーシーン**（amlib 09xx 表示とは別経路）。
レンダラ `FUN_006f2730`(RVA 0x2f2730) が記述子を毎フレーム描画。記述子レイアウト:
`+0x00`=amlib errCode / `+0x04`=detail / `+0x0c`=msgPtr / `+0x10`=errNo(表示番号) / `+0x16`=flags(&4=Caution)。

**device-presence 連鎖**: errCode→errNo→fix の対応は `./presence.js`（各行 note に errNo/state）。発生源関数は
`FUN_0089a010` state2(IC Card)/state3(Touch)/state6(Network)＝`../mxsegaboot/FACTS.md`。1つ満たすと次の
デバイスエラーへ前進（実証順 1000→5101→951→5501→8005）。HLSM は全工程 attract 到達済み。
ネットワークメッセージ: `0xbd02c4` "Network timeout error (DNS-WAN)" / `0xbd0304` "Network type error (WAN)"。

**エラーメッセージテーブル**(連続, pointer table 経由で直接 xref 不可):
`0xbd0374` IC Card R/W / `0xbd038c` Touch Panel / `0xbd03a4` USB Device / `0xbd041c` Keychip /
`0xbd0464` Game Program on Storage / `0xbd0518` Sound Function / `0xbd0534` Graphic Function。

### USB Device (951) = USB JVS I/Oボード の連鎖 [S]
- `FUN_00679de0` 末尾: `DAT_016b88dc < 1`(I/Oボード未検出)→ `iVar2=-0x70(-112)` →
  `if(1<DAT_016b6ffc && DAT_016b7000==0) DAT_016b7000=iVar2` / `if(DAT_016b8670!=0 && DAT_016b7000==0) DAT_016b7000=DAT_016b8670(jvs_error_state)`。
- `FUN_006f0ad0`: `switch(DAT_016b7000)` default → `if(DAT_016b8b50!=8) DAT_016f5af0=0xf`。
- **適用 patch**: `0x6F0B80`（`DAT_016f5af0=0xf` の imm `0F→00`。USB I/O board errCode 無効化＝Error 951 non-fatal）。
  正は `./presence.js`（subsys=devices）。
- 回避: `DAT_016b88dc>=1`(+ `DAT_016b88e0<=1 && DAT_016b88e4==1`) かつ `DAT_016b8670==0`、または `DAT_016b8b50==8`。
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
  正は `./presence.js`（subsys=devices）。
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
裏取り = runtime `NtCreateFile` バックトレース（`tools/runtime/frida_diag/coms_probe.js` / `card_probe.js`）＋
静的解析（呼出元関数の逆コンパイル）。

| COM | 用途 | amlib class | open 元（static_VA） | 設定 | 本 boot での状態 |
|---|---|---|---|---|---|
| **COM1** | タッチパネル | 0x22,0x22 | `FUN_008b2450`（touch driver init） | — | open 失敗 `0xc0000034`（未エミュレート） |
| **COM2** | カードリーダー(Aime/IC) | 0x21,0x21 | `FUN_004f2990`→`FUN_00674ad0`→`FUN_00884e80` | — | open 失敗 `0xc0000034`（未エミュレート） |
| **COM4** | JVS I/O | amJvst（別系統） | `amJvspInit`(0x986720)→`amJvstThreadInit`(0x989B10) `CreateFileA("COM4")` | 115200 / 8N1 | `state.js` が JVS reinit を `ret` patch ＝ **開かない**（入力は node 直書き＝`amjvs/input.js`） |

- ポート名はいずれもハードコード。**JVS = 静的文字列 `"COM4"`**(`43 4F 4D 34 00` @ static_VA `0xAE11F0`,
  reader=amJvspInit のみ・writer 無し)。詳細 transport は `../amjvs/FACTS.md` §JVS I/O Subsystem。
- COM1/COM2 は汎用シリアルラッパ `FUN_0067c3c0`(≤3ch) の **2 呼出元**。JVS(COM4) はこれを使わず amJvst 独自スレッド。
- **ポート選択** `serial_select_com_index`(0x67C360, 暗黙 EAX 引数): touch は `-2`→COM1、card は `-3`→COM2。port 名表 `serial_com_name_table`(0xD4B440)[0..2]={COM1,COM2,COM3}。
  **kdserial（`debug_serial_flags` 0x1696AD4 bit1）有効 & index0(COM1) のとき COM3 へ remap**（カーネルデバッガが COM1 を占有→touch を退避）。retail/standalone は kdserial=OFF＝touch は COM1 固定。これが「環境により COM 番号が違う」報告の正体（COM1↔COM3）。
- **「別の調査で JVS=COM4」の正体**＝この `"COM4"` ハードコード（micetools mxjvs `new_com_hook(4)` も一致）。
  TeknoParrot 下では TP が `CreateFileA` を MinHook で横取りし COM4／pipe `\\.\pipe\teknoparrot_jvs` を
  SHM `TeknoParrot_JvsState` へリダイレクトする（pipe は TP 固有経路、nrs native は COM4）。
- 旧 `amjvs/FACTS.md` の「JVS 接続順 pipe→COM2→COM1」は **TP 要約由来の誤り**で訂正済（COM1=touch, COM2=card）。

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
| `0x8B3B00` | `touchpanel_status` | present 判定（`+0x18`。boot で `=1` patch 済＝`./presence.js`） |
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
- **未確定**: 特定の touch UI 画面でゲームが視覚反応するか（正確な座標ヒット＋完全な game data が前提。
  cha_rba モデルが "invalid object"＝アセット不完全の疑い）。'T' が消費側 `+0x210` へ届く経路（serial→promote）も
  視覚反応で未確証。届かない場合は②③と同じ `report_push`(+0x2b8) 直書きへ切替（device context は COM1 open で生成済）。

**前提ブロッカー**: touch device context(`DAT_016d8690`)は COM1 open 成功で生成される（旧「open 失敗で device を
作らない」状態は COM1 エミュで解消）。**ゲーム実バトル開始 = コイン + 画面タッチ**（START ボタン不可）なので
タッチは開始操作の必須ピース。

### カードリーダー（COM2 / class 0x21）[S+F]
| static_VA | 役割 |
|---|---|
| `FUN_004f2990` | card オブジェクト(class 0x21)操作の起点（`FUN_0089dcb0(0x21,0x21,1)`→method 呼出）→ COM2 を開く |
| `FUN_00674ad0`→`FUN_00884e80` | card のシリアル補助 → COM2 open（`FUN_00884e80` が CreateFile 経路） |
| `FUN_004f3e30` | card context getter（device list を class 0x21 で検索。約100関数が参照する大サブシステム 0x4f3-0x4f8） |
| `0x4F6310` | IC Card R/W ready（`*ctx>>1 &1`。boot で `RET1` patch＝presence 詐称、Error 5101／state2 解消） |

カードリーダーは **presence のみ詐称**で実 I/O 未実装（INPUT TEST「CARD IN」未対応と整合）。実機 Aime RWM 相当。
amlib エラーメッセージテーブルでは `0xbd0374` IC Card R/W（上記「エラーメッセージテーブル」参照）。
