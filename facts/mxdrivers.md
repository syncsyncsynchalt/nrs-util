# mx ドライバ層 FACTS（co-located）

索引 `_index.md` / 横断知見 `workflow.md`。

RingEdge の mx* デバイスドライバを emulate（`src/logic/driver/mxdevices.c`）:
`mxsram` / `mxsuperio` / `mxhwreset` / `mxsmbus` / `columba` / `\\.\pipe\teknoparrot_jvs` を
`CreateFileA/W` ＋ `NtCreateFile` でダミーハンドル化し、`DeviceIoControl` を成功させる
（mxsram/mxsmbus/columba は実データ応答、他は出力ゼロ埋め）。
固定 RVA なし（Win32/native API フック）。**正本＝純正ドライバ** `C:\src\RingOSUpdate\common\segadriver\`（Columba/mxjvs/mxsmbus/mxsuperio/mxhwreset/mxcmos/mxsram…の .sys/.inf）。micetools `dll/drivers/` は補助（再実装）＝純正と食い違ったら純正が正（`../ref.md` 階層）。

## mxsram = 純正 mxsram.sys 準拠（amBackup のバッキング） [F]

amBackup→amSram→mxsram の SRAM デバイス。**正本＝純正 `RingOSUpdate\common\segadriver\mxsram\mxsram.sys`**（RE1 固有差分は `ringedge1\segadriver\mxsram`、下記「実 RingEdge ドライバ mxsram.sys」節で解析済）。micetools `dll/drivers/mxsram.c` は補助参照。
以下を厳密準拠する:

- **サイズ/初期値**: `0x200000`B（=amSram_totalSize, geometry 由来）、新規 0xFF 埋め。
- **永続化**: `nvram.bin`(CWD) に memory-map（`CreateFileMapping`+`MapViewOfFile`）。遅延永続（flush 不要）。map は host 原 CreateFile(`ORIG_CREATE_FILE_W`)で開く（フック版は再入 deadlock）。open 失敗＝揮発 static fallback。
- **DeviceIoControl**: PING `0x9c406000`→`0x01000001` / GET_SECTOR_SIZE `0x9c406004`→4（根拠は下記「実 RingEdge ドライバ」節）/ DRIVE_GEOMETRY `0x00070000`→Cyl256/Fixed(12)/Tracks2/Sectors8/512B（geometry 512=総容量計算用, sector size と別物）。`lpBytesReturned` 4/4/24。GET_LENGTH_INFO は実 mxsram.sys のみ応答。
- **Read/Write/SetFilePointer**: SetFilePointer→global file ptr（単一ハンドル・mutex 直列）。Read/Write 常に TRUE, bytes=実コピー数(残量 clamp)。host が SetFilePointer フック(ABI v4)。

## mxsmbus = amEeprom(AT24C64AN) のバッキング [S/F]

正: 実 `C:\src\ringedge_system_63.01.10\...\segadriver\mxsmbus\mxsmbus.{sys,inf}` ＋ micetools
`dll/drivers/mxsmbus.c`・`dll/devices/smb_at24c64an.c`・`lib/mice/ioctl.h` ＋ nrs.exe `FUN_00984910/620`。

amEeprom は STATIC/CREDIT/NETWORK/HISTORY/ALPB レコードの backing（amBackup の eeprom 系）。固定パスでなく
**SetupAPI デバイスインターフェース GUID 列挙**でデバイスを探す:

- **GUID** `{5C49E1FE-3FEC-4B8D-A4B5-76BE7025D842}`（実 mxsmbus.sys offset 0x20bc で確認）。
  `mxdevices.c` が SetupDiGetClassDevsA/EnumDeviceInterfaces/GetDeviceInterfaceDetailA/DestroyDeviceInfoList を
  hook し、この GUID のときだけ偽装インターフェース（DevicePath=`\\.\mxsmbus`）を1件返す。他列挙は素通り。
- `CreateFileA("\\.\mxsmbus")` → fake handle（classify 済み）。
- **DeviceIoControl**（FILE_DEVICE_SEGA=0x9c40, METHOD_BUFFERED, lpBytesReturned 設定）:
  - `0x9c406008` GET_VERSION → `0x01020001`（nrs は `&0xffff==1` を要求）。
  - `0x9c40200c` I2C(0x27B) / `0x9c402004` REQUEST(0x25B) → パケット解析。
    I2C_PACKET `{u8 status,u8 cmd,u16 v_addr,u16 code,u8 nbytes,u8 data[32]}`（REQUEST は v_addr/code が u8、data@5）。
    `v_addr&0x7fff==0x57`(AT24C64AN) で cmd 分岐: 9=READ_BLOCK→eepromRead、8=WRITE_BLOCK→eepromWrite＋永続、
    他=byte read→0。status=0、ret=TRUE。
- **AT24C64AN store**: 8KB(`0x2000`)、新規 0xFF、`eeprom.bin`(CWD) に memory-map（sram と同方式・遅延永続）。
  レコードは _REG と _DUP(+0x1000) に二重化＋CRC（amiCrc32R、ゲーム側で計算）。

注: DeviceIoControl ログに実 cmd/addr/code を出すので、micetools 値との差異は実機ログで即検証・補正できる。

### `ENABLE_EEPROM`（既定 ON）

サスペンド起動下で **mxsmbus/AT24C64AN emulation が動作**する。amBackup の eeprom 系
レコード STATIC/CREDIT/NETWORK/HISTORY/BACKUP が read/write・`is broken=0`・`error(-3)=0`、
`eeprom.bin`/`sram.bin` に永続する。STATIC は blank だと region/serial チェックで停止するため新規時に
`region=01, serial(実機書式), 正CRC(amiCrc32R=標準CRC32)` で seed する。
**serial 書式 [S]**: 実機 serial は SEGA 工場割当の**固定値（実行時導出なし）**。書式 `[英数4]-[英数3][数字8]`=16文字, 文字集合 base-34 `[0-9A-HJ-NP-Z]`(I/O 除外)。実例 keychip KEY_ID `"A72E-02D11261116"`(micetools sysconf.h)。消費先 `alpbExInitialize`(ALL.Net billing)で書式検証なし。純正フォールバック=`amBackup_buildDefaultStatic`(0x97ff10)が `"INVALID_SERIALNO"`/region=0/CRC=0x5555aaaa。`"SBVA"` は GAME_ID であり serial ではない。micetools `GetSerialNumbers`(WMI+SHA1→'M'接頭辞)は工場値を持たない standalone 用の代替生成で**実機方法ではない**。

**EEPROM は名前 CreateFile でなく SetupDi で開く**(`amEepromCreateDeviceFile` 0x984910)ため standalone(PnP デバイス不在)では `amEepromInit`(0x985160)が失敗し、名前ベース mxsmbus エミュは一度もヒットしない → EEPROM backup が -3 洪水化。
対策＝`api.c eeprom_force_ready()` が eeprom ctx を poke して provisioning（`amEepromInit` 不要）: ctx base `0xccf4e0`（`+0x00`=initFlag=1 / `+0x04,+0x08`=6 / `+0x0c`=mutex(CreateMutexA) / `+0x10`=device handle=**H_MXSMBUS** / `+0x14`=i2c 0x57）。handle を H_MXSMBUS にすると write/read fn の `DeviceIoControl(0x9c40200c, i2c@0x57)` が mxsmbus エミュ(AT24C64AN→eeprom.bin)へ流れる。on_jvs_tick は storage init 後に回るため amEepromInit 試行済み(initFlag==0)を安全に上書きする。
これで R/W は通るが STATIC seed（region=01/serial/CRC）は別途必要 → **実装済**（`src/logic/driver/mxdevices.c` `eeprom_seed_static`: AM_SYSDATAwH_STATIC を region=01/serial/amiCrc32R 正CRC で REG@0x000 へ、blank/無効時のみ）。これが純正供給経路（基板 EEPROM area0=STATIC → `amBackupRead` → `region_game_pcb` 0x16014c4）の再現。詳細 `mxkeychip.md` region 表。

eeprom が成功すると amlib storage init が通り、ゲームが実機運用パスへ進む。その結果ルート
システムシーン callback(0x6C3F10)→`FUN_0089e880`(amApp_shouldShutdown)→`FUN_0089df40`(amApp_shutdown_now)
が `DAT_016f5aa0`(shutdown flag) を立て ATTRACT 前に ExitProcess するため、`src/logic/patches.c` が
0x6C3F20 の `je`→`jmp` patch で無力化する。詳細は `app.md` の「ルートシーン self-shutdown」。
`ENABLE_EEPROM=false` にすると eeprom を発見不可にし degraded パス（records -3）へ戻せる。

## amBackup 層スタック [S]

由来: `\namBackup Ver.1.04 Build:Jun 13 2012`（static 0xAE0CE8）。RingEdge NVRAM セーブ機構で、
mxsram/mxsmbus の上位 am 層。`amlib_storage_init_all`(FUN_004597c0) で **2 デバイスに分かれる**:
- BACKUP レコード → amSram → mxsram（`data/nvram/sram.bin`、上記 mxsram 節）
- STATIC/CREDIT/NETWORK/HISTORY/ALPB → amEeprom → mxsmbus → AT24C64AN @0x57（`data/nvram/eeprom.bin`、上記 mxsmbus 節）

mxsram/mxsmbus が micetools 準拠＋永続化されているため native amBackup パスが実データで成立する
（init がフック後に走るよう host が CREATE_SUSPENDED で注入＝`loader.exe`/GUI の ▶起動）。

呼出階層（static_VA, ImageBase 0x400000）:

```
amBackupRecordReadDup(0x491180) / amBackupRecordWriteDup(0x491200)   ← セーブ管理 0x490xxx 群が利用
  → amBackupRead(0x985a00) / amBackupWrite(0x985940)                  記録プリミティブ
      → amBackupReadRecord(0x9858D0)                                  area記述子→デバイス read
          → amBackup_getAreaDescriptor(0x982f40)  area(0..3)→記述子テーブル(DAT_00adfb88/c28/bd8)
          → amBackupReadDevice(0x985770) / amBackupWriteDevice(0x985820)  記述子+0xc(read)/+0x10(write) fn ptr 呼出
              → area0,1: amBackup_eepromAreaRead(0x984c60)/Write(0x984e20) → mxsmbus EEPROM
              → area2,3: amBackup_sramAreaRead(0x985dd0)/Write(0x985ff0)  → mxsram SRAM
  検証: amBackupRecordCheckValid(0x985620)  CRC(+0)/ID 照合
init: amBackupInit(0x985570)  DAT_012899e0 を含む 0x404B コンテキスト確保
```

### 記述子テーブル分岐（board type 3 ＝本機, 実体裏取り）[F]
`amBackup_getAreaDescriptor` は board type 3 で `DAT_00adfbd8 + area*0x14` を返す。各記述子 0x14B:
`+0x00`=base / `+0x04`=size(dup offset) / `+0x08`=flag / `+0x0c`=read fn / `+0x10`=write fn。実データ:

| area | base | read / write fn | バッキング |
|---|---|---|---|
| 0 | 0x0000 | 0x984c60 / 0x984e20 | EEPROM(AT24C64AN, mxsmbus DIOC 0x9c40200c cmd9/8, dev 0x57) |
| 1 | 0x1000 | 0x984c60 / 0x984e20 | EEPROM（dup 領域）|
| 2 | 0x0000 | 0x985dd0 / 0x985ff0 | SRAM(mxsram, SetFilePointer+ReadFile/WriteFile) |
| 3 | 0x4000 | 0x985dd0 / 0x985ff0 | SRAM（dup 領域）|

⚠ [I] area read/write fn (0x984c60/e20, 0x985dd0/ff0) と `amSram_readWorker`(0x985bc0) は **Ghidra DB に関数未定義**（記述子 fnptr 経由・直接 call xref 無しで auto-analysis 未生成）。アドレス裏取り不能＝要再確認。writeWorker 0x985c80 は DB 定義済(`amSram_writeWorker`)。

- **EEPROM 経路**(0x984c60): initFlag==0 で `-3`。0x20B ページで `amEeprom_smbusReadPage`(0x984700)=`DeviceIoControl(0x9c40200c)` cmd9(R)/cmd8(W), i2c `amEeprom_i2cAddr`=0x57。
- **SRAM 経路**(0x985dd0): initFlag==0 で `-3`。`amSram_sectorSize` で addr/len 剰余=0 アライン検査（SRAM 系 4 record は全 512B/512境界＝512/4 とも通る）→ mutex → worker SetFilePointer(FILE_BEGIN,生オフセット)+ReadFile/WriteFile。SetFilePointer fail=`-6`(0xfffffffa)/Write fail=`-8`(0xfffffff8)。
- **amSramInit(0x986380) は IOCTL ハンドシェイクのみで成功する罠**: PING(0x9c406000)`ver&0xffff==1`/geometry(0x70000 24B)/GET_SECTOR_SIZE(0x9c406004)`<0x801` → initFlag=1。**データ面未エミュでも init 通過**＝「init OK・記録 R/W 全失敗」で `amBackupRecordRead/WriteDup error` 洪水化（columba -21 とは別因）。

### 実 RingEdge ドライバ mxsram.sys（純正イメージ解析）[F]
`mxsram Ver.1.00`「PCMCIA Memory Card Access Driver」= `\Device\mxsram` を公開し下位 `\Device\memcard0` へ
`Zw{Read,Write,DeviceIoControl}File` 転送する wrapper（SpinLock 直列, `_allmul` で 64bit offset）。
DriverEntry(0x11004) MajorFunction: READ=0x10702 / WRITE=0x1085C / DEVICE_CONTROL=0x109C8。
- IRP_MJ_READ は IRP `Read.ByteOffset`(=SetFilePointer 位置) で memcard0 を読む → **nrs.exe の SetFilePointer+ReadFile と一致**。
- DEVICE_CONTROL が自前応答する IOCTL: PING(0x9c406000)→`0x1000001` / GEOMETRY(0x70000)→24B(ext キャッシュ) /
  GET_LENGTH_INFO(0x7405c)→8B。**GET_SECTOR_SIZE(0x9c406004)等は memcard0 へ転送**（自前で答えない）。
- **sector size: RINGEDGE2=4**（micetools `MICE_PLATFORM_RINGEDGE2 ? 4 : 512`）。**出所は micetools のみ**＝純正
  mxsram.sys は GET_SECTOR_SIZE を memcard0 へ転送し自前で答えない（上記）ため純正からは確定不能＝補助値扱い。
  SRAM 系 record は AM_SYSDATAwH_{BACKUP,HM_PEAK,TIMEZONE,ERROR_LOG} とも 512B/512境界なので 512 でも 4 でも
  アラインメント検査は通る（記録 R/W 失敗の原因は sector size ではなくデータ面の配線）。4 は厳密に緩いので採用。

### native エミュ実装（データ面）[S]
host が `SetFilePointer` をフック→`on_set_file_pointer`→`mxdev_seek`。`mxdev_read`/`mxdev_write` が `nvram.bin` を
memory-map した flat バッファ(0x200000B)へ memcpy（micetools `open_mapped_file` 相当・遅延永続）。EEPROM は `eeprom.bin`。
map は host の原 CreateFile(`ORIG_CREATE_FILE_W`)で開く（フック版はロック再入 deadlock。`facts/bugs.md`）。ABI v4 で追加。

| static_VA | Name | Notes |
|---|---|---|
| 0x491180 | amBackupRecordReadDup | 記録読み（dup: primary+backup）。失敗で `amBackupRecordReadDup: error(%d)` |
| 0x491200 | amBackupRecordWriteDup | 記録書き（dup）。失敗で `amBackupRecordWriteDup: error(%d)` |
| 0x985a00 | amBackupRead | 記録 read プリミティブ |
| 0x985940 | amBackupWrite | 記録 write プリミティブ |
| 0x9858D0 | amBackupReadRecord | `*param_1`=area。 |
| 0x985770 | amBackupReadDevice | 記述子+0xc の read fn を呼ぶ（"amBackupRead" 文字列） |
| 0x985820 | amBackupWriteDevice | 記述子+0x10 の write fn を呼ぶ（"amBackupWrite" 文字列） |
| 0x985620 | amBackupRecordCheckValid | CRC/ID 照合（"amBackupRecordCheckValid"） |
| 0x985570 | amBackupInit | コンテキスト初期化、DAT_012899e0=1 |
| 0x982f40 | amBackup_getAreaDescriptor | area(0..3)→記述子テーブル（amPlatformGetBoardType 分岐） |
| 0x986380 | amSramInit | IOCTL ハンドシェイクのみで成功（データ面未エミュでも initFlag=1）|
| 0x985d40 | amSramExit | initFlag==0 で `-3`("No Init Error")。ハンドル CloseHandle |
| 0x984c60 / 0x984e20 | eepromAreaRead/Write [I]DB未定義 | area0,1 = mxsmbus EEPROM 経路（0x20B ページ）|
| 0x984700 | amEeprom_smbusReadPage | `DeviceIoControl(0x9c40200c)` cmd9/8, i2c 0x57 |
| 0x985dd0 / 0x985ff0 | sramAreaRead/Write [I]DB未定義 | area2,3 = mxsram SRAM 経路（sector アライン検査）|
| 0x985bc0 / 0x985c80 | readWorker[I]DB未定義 / `amSram_writeWorker`(DB) | SetFilePointer(FILE_BEGIN)+ReadFile/WriteFile, mutex |

グローバル:

| static_VA | Name | Notes |
|---|---|---|
| 0x12899E0 | amBackup_ctx_initFlag | 0=未init（各 fn が -28/0xffffffe4 を返す）。0x404B コンテキスト先頭 |
| 0x12899D8 | amBackup_debugLevel | >0 で amlib_error_display_0903 にエラー文字列 |
| 0x12899E4 | amBackup_crcCtx | CRC32(amiCrc32R) コンテキスト |
| 0xCCF520 | amSram_initFlag | 0=未init（amBackup_sramArea* が -3）|
| 0xCCF524 | amSram_deviceHandle | mxsram ハンドル（worker が SetFilePointer/ReadFile 対象）|
| 0xCCF528 | amSram_totalSize | 総容量(geometry 由来, 0x200000)。bounds 検査 |
| 0xCCF530 | amSram_sectorSize | address/length のアラインメント単位。RE2=4 |
| 0xCCF534 | amSram_mutex | WaitForSingleObject/ReleaseMutex で R/W 直列化 |
| 0xCCF4E0 | amEeprom_initFlag | 0=未init（amBackup_eepromArea* が -3）|
| 0xCCF4F4 | amEeprom_i2cAddr | AT24C64AN i2c アドレス=0x57 |

SRAM レイアウト（micetools 補助参照 `dll/drivers/mxsram.c`＝純正 mxsram.sys/memcard0 の論理配置で要裏取り）: 記録アドレス
ADDR_BACKUP=0x0 / HM_PEAK=0x200 / TIMEZONE=0x400 / ERROR_LOG=0x600、二重化 ADDR_DUP=+0x1000。
CRC=`amiCrc32RCalc`（record 先頭4Bが CRC）。

## columba = SEGA DMI/SMBIOS 読取ドライバ（board type 判定）[F]

`\\.\columba` は backup ではなく**基板の DMI/SMBIOS（物理メモリ 0xF0000 帯）を読むドライバ**。
**正本＝純正 `RingOSUpdate\common\segadriver\Columba\columba.{sys,inf}`**。補助: micetools `dll/drivers/columba.c` + `lib/mice/dmi.c` + `lib/am/amOemstring.c`
（`dllmain.c`「Columba: Driver-level memory access, used to read the DMI tables」）。IOCTL/DMI 値は純正 columba.sys と nrs.exe 側で裏取り。

呼出: `amBackup_getAreaDescriptor(0x982f40)` → `amPlatformGetBoardType(0x982c50)` →
OEM getter `FUN_00988e70`(System Manufacturer) / `FUN_00988dd0`(OEM string #0..4) →
`FUN_00988c10`(DMI ローダ。`CreateFileW("\\.\columba")` ＋ `DeviceIoControl(IOCTL_COLUMBA_READ)`)。

| 項目 | 値（実体裏取り） |
|---|---|
| IOCTL_COLUMBA_READ | `0x9c406104` = `CTL_CODE(FILE_DEVICE_SEGA=0x9c40,0x841,METHOD_BUFFERED,FILE_READ_ACCESS)`（純正 columba.sys が正・micetools `ioctl.h` とも一致） |
| `AM_COLUMBA_REQUEST`(0x10B) | physAddr(LE u64)@0 / elementSize@8 / elementCount@0xc |
| phys 0xF0000 | `"_DMI_"` アンカー(16B)。探索側は `+6`=StructLength / `+8`=StructAddr のみ参照（checksum 不問） |
| phys 0xF1000 | DMI テーブル本体。table 読取は `nBytesReturned==0x10000` 必須 |
| RINGEDGE2 DMI（本機） | System Manufacturer=`"NEC"` / OEM #2=`"AAL"`(platform) / #4=`"AAL2"`(board type) |
| board type 判定 | `amPlatformGetBoardType`: `"AAL"`&&`"NEC"`&&`"AAL2"` → **3** → `getAreaDescriptor` case 3（有効） |
| 比較先定数 | platform: 0xadfd68=`"NEC"` 0xadfd6c=`"AAM"` 0xadfd70=`"AAL"` / OEM#4: 0xae0470=`"AAL2"` |

未エミュ時 `getAreaDescriptor` null → `-21`(0xffffffeb)連発は解消済み（native が columba DMI=RINGEDGE2 emulate → board type 3 確定, `DAT_01296158`/`DAT_00ccf450` キャッシュ）。columba 修正後も残る `amBackupRecordRead/WriteDup error` は別因＝mxsram データ面欠落（下記）。
エミュ実装＝`mxdevices.c build_dmi`（DMI 192B, 0xF0000→ヘッダ/0xF1000→テーブル。値の正は純正 columba.sys/実機 DMI）。
