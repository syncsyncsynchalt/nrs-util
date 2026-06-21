# mx ドライバ層 FACTS（co-located）

横断定数 `../ARCH.md` / 索引 repo ルート `FACTS.md`。

RingEdge の mx* デバイスドライバを emulate（`devices.js`、persistence=runtime）:
`mxsram` / `mxsuperio` / `mxhwreset` / `\\.\pipe\teknoparrot_jvs` を `CreateFileA/W` ＋ `NtCreateFile`
でダミーハンドル化し、`DeviceIoControl` を成功（出力ゼロ埋め）させる。固定 RVA なし（Win32/native API フック）。
micetools 対応: `dll/drivers/`。

## mxsram = micetools `mxsram.c` 準拠（amBackup のバッキング） [F]

amBackup→amSram→mxsram の SRAM デバイス。micetools `src/micetools/dll/drivers/mxsram.c` を正として
以下を厳密準拠する:

- **サイズ/初期値**: `1024*2084`=2,134,016B、新規は 0xFF 埋め。
- **永続化**: `data/nvram/sram.bin` にファイルバック（mmap 相当）。init 時に `CreateFileW(OPEN_ALWAYS)`
  でロード（既存）/0xFF 書出し（新規、`GetLastError`==183 で判定）。`WriteFile(mxsram)` 毎に
  該当領域を write-through。open 失敗時は揮発フォールバック＋WARN（micetools 同挙動）。
- **DeviceIoControl**: PING `0x9c406000`→`0x01000001` / GET_SECTOR_SIZE `0x9c406004`→512(RE1) /
  DRIVE_GEOMETRY `0x00070000`→Cyl256/Fixed(12)/Tracks2/Sectors8/512B（この時のみ出力ゼロ埋め）。
  **未対応（GET_LENGTH_INFO 等）は FALSE**。`lpBytesReturned`(args[6]) を 4/4/24 で設定。
- **Read/Write/SetFilePointer**: ハンドル毎の file pointer（`ctx->m_Pointer` 相当）。Read/Write は
  micetools 同様 **常に TRUE** を返し、bytesRead/Written は実コピー数。

## mxsmbus = amEeprom(AT24C64AN) のバッキング [S/F]

正: 実 `C:\src\ringedge_system_63.01.10\...\segadriver\mxsmbus\mxsmbus.{sys,inf}` ＋ micetools
`dll/drivers/mxsmbus.c`・`dll/devices/smb_at24c64an.c`・`lib/mice/ioctl.h` ＋ nrs.exe `FUN_00984910/620`。

amEeprom は STATIC/CREDIT/NETWORK/HISTORY/ALPB レコードの backing（amBackup の eeprom 系）。固定パスでなく
**SetupAPI デバイスインターフェース GUID 列挙**でデバイスを探す:

- **GUID** `{5C49E1FE-3FEC-4B8D-A4B5-76BE7025D842}`（実 mxsmbus.sys offset 0x20bc で確認）。
  `devices.js` が SetupDiGetClassDevsA/EnumDeviceInterfaces/GetDeviceInterfaceDetailA/DestroyDeviceInfoList を
  hook し、この GUID のときだけ偽装インターフェース（DevicePath=`\\.\mxsmbus`）を1件返す。他列挙は素通り。
- `CreateFileA("\\.\mxsmbus")` → fake handle（classify 済み）。
- **DeviceIoControl**（FILE_DEVICE_SEGA=0x9c40, METHOD_BUFFERED, lpBytesReturned 設定）:
  - `0x9c406008` GET_VERSION → `0x01020001`（nrs は `&0xffff==1` を要求）。
  - `0x9c40200c` I2C(0x27B) / `0x9c402004` REQUEST(0x25B) → パケット解析。
    I2C_PACKET `{u8 status,u8 cmd,u16 v_addr,u16 code,u8 nbytes,u8 data[32]}`（REQUEST は v_addr/code が u8、data@5）。
    `v_addr&0x7fff==0x57`(AT24C64AN) で cmd 分岐: 9=READ_BLOCK→eepromRead、8=WRITE_BLOCK→eepromWrite＋永続、
    他=byte read→0。status=0、ret=TRUE。
- **AT24C64AN store**: 8KB(`0x2000`)、新規 0xFF、`data/nvram/eeprom.bin` にファイルバック（load/0xFF init/
  write-through）。レコードは _REG と _DUP(+0x1000) に二重化＋CRC（amiCrc32R、ゲーム側で計算）。

注: DeviceIoControl ログに実 cmd/addr/code を出すので、micetools 値との差異は実機ログで即検証・補正できる。

### `ENABLE_EEPROM`（既定 ON）

サスペンド起動下で **mxsmbus/AT24C64AN emulation が動作**する。amEepromInit 成功、amBackup の eeprom 系
レコード STATIC/CREDIT/NETWORK/HISTORY/BACKUP が read/write・`is broken=0`・`error(-3)=0`、
`eeprom.bin`/`sram.bin` に永続する。STATIC は blank だと region/serial チェックで停止するため新規時に
`region=01, serial="SBVA…", 正CRC(amiCrc32R=標準CRC32)` で seed する。

eeprom が成功すると amlib storage init が通り、ゲームが実機運用パスへ進む。その結果ルート
システムシーン callback(0x6C3F10)→`FUN_0089e880`(amApp_shouldShutdown)→`FUN_0089df40`(amApp_shutdown_now)
が `DAT_016f5aa0`(shutdown flag) を立て ATTRACT 前に ExitProcess するため、`boot/app/no_selfshutdown.js` が
0x6C3F20 の `je`→`jmp` patch で無力化する。詳細は `app/FACTS.md` の「ルートシーン self-shutdown」。
`ENABLE_EEPROM=false` にすると eeprom を発見不可にし degraded パス（records -3）へ戻せる。

## amBackup 層スタック [S]

由来: `\namBackup Ver.1.04 Build:Jun 13 2012`（static 0xAE0CE8）。RingEdge NVRAM セーブ機構で、
mxsram/mxsmbus の上位 am 層。`amlib_storage_init_all`(FUN_004597c0) で **2 デバイスに分かれる**:
- BACKUP レコード → amSram → mxsram（`data/nvram/sram.bin`、上記 mxsram 節）
- STATIC/CREDIT/NETWORK/HISTORY/ALPB → amEeprom → mxsmbus → AT24C64AN @0x57（`data/nvram/eeprom.bin`、上記 mxsmbus 節）

mxsram/mxsmbus が micetools 準拠＋永続化されているため native amBackup パスが実データで成立する
（init がフック後に走るよう launch.py をサスペンド起動。`boot/README.md`）。

呼出階層（static_VA, ImageBase 0x400000）:

```
amBackupRecordReadDup(0x491180) / amBackupRecordWriteDup(0x491200)   ← セーブ管理 0x490xxx 群が利用
  → amBackupRead(0x985a00) / amBackupWrite(0x985940)                  記録プリミティブ
      → amBackupReadRecord(0x9858D0)                                  area記述子→デバイス read
          → amBackup_getAreaDescriptor(0x982f40)  area(0..3)→記述子テーブル(DAT_00adfb88/c28/bd8)
          → amBackupReadDevice(0x985770) / amBackupWriteDevice(0x985820)  記述子+0xc/+0x10 の fn ptr 呼出
              → mxsram デバイス（emulate 済み）
  検証: amBackupRecordCheckValid(0x985620)  CRC(+0)/ID 照合
init: amBackupInit(0x985570)  DAT_012899e0 を含む 0x404B コンテキスト確保
```

| static_VA | Name | Notes |
|---|---|---|
| 0x491180 | amBackupRecordReadDup | 記録読み（dup: primary+backup）。失敗で `amBackupRecordReadDup: error(%d)` |
| 0x491200 | amBackupRecordWriteDup | 記録書き（dup）。失敗で `amBackupRecordWriteDup: error(%d)` |
| 0x985a00 | amBackupRead | 記録 read プリミティブ |
| 0x985940 | amBackupWrite | 記録 write プリミティブ |
| 0x9858D0 | amBackupReadRecord | `*param_1`=area。 |
| 0x9858E1 | amBackupReadRecord_body | jne target |
| 0x985770 | amBackupReadDevice | 記述子+0xc の read fn を呼ぶ（"amBackupRead" 文字列） |
| 0x985820 | amBackupWriteDevice | 記述子+0x10 の write fn を呼ぶ（"amBackupWrite" 文字列） |
| 0x985620 | amBackupRecordCheckValid | CRC/ID 照合（"amBackupRecordCheckValid"） |
| 0x985570 | amBackupInit | コンテキスト初期化、DAT_012899e0=1 |
| 0x982f40 | amBackup_getAreaDescriptor | area(0..3)→記述子テーブル（amPlatformGetBoardType 分岐） |

グローバル:

| static_VA | Name | Notes |
|---|---|---|
| 0x12899E0 | amBackup_ctx_initFlag | 0=未init（各 fn が -28/0xffffffe4 を返す）。0x404B コンテキスト先頭 |
| 0x12899D8 | amBackup_debugLevel | >0 で amlib_error_display_0903 にエラー文字列 |
| 0x12899E4 | amBackup_crcCtx | CRC32(amiCrc32R) コンテキスト |

micetools SRAM レイアウト（参照・正、`dll/drivers/mxsram.c`）: 記録アドレス
ADDR_BACKUP=0x0 / HM_PEAK=0x200 / TIMEZONE=0x400 / ERROR_LOG=0x600、二重化 ADDR_DUP=+0x1000。
CRC=`amiCrc32RCalc`（record 先頭4Bが CRC）。
