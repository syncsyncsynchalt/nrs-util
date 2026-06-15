# mx ドライバ層 — FACTS（co-located）

横断定数 `../ARCH.md` / 索引 repo ルート `FACTS.md`。

RingEdge の mx* デバイスドライバを emulate（`devices.js`、persistence=runtime）:
`mxsram` / `mxsuperio` / `mxhwreset` / `\\.\pipe\teknoparrot_jvs` を `CreateFileA/W` ＋ `NtCreateFile`
でダミーハンドル化し、`DeviceIoControl` を成功（出力ゼロ埋め）させる。固定 RVA なし（Win32/native API フック）。
micetools 対応: `dll/drivers/`。

## mxsram = micetools `mxsram.c` 準拠（amBackup のバッキング） [F]

amBackup→amSram→mxsram の SRAM デバイス。micetools `src/micetools/dll/drivers/mxsram.c` を正として
以下を厳密準拠（2026-06-13）:

- **サイズ/初期値**: `1024*2084`=2,134,016B、新規は 0xFF 埋め。
- **永続化**: `data/nvram/sram.bin` にファイルバック（mmap 相当）。init 時に `CreateFileW(OPEN_ALWAYS)`
  でロード（既存）/0xFF 書出し（新規、`GetLastError`==183 で判定）。`WriteFile(mxsram)` 毎に
  該当領域を write-through。open 失敗時は揮発フォールバック＋WARN（micetools 同挙動）。
- **DeviceIoControl**: PING `0x9c406000`→`0x01000001` / GET_SECTOR_SIZE `0x9c406004`→512(RE1) /
  DRIVE_GEOMETRY `0x00070000`→Cyl256/Fixed(12)/Tracks2/Sectors8/512B（この時のみ出力ゼロ埋め）。
  **未対応（GET_LENGTH_INFO 等）は FALSE**。`lpBytesReturned`(args[6]) を 4/4/24 で設定。
- **Read/Write/SetFilePointer**: ハンドル毎の file pointer（`ctx->m_Pointer` 相当）。Read/Write は
  micetools 同様 **常に TRUE** を返し、bytesRead/Written は実コピー数。
- 注: mxsuperio/mxhwreset/jvs_pipe の挙動は従来どおり（変更なし）。

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

### `ENABLE_EEPROM`（既定 ON）— 完全動作・実機検証済み

サスペンド起動下で **mxsmbus/AT24C64AN emulation は完全動作**。amEepromInit 成功、amBackup の eeprom 系
レコード STATIC/CREDIT/NETWORK/HISTORY/BACKUP が read/write・`is broken=0`・`error(-3)=0`、
`eeprom.bin`/`sram.bin` に永続（2回目起動で読み戻し確認）、**clean ATTRACT 到達・維持（#2000+）・実写確認**。
STATIC は blank だと region/serial チェックで停止するため新規時に
`region=01, serial="SBVA…", 正CRC(amiCrc32R=標準CRC32)` で seed する。

経緯メモ: eeprom を成功させると amlib storage init が通り、ゲームが実機運用パスへ進む。その結果ルート
システムシーン callback(0x6C3F10)→`FUN_0089e880`(amApp_shouldShutdown)→`FUN_0089df40`(amApp_shutdown_now)
が `DAT_016f5aa0`(shutdown flag) を立て ATTRACT 前に clean ExitProcess していた（amBackup 自体は正常）。
これは `boot/app/no_selfshutdown.js` が 0x6C3F20 の `je`→`jmp` patch で無力化（boot の checkニュートラ方式）。
詳細は `app/FACTS.md` の「ルートシーン self-shutdown」。`ENABLE_EEPROM=false` にすると eeprom を発見不可にし
従来の degraded パス（records -3）へ戻せる。
