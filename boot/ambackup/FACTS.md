# amBackup — FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。横断定数は `../ARCH.md`、索引は repo ルート `FACTS.md`。
confidence: [F]=Frida確認 [S]=静的解析 [I]=推論

由来: `\namBackup Ver.1.04 Build:Jun 13 2012`（static 0xAE0CE8）。RingEdge NVRAM セーブ機構。
**2 デバイスに分かれる**（`amlib_storage_init_all` FUN_004597c0 で確定）:
- BACKUP レコード → amSram → mxsram（`data/nvram/sram.bin`）
- STATIC/CREDIT/NETWORK/HISTORY/ALPB → amEeprom → mxsmbus → AT24C64AN @0x57（`data/nvram/eeprom.bin`）
いずれも `boot/mxdrivers/devices.js` が micetools 準拠で emulate（詳細は `mxdrivers/FACTS.md`）。
init がフック後に走るよう launch.py をサスペンド起動する（`boot/README.md`）。

---

## native amBackup を使用

mxsram が micetools 準拠＋永続化されているため native パスが実データで成立する。
BACKUP→amSram→mxsram、STATIC/CREDIT/NETWORK/HISTORY/ALPB→amEeprom→mxsmbus で emulate。

## amBackup スタック [S]

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

## グローバル [S]

| static_VA | Name | Notes |
|---|---|---|
| 0x12899E0 | amBackup_ctx_initFlag | 0=未init（各 fn が -28/0xffffffe4 を返す）。0x404B コンテキスト先頭 |
| 0x12899D8 | amBackup_debugLevel | >0 で amlib_error_display_0903 にエラー文字列 |
| 0x12899E4 | amBackup_crcCtx | CRC32(amiCrc32R) コンテキスト |

## micetools SRAM レイアウト（参照・正） [S]

`dll/drivers/mxsram.c`: SRAM_SIZE_MAX=1024*2084、新規 0xFF。記録アドレス
ADDR_BACKUP=0x0 / HM_PEAK=0x200 / TIMEZONE=0x400 / ERROR_LOG=0x600、二重化 ADDR_DUP=+0x1000。
CRC=`amiCrc32RCalc`（record 先頭4Bが CRC）。
