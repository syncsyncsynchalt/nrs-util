# amPlatform FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。索引 `_index.md` / 横断知見 `workflow.md`。
confidence: [S]=静的解析 [L]=ライブ実走 [I]=推論 [F]=旧 Frida 計装(履歴・再取得は Ghidra/実走)

---

### amPlatform gate と期待値（エミュ供給）

| static_VA | Function | 期待値（gate 通過に必要） | 供給元 |
|---|---|---|---|
| 0x981D60 | amPlatformGetOsVersion | 非ゼロ parse で戻り 0（値自体は捨てられる。下記） | 仮想 `SystemVersion.txt`（api.c）|
| 0x981FF0 | amPlatformGetPlatformId | "AAL"（board ID。比較先 "AAL"/"AAM"/"NEC" と一致。"RingEdge" は表示名で NG） | columba DMI（mxdevices.c）|

platform gate `FUN_0045a6f0`（不一致で errCode 2/3 を latch）が読むのは **PlatformId と OsVersion のみ**。
Error 0901/AAL latch の真因もこの `FUN_0045a6f0`。両値は静的パッチでなくエミュで供給する（供給元は上表・詳細は下記）。`args[1]`(bufLen) はスタックゴミなので無視。

### patch しない関数（誤 patch 防止の注記）
- **amPlatformGetBoardType (0x982C50)**: patch 不要。AAL gate `FUN_0045a6f0` は BoardType を参照しない
  （消費先は `amBackup_getAreaDescriptor` 0x982f40 のみで attract 非 gate）。
- **HW type dispatcher 0x891B20**: patch 不要。packet recv 経路の dispatcher で SYSTEM STARTUP SM にも
  errCode latch にも到達しない＝**Error 0901 とは無関係**（0901 の真因は上記 `FUN_0045a6f0`）。

### RINGEDGE2 レジストリは nrs.exe 非依存 [S]

純正イメージの `REG_PLATFORM.reg` は `HKLM\SOFTWARE\SEGA\RING\LIBRARY\VERSION="RINGEDGE2"` を設定するが、
**nrs.exe はこの値も "RINGEDGE2" 文字列も参照しない**（`list_strings` でヒット無し）。RING\LIBRARY\VERSION は
システム層（mx*/amLib）が消費する値で、nrs.exe が見るのは board ID "AAL"＝本サブシステムの "AAL" 注入で十分。

---

### 0x981FF0(PlatformId) = columba DMI 供給 [S]

`amPlatformGetPlatformId`(0x981FF0) = `amOemstringGetOemstring`(0x988dd0, index 2) で DMI OEM 文字列を読み、
"AAL"/"AAM"/"NEC"(0xadfd70/6c/68) と照合（出力=一致した OEM 文字列。gate `FUN_0045a6f0` は strncmp で **"AAL" のみ通す**）。
DMI ロード= `amOemstring_loadDmi`(0x988c10) が `CreateFileW(\\.\columba)`＋`DeviceIoControl(0x9c406104)`。
columba は host エミュ（`src/logic/driver/mxdevices.c` build_dmi が index 2="AAL" を返す）。

### 0x981D60(OsVersion) = 仮想ファイル供給 [S]

gate `FUN_0045a6f0` は OsVersion の **戻り値が 0 か**だけを見る（値 local_10 は直後の memory size 取得で上書き＝捨てる。caller は gate ただ一つ）。
原関数 `amPlatformGetOsVersion`(0x981d60) は `C:\System\SystemVersion.txt` を CreateFileW→ReadFile(8B)→数値 parse し、末尾(0x981f19)で `DAT_00ccf44c!=0 → 戻り 0 / ==0 → 戻り -3`。standalone は同ファイル欠損で -3→errCode 3。
**解法**: host が仮想 `SystemVersion.txt` を供給（`api.c` on_create_file→sentinel 0xC0114002、on_read_file→8 バイト ASCII "20110728"）。非ゼロに parse → DAT_00ccf44c!=0 → 戻り 0 → gate 通過。パッチの "WindowsXP" 文字列は gate に無関係。
