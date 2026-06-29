# amPlatform FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。索引 `_index.md` / 横断知見 `workflow.md`。
confidence: [S]=静的解析 [L]=ライブ実走 [I]=推論 [F]=旧 Frida 計装(履歴・再取得は Ghidra/実走)

---

### amPlatform gate と期待値（静的パッチは撤去済み＝エミュ供給）

| static_VA | Function | 期待値（gate 通過に必要） |
|---|---|---|
| 0x981D60 | amPlatformGetOsVersion | 非ゼロ parse で戻り 0（値自体は捨てられる。下記） |
| 0x981FF0 | amPlatformGetPlatformId | "AAL"（board ID。比較先 "AAL"/"AAM"/"NEC" と一致。"RingEdge" は表示名で NG） |

platform gate `FUN_0045a6f0`（不一致で errCode 2/3 を latch）が読むのは **PlatformId と OsVersion のみ**。
Error 0901/AAL latch の真因もこの `FUN_0045a6f0`。**2026-06-29 に両関数の静的パッチ（旧 Frida 注入 "AAL"/"WindowsXP"）を
撤去しエミュ供給へ移行**: PlatformId は columba DMI、OsVersion は仮想 `SystemVersion.txt`（下記）。`args[1]`(bufLen) は
スタックゴミなので無視。

### patch しない関数（誤 patch 防止の注記）
- **amPlatformGetBoardType (0x982C50)**: patch 不要。AAL gate `FUN_0045a6f0` は BoardType を参照しない
  （消費先は `amBackup_getAreaDescriptor` 0x982f40 のみで attract 非 gate）。
- **HW type dispatcher 0x891B20**: patch 不要。packet recv 経路の dispatcher で SYSTEM STARTUP SM にも
  errCode latch にも到達しない＝**Error 0901 とは無関係**（0901 の真因は上記 `FUN_0045a6f0`）。

### RINGEDGE2 レジストリは nrs.exe 非依存（純正イメージとのクロスチェック）[S]

実機イメージ `C:\src\ringedge_system_63.01.10\` の `REG_PLATFORM.reg` は
`HKLM\SOFTWARE\SEGA\RING\LIBRARY\VERSION="RINGEDGE2"` を設定するが、**nrs.exe はこのレジストリ値も
"RINGEDGE2" 文字列も参照しない**（Ghidra `list_strings` で "RINGEDGE2"/"SOFTWARE\SEGA\RING" ともにヒット無し。
nrs 内の SEGA 関連文字列は AM Library バナー・フォント名・"RingEdge-BorderBreak/4.5" のみ）。
→ RING\LIBRARY\VERSION はシステム層（mx*/amLib）が消費する値で、**nrs.exe が見るのは board ID "AAL"**。
本サブシステムの "AAL" 注入で十分で、RINGEDGE2 レジストリ供給は不要。実機イメージが RINGEDGE2 世代である
ことの確認のみが裏取り成果（`ref.md` の RingEdge 純正イメージ）。なお nrs.exe は **OpenSSL 0.9.8i** を静的リンク
（ビルドパス文字列 `...\ring\openssl\openssl-0.9.8i\crypto\ec\ec2_smpt.c` で確認）。

---

### 0x981FF0(PlatformId) は columba DMI でエミュ済み＝静的パッチ冗長 [S]

`amPlatformGetPlatformId`(0x981FF0) の素の実体は `amOemstringGetOemstring`(0x988dd0, index 2) で DMI の OEM 文字列を読み、
期待値 "AAL"/"AAM"/"NEC"（0xadfd70/6c/68）と照合して platform id を決める。
OEM 文字列のロードは `amOemstring_loadDmi`(0x988c10) が `CreateFileW(\\.\columba)` ＋ `DeviceIoControl(0x9c406104)` で
オンデマンドに行う。columba は host が完全エミュ済みで、`src/logic/driver/mxdevices.c` の build_dmi が OEM 文字列
index 2 = "AAL" を返す。
よって amPlatformGetPlatformId は **静的パッチ無しでも "AAL" を返す**＝0x981FF0 は冗長。
**撤去済み（2026-06-29）。ライブ確認**：新 logic（patches.applied count 29→28）で host.ready → 約3分の安定 attract
（JVS/touch ポーリング継続、ログ実時間成長）、Error 0901・error scene・errCode マーカー 0 件。
columba DMI が "AAL" を実走で供給することを確証。再発時のみ復活させる。

**OsVersion(0x981D60) も撤去済み（2026-06-29, ライブ確認）= 仮想ファイル化。** gate `FUN_0045a6f0` を実体確認した結果、
OsVersion は **戻り値が 0 か**だけを見る（値 local_10 は直後の memory size 取得で上書き＝捨てる。caller は gate ただ一つ）。
原関数 `amPlatformGetOsVersion`(0x981d60) は `C:\System\SystemVersion.txt` を CreateFileW→ReadFile(8B)→数値 parse し、
末尾(0x981f19)で `DAT_00ccf44c!=0 → 戻り 0 / ==0 → 戻り -3`。standalone は同ファイル欠損で -3→errCode 3。
**解法**: host が仮想 `SystemVersion.txt` を供給（`api.c` on_create_file→sentinel 0xC0114002、on_read_file→8 バイト ASCII "20110728"）。
非ゼロに parse → DAT_00ccf44c!=0 → 戻り 0 → gate 通過。パッチの "WindowsXP" 文字列は gate に無関係だった。
ライブ: count=25、`sysver.open` 後 errCode 3 なし・host.ready→安定 attract（uptime 130s+）。
