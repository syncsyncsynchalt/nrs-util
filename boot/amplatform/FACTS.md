# amPlatform — FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。横断定数は `../ARCH.md`、索引は repo ルート `FACTS.md`。
confidence: [F]=Frida確認 [S]=静的解析 [I]=推論

---

### hookAmPlatform IIFE

| RVA | Function | Injected Value |
|---|---|---|
| 0x581D60 | amPlatformGetOsVersion | "WindowsXP" |
| 0x581FF0 | amPlatformGetPlatformId | "AAL" (ハードウェア board ID。比較先 "AAL"/"AAM"/"NEC" と一致させる。"RingEdge" は表示名で NG) |
| 0x582C50 | amPlatformGetBoardType | integer 0 (DWORD* out へ書く board type index。文字列を書くと 0x676E6952 に化けジャンプ表破損) |

Implementation: `Memory.patchCode`（`patchPlatformFunc` / `patchBoardTypeFunc` ヘルパー）で関数先頭を
永続パッチ。`mov eax,[esp+4]; byte-by-byte write; xor eax,eax; ret 4`（stdcall, ret 4 確認済）。
Interceptor ではないため Frida detach 後も有効。`args[1]` (bufLen) はスタックゴミ（観測値 1,3）なので読まない。

### RINGEDGE2 レジストリは nrs.exe 非依存（純正イメージとのクロスチェック）[S]

実機イメージ `C:\src\ringedge_system_63.01.10\` の `REG_PLATFORM.reg` は
`HKLM\SOFTWARE\SEGA\RING\LIBRARY\VERSION="RINGEDGE2"` を設定するが、**nrs.exe はこのレジストリ値も
"RINGEDGE2" 文字列も参照しない**（Ghidra `list_strings` で "RINGEDGE2"/"SOFTWARE\SEGA\RING" ともにヒット無し。
nrs 内の SEGA 関連文字列は AM Library バナー・フォント名・"RingEdge-BorderBreak/4.5" のみ）。
→ RING\LIBRARY\VERSION はシステム層（mx*/amLib）が消費する値で、**nrs.exe が見るのは board ID "AAL"**。
本サブシステムの "AAL" 注入で十分で、RINGEDGE2 レジストリ供給は不要。実機イメージが RINGEDGE2 世代である
ことの確認のみが裏取り成果（`docs/ringedge_system.md`）。なお nrs.exe は **OpenSSL 0.9.8i** を静的リンク
（ビルドパス文字列 `...\ring\openssl\openssl-0.9.8i\crypto\ec\ec2_smpt.c` で確認）。
