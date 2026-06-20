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

### HW type dispatcher 0x891B20 — Error 0901 SEH bypass [S+F]

| static_VA | Function | Patch | 効果 |
|---|---|---|---|
| 0x891B20 | HW type dispatcher（hw types 0-7 のジャンプ表）| `mov eax,1; ret 4`（`B8 01 00 00 00 C2 04 00`）| SEH 例外回避 → Error 0901 抑止 |

Root cause chain: `0x30292B → 0x4927F0`(hw enum, types 0-7) `→ 0x492710`(per-type wrapper, SEH 設置) `→ 0x891B20`
(dispatcher) `→ 0x5F0600 ほか`(hw 固有 fn, -1=no hardware)。hw fn が -1 を返すと dispatcher が C++ 例外を投げ、
`0x491AA9` の SEH が捕捉 → Error 0901 "Wrong Platform"。Fix: dispatcher を `ret 1` 化すると `0x492710` が
je→`xor al,al` 経路で al=0(success) を返し、`0x4927F0` が全 8 type をクリーンに抜ける（例外なし）。呼び元
`0x30292B` は戻り値を無視するため副作用なし。実装は **`patches.json`**（旧 `amplatform/hwdetect.js`）。

### RINGEDGE2 レジストリは nrs.exe 非依存（純正イメージとのクロスチェック）[S]

実機イメージ `C:\src\ringedge_system_63.01.10\` の `REG_PLATFORM.reg` は
`HKLM\SOFTWARE\SEGA\RING\LIBRARY\VERSION="RINGEDGE2"` を設定するが、**nrs.exe はこのレジストリ値も
"RINGEDGE2" 文字列も参照しない**（Ghidra `list_strings` で "RINGEDGE2"/"SOFTWARE\SEGA\RING" ともにヒット無し。
nrs 内の SEGA 関連文字列は AM Library バナー・フォント名・"RingEdge-BorderBreak/4.5" のみ）。
→ RING\LIBRARY\VERSION はシステム層（mx*/amLib）が消費する値で、**nrs.exe が見るのは board ID "AAL"**。
本サブシステムの "AAL" 注入で十分で、RINGEDGE2 レジストリ供給は不要。実機イメージが RINGEDGE2 世代である
ことの確認のみが裏取り成果（`docs/ringedge_system.md`）。なお nrs.exe は **OpenSSL 0.9.8i** を静的リンク
（ビルドパス文字列 `...\ring\openssl\openssl-0.9.8i\crypto\ec\ec2_smpt.c` で確認）。
