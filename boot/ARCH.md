# boot/ARCH.md — 横断定数（全サブシステム共通）

バイナリ base / RVA 式 / PCP ポート・ワイヤ形式 / 静的ライブラリ / TeknoParrot パッチ。
サブシステム別の事実は `boot/<subsys>/FACTS.md`（索引は repo ルート `FACTS.md`）。

---

## Binary

| Property | Value |
|---|---|
| Path | C:\src\bbs\nrs.exe |
| Arch | x86 32-bit |
| ImageBase | 0x00400000 |
| OEP (static_VA) | 0x0067DAD4 |
| ImageSize | 0x02132000 (~33 MB) |
| ASLR | yes — nrs base varies per run (observed: 0x800000, 0x830000) |
| GameID string | "SBVA" at static_VA 0xC87384 (disasm.py verified) |

## Address dialect — STATIC VA everywhere (one dialect)

すべての番地は **Ghidra static_VA**（ImageBase 0x400000 込みの絶対 VA）で書く。RVA・runtime_VA は
`boot/lib/base.js` の `va()` helper の **内部だけ** に存在し、ドキュメント/ツール/コードの境界には出さない。

```
va(staticVA)        = nrsBase.add(staticVA - 0x400000)   // 唯一の変換境界
rtToVa(runtimePtr)  = (runtimePtr - nrsBase) + 0x400000  // runtime addr → static_VA（ログ用）
```

- Ghidra MCP / `tools/static/disasm.py` / boot シム / `MANIFEST.json` `va[]` / `known_names.json` キー /
  FACTS / BUGS — 全て static_VA。
- 生 `nrsBase.add(...)` は `tools/hygiene/check_doc_sync.py` が禁止（va() 経由を強制）。
- ⚠️ 旧 dialect 注意: 既存の **散文コメント・FACTS 本文には RVA 表記が残る**（reference 扱い・非実行）。
  値が要るときは Ghidra MCP / disasm.py（static_VA）で取り直す。

---


## PCPA Port Map [F]

| Port | Service | Notes |
|---|---|---|
| 40100 | mxmaster — foreground process mgmt | |
| 40102 | appslot — app/slot status queries | |
| 40104 | amNet — DHCP/NIC status | game bind-loops here until query_nic_status returns IP |
| 40106 | keychip — setup + **ds.compute** | ds.compute confirmed here by Frida; NOT port 40110 |
| 40110 | keychip — ssd.proof, stopcatcher, billing | PUSH 40110 at static_VA 0x978ADC [S] |
| 40111 | keychip — data channel | [I] |
| 40113 | mx-catcher — pause/stopcatcher | [F] raw winsock (NOT pcpaOpenClient); request=pause → code=0 |

Wire format (all ports):
```
S→C: ">"
C→S: "key1=val1&key2=val2\r\n"   ← request: &-separated key=val, one line, \r\n or \n terminated
S→C: "key=val\r\n[key=val\r\n...]>"  ← response: key=val lines, terminated by next ">" prompt
```
pcpaRecvResponse parses all key=val pairs into a buffer; callers query keys by name.

Other observed ports [F]: 23456 = `bind(192.168.1.209:23456)` (amNet loop-exit trigger);
30000-30002 = TeknoParrot bind (purpose unknown).

**NAOMI Net auth bypass** [S]: auto-skipped when Auth Server IP is unset. Confirmed string
"Auth Server IP is not specified. Auth authentication skipped." Leave auth IP unset in teknoparrot.ini.

---


## TeknoParrot nrs.exe Patches [F]

実行時観測 (`tools/runtime/frida_diag/tp_trace.js` + VirtualProtect フック)。
すべて **TeknoParrot が TP管理下の nrs.exe に適用するパッチ**。nrs-util は別手段で同等を達成している。
正は実機 TP（`C:\src\TPBootstrapper\`）の挙動。値が要るときは上記トレーサで取り直す。

### IAT パッチ (data section RVA 0x6dcXXX, size=4)

| RVA | 元ポインタ (LE) | TP 書込み値 (LE) | 備考 |
|---|---|---|---|
| 0x6dc164 | 60 84 0c 75 | 30 15 3e 68 | amDongle IAT → TP+0x153e30 |
| 0x6dc168 | 70 84 0c 75 | 50 16 3e 68 | |
| 0x6dc1a4 | a0 7d 0c 75 | e0 0a 3e 68 | |
| 0x6dc238 | 90 7d 0c 75 | 90 07 3e 68 | |
| 0x6dc254 | 70 82 0c 75 | 80 17 3e 68 | |
| 0x6dc268 | 10 7b 0c 75 | 70 06 3e 68 | |
| 0x6dc2b4 | 60 81 0c 75 | d0 12 3e 68 | |
| 0x6dc2bc | 90 83 0c 75 | 40 05 3e 68 | |
| 0x6dc2c0 | f0 83 0c 75 | 90 10 3e 68 | |
| 0x6dc2c4 | 50 84 0c 75 | 10 14 3e 68 | |
| 0x6dc2c8 | 20 7f 0c 75 | 70 0f 3e 68 | |
| 0x6dc2cc | 10 84 0c 75 | b0 11 3e 68 | |

元ポインタ高バイト = `0x750cXXXX` = nrs.exe 内の amDongle/amNet 関数群。TP は全て `0x683eXXXX` = TeknoParrot.dll 内の代替実装にリダイレクト。

### インライン JMP フック (E9 xx xx xx xx, 5バイト上書き)

代表的なもの（全50+）。RVA → TP ジャンプ先はセッション毎に変動 (ASLR)。

| RVA | 元1バイト | 機能 |
|---|---|---|
| 0x56c480 | 53 (PUSH EBX) | **amDongleInit** — TP が完全代替 |
| 0x56c590 | a1 (MOV EAX) | amDongle 関連 |
| 0x56dad0 | 51 (PUSH ECX) | amDongle 関連 |
| 0x56ee80 | a1 | amDongle 関連 |
| 0x56ef80 | a1 | amDongle 関連 |
| 0x56f070 | a1 | amDongle 関連 |
| 0x56f160 | a1 | amDongle 関連 |
| 0x56f250 | a1 | amDongle 関連 |
| 0x56f340 | a1 | amDongle 関連 |
| 0x56f470 | a1 | amDongle 関連 |
| 0x570fc0 | 8b (MOV) | amDongle 関連 |
| 0x571c40 | 53 | amDongle 関連 |
| 0x571ce0 | 83 | amDongle 関連 |
| 0x571d20 | 83 | amDongle 関連 |
| 0x571d70 | 81 | amDongle 関連 |
| 0x572c90 | 81 | amDongle 関連 |
| 0x572fe0 | 81 | amDongle 関連 |
| 0x274b30 | 55 (PUSH EBP) | FUN_00674b30 (PCPA state machine?) |
| 0x230444 | 0f | FUN_00630400 の先 (set_stage_id 付近) |
| 0x4b3b00 | a1 | FUN_008b3b00 (Touch Panel present check) |
| 0x575d00..0x578640 | a1/83 etc. | amNet/amPlatform 関連 多数 |
| 0x581d60..0x582c50 | 83 | amPlatform 関連 (nrs-util `04` で既対応) |
| 0x5842a0..0x586380 | 83/51 | amJvs 関連 (nrs-util `10` で既対応) |
| 0x595a0 | a1 | amDongle 初期化チェーン |
| 0xf3610 | 0f | FUN_004f3610 付近 |

### NOP パッチ

| RVA | サイズ | 元命令 | 目的 |
|---|---|---|---|
| 0x2ffc5d | 7 | `c6 05 10 b6 c4 02 01` → MOV BYTE PTR [0x02c4b610],1 | 0x02c4b610 を 0 に保持 |
| 0x2ffd99 | 7 | 同上 | 同上 |
| 0x30008c | 7 | 同上 | 同上 |
| 0x49a6ed | 6 | `0f 84 f5 01 00 00` → JE +0x1f5 | SYSTEM STARTUP (FUN_0089a010) の JE 除去 |
| 0xf2af3  | 6 | `8b 1d 6c fe db 02` → MOV EBX,[0x02dbfe6c] | (後続で inline hook に再パッチされる) |

### RET パッチ (4バイト `c3 00 00 00`)

| RVA | 元バイト | 機能推定 |
|---|---|---|
| 0x5a370 | 53 e8 4a 01 | 不明(amDongle 関連) — TP が即 RET |
| 0x575c0 | 80 3d 19 6a | 不明 — TP が即 RET |
| 0x4b2ad0 | 57 6a 54 33 | FUN_008b2ad0 (Touch Panel state machine) — TP が即 RET |

### データ上書き (ホスト名 → localhost)

TP は以下の .rdata 文字列フラグメントを `"localhost\0"` に上書きし、ALL.Net 接続を自サーバにリダイレクト。

| RVA | 元文字列(先頭10バイト) | TP書込み |
|---|---|---|
| 0x441ddc | naominet.j | localhost\0 |
| 0x441df8 | tenporouteau | localhost\0 |
| 0x441de8 | bbrouter.l | localhost\0 |
| 0x4426a0 | ib.naominet | localhost\0 |

nrs-util ではこれらは不要（SYSTEM STARTUP state6 で ALL.Net auth をスキップ、pcpa_server.py が PCPA を localhost で受信）。

### フラグ書き込み

| RVA | 変更 | 備考 |
|---|---|---|
| 0x5a93c | 0x00 → 0x01 | TP が mxkeychip/dongle present フラグを強制 1 に |

---


## Static Libraries in nrs.exe [S]

| Library | Version |
|---|---|
| SEGA AM Library (amLib) | 1.16 / 1.11 |
| amDongle | 1.12 |
| amJvs / amJvsp / amJvst | 1.07 / 1.05 / 1.05 |
| CRI Audio/PCx86 | 3.50.00 |
| OpenSSL | - |
| Lua | 5.1.4 |
| zlib | - |

---

## RingEdge System Image — 純正バイナリの所在 [S]

nrs.exe が載る OS/システム層の実機イメージ = `C:\src\ringedge_system_63.01.10\`（v63.01.10 / RINGEDGE2）。
要約は `docs/ringedge_system.md`、正は実バイナリ直読。本リポジトリ直結のもの:
- **keychip デーモンの実装の正** = `system\mxkeychip.exe`（`pcpa_server.py` が偽装する相手）。**非パック＝Ghidra
  静的解析可**（entropy 6.68・完全 import 表・libpcp 1.08・OpenSSL AES-CBC。CrackProof=Htsysm は runtime
  kernel ドライバで on-disk PE は素）。PCP キー全集合は `mxkeychip/FACTS.md`。
- **ringmaster RSA 公開鍵**（ALL.Net/billing 署名検証ルート）= `system\ringmaster_pub.pem`（RSA-1024, e=0x10001,
  modulus 先頭 `00:c7:ff:2d:0b:16:e8:95...`）。micetools 同梱の billing.pub/ca.crt とは別物。
