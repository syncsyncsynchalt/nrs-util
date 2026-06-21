# keychip / PCP — FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。横断定数は `../ARCH.md`、索引は repo ルート `FACTS.md`。
confidence: [F]=Frida確認 [S]=静的解析 [I]=推論

> **PCP 応答の正準実装**: 下表は nrs.exe 側観測＋micetools。**実機 keychip デーモンの正バイナリ** =
> `C:\src\ringedge_system_63.01.10\system\mxkeychip.exe`（CrackProof の公算大→実行時観測で裏取り。
> 要約 `docs/ringedge_system.md`）。`code=54` バイパス・`encrypt`/`decrypt` AES・billing の実装確認は
> ここで行う。署名検証ルート鍵 = `system\ringmaster_pub.pem`（RSA-1024, e=0x10001。**nrs.exe 自身は非参照**
> ＝システム/ALL.Net 層が消費、将来のネットワーク層課題）。

---

## keychip PCPA Requests

| Key | Response | Port | Notes |
|---|---|---|---|
| `keychip.appboot.systemflag=?` | `keychip.appboot.systemflag=00` | 40106 | outerSM setup; hex byte, bit0=develop mode |
| `keychip.version=?` | `keychip.version=0001` | 40106 | outerSM setup |
| `keychip.ds.compute=<hex>&page=N` | `code=54` | 40106 | DS28CN01 bypass |
| `keychip.ssd.proof=<hex>` | `code=54` | 40110 | SSD auth bypass |
| `keychip.ssd.hostproof=<hex>` | `code=54` | 40110 | |
| `keychip.appboot.gameid=?` | `keychip.appboot.gameid=SBXX` | any | |
| `keychip.appboot.region=?` | `keychip.appboot.region=01` | any | 01=JAPAN (JAPAN build, FUN_0048f9c0: 01=JP/02=US/08=EXP). 02 fails the region check |
| `keychip.billing.playlimit=?` | `keychip.billing.playlimit=FFFFFFFF` | any | FreePlay |

**code=54 = ERR_COMMAND** (sega.bsnk.me/ringedge/security/): keychip lib treats it as "command not
supported" → skips cryptographic verification. This is the bypass for ds.compute / ssd.proof.
Other keychip commands: `appboot.platformid`/`networkaddr`, `encrypt`/`decrypt` (AES, data channel),
`setiv`, `billing.playcount`/`nearfull`/`keyid`, `tracedata.*`.

### PCP キー全集合 — 実機 mxkeychip.exe で裏取り [S]

純正 keychip デーモン `C:\src\ringedge_system_63.01.10\system\mxkeychip.exe`（**非パック**＝静的解析可。
entropy 6.68 / 完全 import 表 / 5768 文字列。CrackProof=Htsysm は runtime kernel ドライバで on-disk PE は
素のまま）から PCP キー全集合と内部ハンドラ名を確認。nrs.exe(client/libpcp) 側にも同一文字列が存在（両側一致）。

- `keychip.appboot.{gameid, systemflag, region, platformid, modeltype, formattype, networkaddr, dvdflag}`
  — server/client 両側に実在（nrs `list_strings` 一致）。
- `keychip.billing.{keyid, mainid, playcount, playlimit, nearfull, signaturepubkey, cacertification}`
  — **`signaturepubkey`/`cacertification` は現行 pcpa_server 未対応**だが attract 非ブロッカー（billing 専用）:
  - `amDongleBillingGetSignaturePubKey` = nrs static_VA **0x96FE50**（caller 0x45419F）→ PCP
    `keychip.billing.signaturepubkey&cache=...` を送る。**応答は ringmaster billing 公開鍵**
    （= `system\ringmaster_pub.pem`, RSA-1024）。
  - `amDongleBillingGetCaCertification` = nrs static_VA **0x96FF60** → `keychip.billing.cacertification&cache=...`。
  - 両者 billing クレジット系で attract demo ループでは未呼出（だから pcpa_server 未対応でも clean attract）。
    **将来のネットワーク/billing 層で必要**になったら pcpa_server に追加し、pem を base64/hex で返す。
- `keychip.ds.compute`、`keychip.ssd.{proof, hostproof}`、`keychip.setiv`、
  `keychip.tracedata.{restore, put, get, logicalerase, sectorerase}`（`logicalerase` も実在・現行未対応）。
- 暗号: **OpenSSL `AES-256-CBC`/192/128**（`encrypt`/`decrypt` データチャネル）、RSA。PCP ライブラリ
  = `libpcp Ver.1.08 Build:Nov 26 2012`（nrs 側 hookPcpa の pcpaSetSendPacket 等と同一実装）。
- 物理層ハンドラ名（参考）: `mxkN2Cmd{ReadKeychipID,ReadPlayCount,AddPlayCount}`(N2/SMBus)、
  `mxkDsKeychip{ComputeMac,ReadEeprom,Busy}`/`mxkGetKeychipIdFromN2`(DS28CN01/1-Wire)。
  詳細は `docs/ringedge_system.md`。

**mxmaster (port 40100)** [F]: `mxmaster.foreground.getcount=N` → must echo `getcount=N` AND a
separate `count=0` line (returning only `code=0` → game exits ~2s). `foreground.active=?`/`current=?` → `=0`.

---

## amlib region gate (Error 0903 "Wrong Region") [S]

region ゲートは2関数にあり、両方とも同じ判定式 — **NOP/jl→jmp の対象**:

```c
bVar = DAT_016014a2 ? DAT_01601989 : 0;            // gate付き dongleRegion
if ((DAT_016014c4 & bVar & 5) == 0) {              // PcbRegion & dongleRegion & 5
    "amlib: Region error."
    if (DAT_016f5af0 == 0) DAT_016f5af0 = 4;        // ← errCode 4 を latch（==0 ガードで固着）
}
```

JAPAN=01 を通すには **3オペランド全てに bit0 が必要**。各オペランドの出所（xref 確定）:

| データ | static | 意味 | writer | 状態 |
|---|---|---|---|---|
| `DAT_01601989` | 0x1601989 | dongle region | `FUN_00459220`→`FUN_0096f160`（keychip `appboot.region`） | pcpa=01 で満たせる |
| `DAT_01601744` | 0x1601744 | appboot m_Region cache | keychip appboot ブロック copy | pcpa=01 で 01 |
| **`DAT_016014c4`** | 0x16014C4 | **PcbRegion** | **writer 無し（全 xref READ）**＝本来 mxGetHwInfo/基板コンフィグ値 | バイパス構成では常に 0 |

→ PcbRegion=0 ゆえ `(0 & x & 5)=0` は不可避。data-write 強制は timing-fragile（setter が forceRegion 着弾前に走り
errCode 4 を display struct へ snapshot）。**解法は TeknoParrot 同様チェック無力化**: errCode 4 ストアを NOP。

| RVA(static) | 命令(10B) | 関数 | 呼出元(戻り値破棄) |
|---|---|---|---|
| 0x59109 (0x459109) | `MOV [0x016f5af0],4` → NOP10 | `FUN_00458fd0`（早期に走る本命 latcher） | `FUN_006c3730` |
| 0x5A846 (0x45a846) | `MOV [0x016f5af0],4` → NOP10 | `FUN_0045a7f0` | `FUN_00643de0` |

`DAT_016014c4=01`(PcbRegion) の data-write は anti-tamper `FUN_0048f9c0` の region-index 整合（01→0=JAPAN,
他→3）のため**維持**（errCode 抑止用ではない）。実装 `boot/mxkeychip/region.js`。比較は `docs/teknoparrot.md`/`docs/micetools.md`。

---


### hookPcpa IIFE

| RVA | Function |
|---|---|
| 0x58AEA0 | pcpaOpenClient(stream, ip, port, timeout_ms, unk) → logs orig; only forces ret→0 if orig<0 |
| 0x58AB20 | pcpaSetSendPacket(stream, key, val) |
| 0x58AB60 | pcpaAddSendPacket(stream, key, val) |
| 0x58AF50 | pcpaSendRequest(stream, unk) |
| 0x58AFF0 | pcpaRecvResponse(stream, unk) → log only; passes through（orig=1 は "still polling" で、ここで注入すると pcpa_server 応答前にバッファ破損するため注入しない） |

Response buffer offsets (stream struct): +0x258 and +0x1EC.
pcpaOpenClient return value semantics [F]: orig=1 = "new connection established, socket handle stored"; orig=0 = "use cached existing connection"; negative = error. Forcing 0 when orig=1 causes pcpaSendRequest to fail (-4) on ports with no prior cached socket (40106, 40104).
