# keychip / PCP FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。索引 `_index.md` / 横断知見 `workflow.md`。
confidence: [S]=静的解析 [L]=ライブ実走 [I]=推論 [F]=旧 Frida 計装(履歴・再取得は Ghidra/実走)

> **PCP 応答の正準実装**: 下表は nrs.exe 側観測＋micetools(補助)。**正本＝実機 keychip デーモン** =
> `C:\src\ringedge_system_63.01.10\system\mxkeychip.exe`（CrackProof の公算大→実行時観測で裏取り。
> 所在 `ref.md`）。`code=54` バイパス・`encrypt`/`decrypt` AES・billing の実装確認は
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

### PCP キー全集合（実機 mxkeychip.exe で裏取り）[S]

純正 keychip デーモン `C:\src\ringedge_system_63.01.10\system\mxkeychip.exe`（**非パック**＝静的解析可。
entropy 6.68 / 完全 import 表 / 5768 文字列。CrackProof=Htsysm は runtime kernel ドライバで on-disk PE は
素のまま）から PCP キー全集合と内部ハンドラ名を確認。nrs.exe(client/libpcp) 側にも同一文字列が存在（両側一致）。

- `keychip.appboot.{gameid, systemflag, region, platformid, modeltype, formattype, networkaddr, dvdflag}`
  server/client 両側に実在する（nrs `list_strings` 一致）。
- `keychip.billing.{keyid, mainid, playcount, playlimit, nearfull, signaturepubkey, cacertification}`
  **`signaturepubkey`/`cacertification` は現行 pcpa_server 未対応**だが attract 非ブロッカー（billing 専用）:
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
  所在 `ref.md`。

**mxmaster (port 40100, foreground process manager)** [F]: in-game モジュールを持たず、サーバ側
`src/host/keychip_server.c`(40100) が応答する（micetools `micemaster/callbacks/foreground.c` 相当）。応答仕様:
- `mxmaster.foreground.getcount=N` → `getcount=N` ＋**別行 `count=0`**（`code=0` のみだとゲームが ~2 秒で終了）。
- `foreground.active=?` / `current=?` → `=1`（実機 mxmaster は非 develop モードで `m_current=1` 開始）。
- `foreground.next=N` → `next=N`（ack）、`foreground.fault=?` → `fault=0`、`foreground.setcount=N` → `setcount=N` ＋`count=N`。

---

## amlib region gate (Error 0903 "Wrong Region") [S]

region ゲートは2関数にあり、両方とも同じ判定式（**NOP/jl→jmp の対象**）:

```c
bVar = DAT_016014a2 ? DAT_01601989 : 0;            // gate付き dongleRegion
if ((DAT_016014c4 & bVar & 5) == 0) {              // PcbRegion & dongleRegion & 5
    "amlib: Region error."
    if (DAT_016f5af0 == 0) DAT_016f5af0 = 4;        // ← errCode 4 を latch（==0 ガードで固着）
}
```

JAPAN=01 を通すには **3オペランド全てに bit0 が必要**。各オペランドの出所（xref 確定）:

| データ | static | 意味 | 純正の供給源（実体確定） | 状態 |
|---|---|---|---|---|
| `region_dongle` | 0x1601989 | dongle region | keychip `appboot.region`（`FUN_00459220`→`FUN_0096f160`, PCP） | pcpa=01 で満たせる |
| `region_cached` | 0x1601744 | **AM_SYSDATAwH_HISTORY.m_Region**（EEPROM area4 @0x1601738+0xC） | 基板 EEPROM HISTORY レコード | EEPROM seed で 01 |
| `region_game_pcb` | 0x16014C4 | **AM_SYSDATAwH_STATIC.m_Region**（`amSysdataStatic` 0x16014b8+0xC のミラー） | **基板 EEPROM(AT24C64AN) area0=STATIC**。`amlib_storage_init_all`→`amBackupRead(area0,&amSysdataStatic)`→CRC 検証で展開 | **EEPROM seed で 01（実装済）** |

**訂正 [S] 2026-06-30**: `region_game_pcb` の「writer 無し」は `amBackupRead` が base 0x16014b8 へ**一括読込み**する静的 xref の死角だった。実体は**基板 EEPROM の STATIC レコード `m_Region`**で、ゲーム自身が CRC 検証付きで読む正規データ。`region_cached` も「keychip appboot cache」は誤りで EEPROM HISTORY.m_Region。
→ **純正の供給経路の再現**: EEPROM STATIC を seed すれば 3 オペランド全て正規経路で 01 になり `(1&1&5)!=0` で通る。直書き/NOP より faithful かつ timing-fragile でない（最初の SMBus read から正）。実装 `src/logic/driver/mxdevices.c` `eeprom_seed_static`（region=01/serial/amiCrc32R 正CRC を REG@0x000 へ。CRC 一致時は温存）。CRC = `amiCrc32RGet`(0x98a820, 反射 CRC-32 poly 0xEDB88320)。
→ これにより errCode-4 NOP(0x459109/0x45A846)と region DATA-write は撤去可能か検討。`amBackupRead` は REG 有効で DUP を読まず短絡するため REG seed のみで足りる。
（旧解法メモ: data-write 直書きは CrackProof 再init と setter 先行で timing-fragile だった。EEPROM seed はこれを回避する。）

**ライブ検証 [L] 2026-06-30**（seed＋`amEepromInit` detour 後）:
- **STATIC seed は genuine 経路で機能**: `amEepromInit() failed`=0 / `STATIC is broken`=0 / **region_game_pcb 00→01**。`amlib_master_init`(0x458fd0, 3値版) の `Region error (00,01,05)` は**消失**＝この check は genuine に通過 → **errCode-4 NOP `0x459109` は撤去済（2026-06-30 差分実証, patches 22→21）**。撤去後も 3値 region error は出ず errCode カスケードも無し（seed が「最初に立つ errCode」の根を断つ）。
- ただし**第2の region check `FUN_0045a7f0`(0x45a7f0, 4値版) は別経路で残存**: `Region error (01,01,00,05)`。第3オペランド `bVar2` は `FUN_006ff900(0/3)`＝**alAbEx/ALL.Net network region**（`DAT_0210aed0/aed2` auth ゲート後 `DAT_0210b594` 文字列でテーブル検索）で、EEPROM/keychip 非依存。net auth を詐称(network_auth_force_ready)するため発火し、network region 未供給で 0。**errCode-4 NOP `0x45A846` はこの network check のため当面維持**（撤去には ALL.Net region 供給が要る）。masked で非致命。
- **タイミングが鍵だった**: per-frame `eeprom_force_ready` は main loop（storage init 後）で遅すぎ region_game_pcb=0 を latch。`amEepromInit`(0x985160) を gamehook detour（`src/host/gamehook.c` d_eeprom_init, __thiscall→__fastcall, orig 非呼出で ctx provisioning＋0 返し）して storage init の最中に前倒しすると genuine な amBackupRead(STATIC) が seed を読む。abi v5(`on_eeprom_init`)。
- **永続 [L] 修正済**: 当初 実行後 eeprom.bin の STATIC が region=0x20/serial 化け＝**mxsmbus エミュの 8bit vcode 切詰め**(`mxdevices.c`)で高位 record(DUP @+0x1000 等)を STATIC(0x000)へ alias 混入していた。`vcode` を 13bit(0..0x1FFF, AT24C64AN 正幅)化して解消。実証: 1st boot で STATIC REG が region=01/serial="ABLN-00100000001" のまま無傷、**2nd boot(eeprom 温存)でも `STATIC broken`=0 / region_game_pcb=01 維持**（seed は CRC 一致で温存）。

| RVA(static) | 命令(10B) | 関数 | 呼出元(戻り値破棄) |
|---|---|---|---|
| 0x59109 (0x459109) | `MOV [0x016f5af0],4` → NOP10 | `FUN_00458fd0`（早期に走る本命 latcher） | `FUN_006c3730` |
| 0x5A846 (0x45a846) | `MOV [0x016f5af0],4` → NOP10 | `FUN_0045a7f0` | `FUN_00643de0` |

region 関連の patch/hook サイト（native は静的分を `src/logic/patches.c` で適用。旧 Frida の hook/watchdog は
root-cause 静的化で代替＝`port_status.md`）:
- **静的 patch（patches.c で適用）**: 0x986A66/0x986A74/0x986A92（keychip txn 成否ゲートを NOP6。下記訂正）、
  0x97588A/0x97595F/0x975A1F（isrelease SM の error-display 分岐 jl→jmp）、0x459109/0x45A846（上表 errCode=4 ストア NOP10）。
- **旧 hook（native 不要）**: 0x458FD0/0x45A7F0（amlib region check 2関数）、0x98A5F0（error-display 診断）。
- **data-write**: 0x16014C4/0x1601744/0x1601989（region-index 整合・上表）。

`DAT_016014c4=01`(PcbRegion) の data-write は anti-tamper `FUN_0048f9c0` の region-index 整合（01→0=JAPAN,
他→3）のため**維持**（errCode 抑止用ではない）。実装 `src/logic/patches.c`。比較は純正 `system\mxkeychip.exe` を正に、micetools / TeknoParrot は補助（`ref.md` 階層）。

**訂正 [S]**: 0x986A66/74/92 は「region の局所バイト比較」ではなく **keychip トランザクションの成否ゲート**だった。
実体は keychip コマンド 0xd9f0 を構築(0x987CA0)→ JVS フレーム符号化(`jvsp_frame_encode` 0x988810: チェックサム＋0xe0/0xd0 エスケープ)→
amJvsp で送信/応答(0x989020) の 3 段で、各段の失敗が Error 0x381/0x387/0x38D。`amJvs_sub1_ctx_ptr`（JVS 上の keychip）を使い、
PCP ネットワーク keychip（`keychip_server.c`, port 40100, テキスト protocol）とは別チャネル（バイナリ keychip-over-serial）。
NOP をエミュで外すには amJvsp keychip トランザクション（0xd9f0 round-trip）の実装が要り、現状どのエミュも未対応＝NOP 維持。
（パッチ注記「region jne」は旧 Frida の表層理解。実体は keychip 通信。）

---


### hookPcpa（PCP クライアント関数。native は `src/host/keychip_server.c` が全 7 ポートを serve＝client 介入不要）

| static_VA | Function |
|---|---|
| 0x98AEA0 | pcpaOpenClient(stream, ip, port, timeout_ms, unk)。orig<0 のときだけ ret→0 だが、server bind 済で負戻り無し＝回復 hook 不要（`port_status.md`） |
| 0x98AB20 | pcpaSetSendPacket(stream, key, val) |
| 0x98AB60 | pcpaAddSendPacket(stream, key, val) |
| 0x98AF50 | pcpaSendRequest(stream, unk) |
| 0x98AFF0 | pcpaRecvResponse(stream, unk)（orig=1 は "still polling"。ここで注入すると pcpa 応答前にバッファ破損するので注入しない） |

Response buffer offsets (stream struct): +0x258 and +0x1EC.
pcpaOpenClient return value semantics [F]: orig=1 = "new connection established, socket handle stored"; orig=0 = "use cached existing connection"; negative = error. Forcing 0 when orig=1 causes pcpaSendRequest to fail (-4) on ports with no prior cached socket (40106, 40104).

keychip setup: `src/host/gamehook.c` on_keychip_hold（game-fn hook 0x6F0A80, `FUN_006f0a80` errCode-1 latcher）が keychipSM setup を駆動補助し、`DAT_016014a2` ラッチ等を satisfy 維持する（server 前提で発火）。
