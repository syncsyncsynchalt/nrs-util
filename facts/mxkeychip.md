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
| `keychip.appboot.systemflag=?` | `keychip.appboot.systemflag=01` | 40106 | outerSM setup; hex byte, bit0=develop mode（`keychip_proto.c KC_SYSFLAG "01"`）|
| `keychip.version=?` | `keychip.version=0001` | 40106 | outerSM setup |
| `keychip.ds.compute=<hex>&page=N` | `code=54` | 40106 | DS28CN01 bypass |
| `keychip.ssd.proof=<hex>` | `code=54` | 40110 | SSD auth bypass |
| `keychip.ssd.hostproof=<hex>` | `code=54` | 40110 | |
| `keychip.appboot.gameid=?` | `keychip.appboot.gameid=SBVA` | any | value from keychip_proto.c KC_GAMEID |
| `keychip.appboot.region=?` | `keychip.appboot.region=01` | any | 01=JAPAN (JAPAN build, FUN_0048f9c0: 01=JP/02=US/08=EXP). 02 fails the region check |
| `keychip.billing.playlimit=?` | `keychip.billing.playlimit=FFFFFFFF` | any | FreePlay |

**code=54 = ERR_COMMAND** (sega.bsnk.me/ringedge/security/): keychip lib treats it as "command not
supported" → skips cryptographic verification. This is the bypass for ds.compute / ssd.proof.
Other keychip commands: `appboot.platformid`/`networkaddr`, `encrypt`/`decrypt` (AES, data channel),
`setiv`, `billing.playcount`/`nearfull`/`keyid`, `tracedata.*`.

### PCP キー全集合（正本 = 実機 `system\mxkeychip.exe` 非パック）[S]。served= keychip_proto.c
キー全集合 = `keychip.appboot.{gameid,systemflag,region,platformid,modeltype,formattype,networkaddr,dvdflag,seed}` /
`keychip.billing.{keyid,mainid,playcount,playlimit,nearfull,signaturepubkey,cacertification}` /
`keychip.ds.compute` / `keychip.ssd.{proof,hostproof}` / `keychip.{encrypt,decrypt,setiv}` /
`keychip.tracedata.{restore,put,get,logicalerase,sectorerase}`。両側(server/client) list_strings 一致。
- billing `signaturepubkey`/`cacertification`: keychip_proto.c 未対応・attract 非ブロッカー。
  `amDongleBillingGetSignaturePubKey`=0x96FE50(caller 0x45419F), `amDongleBillingGetCaCertification`=0x96FF60。
  応答=ringmaster billing 公開鍵(`system\ringmaster_pub.pem`, RSA-1024)。attract 未呼出。billing 層で必要時 pem を base64/hex 返し。
- 暗号 = OpenSSL AES-256/192/128-CBC(`encrypt`/`decrypt`), RSA。lib=`libpcp Ver.1.08 Build:Nov 26 2012`。

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

`region_game_pcb` は writer 無しではなく、**基板 EEPROM の STATIC レコード `m_Region`**（`amBackupRead` が base 0x16014b8 へ一括読込みするため直接 xref に出ない）で、ゲーム自身が CRC 検証付きで読む正規データ。`region_cached` は EEPROM HISTORY.m_Region。
→ **純正の供給経路の再現**: EEPROM STATIC を seed すれば 3 オペランド全て正規経路で 01 になり `(1&1&5)!=0` で通る（最初の SMBus read から正で timing-fragile でない）。実装 `src/logic/driver/mxdevices.c` `eeprom_seed_static`（region=01/serial/amiCrc32R 正CRC を REG@0x000 へ、CRC 一致時は温存）。CRC = `amiCrc32RGet`(0x98a820, 反射 CRC-32 poly 0xEDB88320)。`amBackupRead` は REG 有効で DUP を読まず短絡するため REG seed のみで足りる。

- STATIC seed 効果: `amlib_master_init`(0x458fd0, 3値版) の `Region error (00,01,05)` 消失＝genuine 通過→**errCode-4 NOP `0x459109` 撤去済み**。
- `amlib_region_gate`(0x45a7f0, 4値版) 残存: `Region error (01,01,00,05)`。第3オペランド `bVar2`=`FUN_006ff900(0/3)`＝alAbEx/ALL.Net network region（`DAT_0210aed0/aed2` auth 後 `DAT_0210b594` テーブル検索、EEPROM/keychip 非依存）。net auth 詐称で発火・region 未供給で 0→errCode-4 NOP `0x45A846` は**撤去済**（src に不在, 下記表・line 86）。残る `Region error (01,01,00,05)` は masked 非致命ゆえ NOP 無しでも通過（完全解消には ALL.Net region 供給要）。
- タイミング: `amEepromInit`(0x985160) を gamehook detour（`src/host/gamehook.c` d_eeprom_init, __thiscall→__fastcall, orig 非呼で ctx provision＋0 返し, abi v5 `on_eeprom_init`）で storage init 中に前倒し→genuine amBackupRead(STATIC) が seed 読む。per-frame force は main loop で遅すぎ latch する。
- 永続: mxsmbus `vcode` は 13bit(0..0x1FFF, AT24C64AN 正幅。8bit 切詰めは DUP@+0x1000 が STATIC@0x000 へ alias→region=0x20 化け)。1st/2nd boot とも region_game_pcb=01 維持（seed CRC 一致で温存）。

| RVA(static) | 命令(10B) | 関数 | 呼出元(戻り値破棄) |
|---|---|---|---|
| 0x59109 (0x459109) | `MOV [0x016f5af0],4` → NOP10 | `amlib_master_init`(0x458fd0, 早期に走る本命 latcher) | `FUN_006c3730` |
| 0x5A846 (0x45a846) | `MOV [0x016f5af0],4` → NOP10 | `amlib_region_gate`(0x45a7f0) | `FUN_00643de0` |

region 関連の patch/hook サイト（native は静的分を `src/logic/patches.c` で適用）:
- **静的 patch（patches.c で適用）**: 0x97588A/0x97595F/0x975A1F（isrelease SM の error-display 分岐 jl→jmp）のみ。
  0x986A66/0x986A74/0x986A92（keychip txn 成否ゲート）・0x459109/0x45A846（errCode=4 ストア）に該当する patch は無し（応答・genuine 供給で解消、src に不在）。
- **data-write は全撤去**（0x1601744/0x1601989/0x16014C4）。genuine 供給に置換されて冗長:
  - `0x1601989`(region_dongle) ← `FUN_00459220` の `FUN_0096f160(&region_dongle,0)` = keychip `appboot.region` PCP（keychip present 枝、`on_keychip_hold` で presence 維持・`keychip_server` が `=01`）。撤去後も `Region error (01,01,00,05)` の第2 operand=01 維持＝keychip 供給がライブで効く証拠。
  - `0x1601744`(region_cached) ← `FUN_0045acc0` の `DAT_01601744 = DAT_016014c4`（region_game_pcb/STATIC seed=01 のコピー、`amlib_eeprom_ok` 成立時に HISTORY area4 へ書く）。STATIC 由来でコピーされるため genuine。
  - `0x16014C4`(region_game_pcb/STATIC) ← EEPROM STATIC seed（`mxdevices.c eeprom_seed_static`, m_Region@+0x0C=01）が供給。bind 時 direct-write は CrackProof アンパックで clobber されるため実供給は seed が担う。撤去後も 4値 region error の第1 operand=01 維持。anti-tamper `FUN_0048f9c0` の region-index 整合（01→0=JAPAN, 他→3）も seed 値で満たされ fault 不在。回帰（0903/第1 operand=00/anti-tamper）時は patches.c の本行を復活。比較は純正 `system\mxkeychip.exe` を正に、micetools / TeknoParrot は補助（`ref.md` 階層）。

**0x986A66/74/92 = keychip トランザクションの成否ゲート**（「region の局所バイト比較」ではない）: 実体は keychip コマンド 0xd9f0 を構築(0x987CA0)→ JVS フレーム符号化(`jvsp_frame_encode` 0x988810: チェックサム＋0xe0/0xd0 エスケープ)→ amJvsp で送信/応答(0x989020) の 3 段で、各段の失敗が Error 0x381/0x387/0x38D。`amJvs_sub1_ctx_ptr`（JVS 上の keychip）を使い、PCP ネットワーク keychip（`keychip_server.c`, port 40100, テキスト protocol）とは別チャネル（バイナリ keychip-over-serial）。NOP をエミュで外すには amJvsp keychip トランザクション（0xd9f0 round-trip）の実装が要り、現状どのエミュも未対応＝NOP 維持。

---


### hookPcpa（PCP クライアント関数。native は `src/host/keychip_server.c` が全ポート(40100..40115,30000; PORTS[]=13 ポート)を serve＝client 介入不要）

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
