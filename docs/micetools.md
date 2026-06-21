# micetools 要約（SEGA Ring series 参照実装。keychip / amDongle / PCP）

**正（source of truth）はローカルの C ソース `C:\src\micetools\`。本資料はその要約。**
keychip 認証・amDongle・billing・PCP の値/フォーマット/シーケンス/構造体オフセットを使う前に、必ず該当
`.c`/`.h` を**直読**して裏取りする（下記表の対応で当該ファイルへ飛ぶ）。nrs.exe は同じ `am*` ライブラリを
リンクしているので、関数名・構造体・PCP keyword・エラーコードがそのまま一致する。**TeknoParrot より低レイヤ**。

- ローカル: `C:\src\micetools\`（無ければ §11 で clone）。上流 `https://gitea.tendokyu.moe/Bottersnike/micetools`
  （master, 本要約作成時 commit `05fcc7f`）。WebFetch は 403、clone のみ。作者 Bottersnike。
- 関連: `docs/teknoparrot.md`（上位レイヤ）、`../boot/<subsys>/FACTS.md`（nrs 実アドレス）、`../BUGS.md`。

---

## 1. これが効く理由（nrs-util の Frida スクリプトとの対応）

micetools は SEGA の `am*` ライブラリ（amDongle/amEeprom/amBackup/…）と keychip サーバを
クリーンルーム再実装している。nrs.exe は同じ `am*` ライブラリをリンクしているので、
**関数名・構造体・プロトコル・エラーコードがそのまま一致する**。

| nrs-util の Frida スクリプト | micetools の参照実装 | 何が分かるか |
|---|---|---|
| `boot/amdongle/patch.js` | `lib/am/amDongle.c` / `.h` | amDongle 状態機械・リクエストコード・PCP 会話の全手順 |
| `boot/mxkeychip/setup.js`（観測 `frida_diag/keychip_setup_diag.js`） | `amDongle.c::amDongleSetupKeychip` + `micekeychip/` | keychip セットアップが投げる PCP keyword と期待応答 |
| `boot/amdongle/*`（観測 `frida_diag/dongle_update_diag.js`） | `amDongle.c::amDongleUpdate` / tracedata callbacks | dongle update が tracedata.restore で何を待つか |
| `boot/patches.json(0xA065C0)` | `micekeychip/callbacks/billing.c` | playcount/playlimit/nearfull/keyid の応答フォーマット |
| `boot/mxgfetcher/getstatus.js` | `lib/am/amGfetcher.h` + `patches/mxgfetcher.patch` | gfetcher は薄い。実体は AMSRAM ログフラグ程度 |
| region error(0903)調査 | `micekeychip/callbacks/appboot.c::mxkPcpAbRegion` | region は `keychip.appboot.region` の 2 桁 HEX 応答 |
| Error 1000 調査 | `amDongle.c` の `AM_DONGLE_STATUS_*` 列挙 | dongle 系エラーの正準コード表 |

> **使い方の勘所**: nrs を Frida で殴る代わりに、micetools の knowledge を使えば
> 「keychip サーバ(127.0.0.1:40106)を立てて正規応答を返す」方向の解法も取れる。
> 少なくとも「nrs が次に何の PCP keyword を投げ、どんな文字列を期待しているか」が
> 確定するので、フックの当て先と返り値が推測でなく確定になる。

---

## 2. アーキテクチャ（keychip は2層）

物理 keychip と、ゲームが話す相手は **別物**。間に keychip サーバプロセスが挟まる。

```
[ゲーム nrs.exe]
   └ amDongle (lib/am/amDongle.c)         ← nrs-util が殴っている層
        │  PCP over TCP  127.0.0.1:40106(制御) / 40107(バイナリ)
        ▼
[keychip サーバ = 実機では mxkeychip.exe / micetools では micekeychip.exe]
   └ PCP keyword ディスパッチ (micekeychip/mxk.c)
        │  SMBus / パラレルポート 低レベルコマンド (lib/mxk/*)
        ▼
[物理 keychip = N2 チップ(SMBus) または PIC + DS2460/DS28CN01(1-Wire SHA)]
```

- **amDongle ↔ keychip サーバ**: テキストベースの **PCP プロトコル**（後述）。ここが nrs-util の主戦場。
- **keychip サーバ ↔ 物理チップ**: SMBus/パラレル経由のバイナリコマンド（`lib/mxk/mxkDefs.h` の enum）。
  実機 keychip がある運用者向け。スタンドアロン化では **PCP 層を偽装すれば物理層は不要**。
- micetools の `micekeychip` は PCP サーバを丸ごとエミュレートし、物理チップなしで応答を返す。

---

## 3. PCP プロトコル（amDongle ⇄ keychip サーバ）

`key=value` を `&` で連結したテキストを TCP で往復。先頭 key が「keyword(=コマンド)」、
`code=<n>` がステータス、`cache`/`size`/`port`/`address` などが付帯。

- **制御ポート 40106**、**バイナリ転送ポート 40107**（`amDongle.c` のデフォルト、`micekeychip/config.def` と一致）。
- バインドは既定 `127.0.0.1`（`bind_global=true` で 0.0.0.0）。
- 実装: `lib/libpcp/pcpa.*`（amDongle 側）／ `lib/libpcp/libpcp.*` ＋ `micekeychip/mxk.c`（サーバ側）。

### keyword 一覧（= keychip が解釈するコマンド）

`micekeychip/callbacks/callbacks.h` のディスパッチ表が正準。応答フォーマットは各 callback 実装より。

| keyword | 用途 | 応答（micekeychip 実装） |
|---|---|---|
| `keychip.version` | PIC/N2 バージョン | `%04X`（PIC=0x0104, N2=0x0106）。`device=n2` で N2 を返す |
| `keychip.status` | 生存確認 | `"available"` |
| `keychip.appboot.gameid` | ゲーム ID | KCF ヘッダ m_GameId 4 文字 |
| `keychip.appboot.systemflag` | システムフラグ | `%02X`。bit0=develop |
| `keychip.appboot.modeltype` | 機種型 | `%02X` |
| `keychip.appboot.formattype` | フォーマット型 | `%02X` |
| `keychip.appboot.region` | **リージョン** | `%02X`（**0903 系の元データ**） |
| `keychip.appboot.platformid` | プラットフォーム ID | 3 文字（例 `AAV`/`ACA`…） |
| `keychip.appboot.networkaddr` | ネットワークアドレス | `a.b.c.d` ドット表記 |
| `keychip.appboot.dvdflag` | DVD フラグ | `%02X` |
| `keychip.appboot.seed` | appboot seed | バイナリ送信(16B)＋ `port=40107`,`size=16` |
| `keychip.billing.keyid` | keychip ID | 例 `A69E-01A8888`（17桁、`XXXX-XXXXXXX`） |
| `keychip.billing.mainid` | 基板 ID(board id) | 文字列(≤11) |
| `keychip.billing.playcount` | プレイ数 | `%08X` |
| `keychip.billing.playlimit` | プレイ上限 | `%08X`（既定 0x00001400） |
| `keychip.billing.nearfull` | 課金報告閾値 | `%08X`（既定 0x00066048） |
| `keychip.billing.signaturepubkey` | 署名公開鍵 | バイナリ送信（`billing.pub`） |
| `keychip.billing.cacertification` | ルート CA 証明書 | バイナリ送信（`ca.crt`） |
| `keychip.encrypt` | AES 暗号化 | 平文 HEX→暗号 HEX（AES-128-CBC, KCF の Key/Iv） |
| `keychip.decrypt` | AES 復号 | 暗号 HEX→平文 HEX（IV は前ブロック連鎖） |
| `keychip.setiv` | IV リセット | `"1"`、内部 workingIv を KCF Iv に戻す |
| `keychip.ds.compute` | DS(1-Wire SHA) 챌レンジ | micekeychip は未実装 → `code=54`(COMMAND err) |
| `keychip.ssd.proof` | SSD 챌レンジ | 同上 `code=54` |
| `keychip.ssd.hostproof` | SSD ホスト証明 | 空応答 |
| `keychip.tracedata.restore` | 課金トレース復元 | `restart=1` なら `"1"` 、否なら `"2"` |
| `keychip.tracedata.put` | トレース書込 | `"6410"` |
| `keychip.tracedata.get` | トレース読出 | `"0"` ＋ `address=0` |
| `keychip.tracedata.logicalerase` | 論理消去 | `"0"` |
| `keychip.tracedata.sectorerase` | セクタ消去 | `"0"` |
| `keychip.eeprom` | EEPROM | `"0"` |
| `keychip.nvram0`..`9` | NVRAM 領域 | `"0"` |

### `code=` ステータス（`amDongle.c::amDongleCodeToStatus`）

```
0  OK / 1,2 KEYCHIP error / 50 VERIFY / 51 LOG_FULL / 52 NO_LOG
53 ONE_WRITE / 54 COMMAND(=micekeychip が未実装時に返す) / 55 KEYCHIP_DATA
```

---

## 4. amDongle 状態機械（`lib/am/amDongle.c`）

ゲーム側 API。`AM_LIB_*` マクロでシングルトン `amDongle` を持つ。要点のみ。

- **`amDongleSetupKeychip()`**: 非ブロッキングのセットアップ状態機械（`PENDING` を返し続け `OK` で完了）。
  手順: open → `keychip.appboot.systemflag?` 送信 → systemflag 取得(bit0→develop)
  → `keychip.version?` 送信 → version 取得 → close → `available=1,done_init=1`。
  **`code=1/2`(KEYCHIP) を踏むと available=0 のまま ERR で抜ける** ＝ ここが Error 1000 系の発生点候補。
- **`amDongleSendAndReceiveEx()`**: 1 リクエスト＝send→recv→`amDongleResponseCheck()`。
  `requestCode & 0x80` が立つとバイナリ転送(40107)へ。`&0x40` で送信/受信を分岐。
- **`amDongleResponseCheck()`**: keyword 別に応答を `valueBuffer`/`dataBuffer` へパース（巨大 switch、TODO 多数）。
- リクエストコード `AM_DONGLE_REQUEST`（`amDongle.h`）抜粋:
  ```
  1 SET_IV  2 DECRYPT  3 ENCRYPT  4 GET_GAME_ID  5 GET_SYSTEMFLAG  6 GET_MODEL_TYPE
  7 GET_REGION  8 GET_PLATFORM_ID  9 GET_NETWORK_ADDRESS  10 GET_VERSION
  11..25 BILLING_*（keyid/mainid/playcount/playlimit/nearfull/tracedata…）
  26 GET_DVDFLAG  27 GET_DS_COMPUTE  28 GET_SSD_PROOF  30 GET_FORMAT_TYPE
  0x80|0 APPBOOT_SEED  0x80|2 BILLING_GET_TRACEDATA  0x80|3 SIGNATURE_PK  0x80|4 CA_CERT
  0xC0|1 UPDATE_PLAYLIMIT  0xC0|2 UPDATE_NEARFULL   (0x80=recv bin, 0xC0=send bin)
  ```
- ステータス列挙 `AM_DONGLE_STATUS`（`amDongle.h`）: `OK=0, BUSY=1, PENDING=2,
  NG=-1, ERR_INVALID_PARAM=-2, ERR_NO_INIT=-3, ERR_ALREADY_INIT=-4, ERR_PCP=-5,
  ERR_COMMAND=-6, ERR_VERIFY=-7, …, ERR_KEYCHIP_DATA=-11, ERR_KEYCHIP=-12,
  ERR_NO_SERVER=-13, ERR_AUTH_READY=-14, ERR_NO_COMMAND=-15, ERR_SYS=-16, ERR_PRECONDITION=-17`。

### ツール参照: `util/dongleDecrypt.c`

amDongle を使った実コードの最小例。初期化順が分かる:
`amDongleInit → amDongleSetupKeychip(ループ) → amDongleSetAuthConfig("toolmode")
→ amDongleBillingGetKeychipId → amDongleGetGameId/SystemFlag/ModelType/Region/NetworkAddress`。
その後 `amDongleSetIv → amDongleDecrypt` を 16B 単位で回し AES-128-CBC 復号。
**`"toolmode"` という authConfig 文字列**が存在する点に注意（開発/ツール用パス）。

---

## 5. KCF（keychip 設定ファイル）と AM_APPBOOT 構造体

keychip の「中身」。`micekeychip` は KCF を読んで上記応答を生成する。

`lib/mice/kcf.h`:
```c
#pragma pack(push,1)
typedef struct AM_KCF {
    AM_APPBOOT m_Header;    // 下記
    BYTE m_AppData[216];
    BYTE m_Seed[16];        // appboot.seed
    BYTE m_Key[16];         // AES-128 鍵
    BYTE m_Iv[16];          // AES-128 IV
    BYTE Unk[128];
} AM_KCF;
```

`segastructs.h` の `AM_APPBOOT`（28B, packed）:
```c
typedef struct AM_APPBOOT {
    uint32_t m_Crc;
    uint32_t m_Format;
    char     m_GameId[4];   // 例 "SDEY" など
    uint8_t  m_Region;      // ← region 応答の元
    uint8_t  m_ModelType;
    uint8_t  m_SystemFlag;  // bit0=develop
    uint8_t  Rsv0f;
    char     m_PlatformId[3];
    uint8_t  m_DvdFlag;
    uint32_t m_NetworkAddr;
} AM_APPBOOT;
```
- KCF 探索パス（`micekeychip/mxk.c`）: `S:\config.kcf` → `C:\system\device\config.kcf`。
- nrs の appboot データを Ghidra/メモリから引いて、この構造体に当てれば各 PCP 応答値が逆算できる。

---

## 6. 暗号（keychip crypto）

- **データ暗号**: AES-128-CBC、鍵=KCF `m_Key`、IV=KCF `m_Iv`。
  `decrypt` は CBC 連鎖を継続（直前の暗号文ブロックを次の IV に）。`setiv` で IV を初期値へ戻す。
  実装: `micekeychip/callbacks/crypto.c`（OpenSSL EVP）、低レベル版 `lib/mxk/mxkCrypt.*`。
- **DS チャレンジ（1-Wire SHA / DS2460・DS28CN01）**: micekeychip は **未実装**（`code=54`）。
  実物理層は `dll/devices/smb_ds2460.c` / `smb_ds28cn01.c` / `devices/_ds_sha.c` に SHA-1 챌レンジ実装あり。
- **SSD proof / 署名検証 / RSA**: `mxkCrypt.h` に `mxkCryptRsaSignVerify` 等のシグネチャのみ。
  billing 署名鍵 `system/billing.pub`、ルート CA `system/ca.crt` がリポジトリ同梱（実バイナリ）。
- 低レベル keychip コマンド番号（`lib/mxk/mxkDefs.h`、サーバ↔物理チップ間）:
  ```
  0 SetKeyS 1 SetKeyR 2 SetIV 3 Decrypt 4 Encrypt 5 GetAppBootInfo
  6/7 Eeprom W/R  8/9 Nvram W/R  10 AddPlayCount  11 FlashRead 12 FlashErase 14 FlashWrite
  20 GetVersion 21/22 Set/GetMainId 23/24 Set/GetKeyId 25 GetPlayCounter
  ```

---

## 7. デフォルト設定値（`micekeychip/config.def`。そのまま使える正準値）

```
billing.keyid    = "A69E-01A8888"        # keychip ID 形式 XXXX-XXXXXXX
billing.playlimit= 0x00001400            # 上限
billing.nearfull = 0x00066048            # 課金報告閾値
billing.pubkey   = C:\system\device\billing.pub
billing.cacert   = C:\system\device\ca.crt
crypto.table     = C:\system\device\SDEY_Table.dat   # DS テーブル(*_Table.dat)
pcp.control_port = 40106 / pcp.binary_port = 40107 / bind_global=false
```

keychip ID → serial id 変換（`lib/am/amSerialId.c`）:
`XXXX-XXXXXXX`(17桁) から `-` を除いた 4+7=11 桁。検証規則は
`[0-3]=英数大文字(I,O 除外), [4]='-', [5-11]=数字`。

---

## 8. バイナリパッチ手法（nrs-util の patchCode に直輸入できる）

`src/patches/*.patch` は **`*<VA>: <before> > <after> # 注釈`** 形式の単純メモリ書換。
中身はほぼ **am ライブラリの `*DebugLevel` グローバルを 0→1 にしてログ全開にする**もの。
nrs.exe にも同名グローバルがあるはずで、**Ghidra で `amDongleDebugLevel` 等を探して
Frida patchCode で 1 を書けば、nrs 自身の詳細ログが出る**（＝フック前の最有力な観測手段）。

判明しているデバッグレベル・グローバル名（他バイナリの値だが**名前が手掛かり**）:
```
amDongleDebugLevel  amEepromDebugLevel  amSramDebugLevel   amBackupDebugLevel
amRtcDebugLevel     amHmDebugLevel      amNetworkDebugLevel amPlatformDebugLevel
amGcatcherDebugLevel amGdeliverDebugLevel amGfetcherDebugLevel amInstallDebugLevel
amDipswDebugLevel   amMasterDebugLevel  amiTimerDebugLevel
pcpDebugLevel / libpcpDebugLevel
```
nxAuth.patch には `c7460801000000`(= `mov dword[esi+8],1`)で**マネージャのデバッグレベルを
コード書換で立てる**例もある。`mxgfetcher.patch` は `LOG_EN_AMSRAM` を 1 にするだけ＝
**gfetcher は薄く、実体は AMSRAM ログ**という nrs-util の `boot/mxgfetcher/getstatus.js` の裏取りになる。

> 注: patch の VA は **micetools が解析した別バイナリ**のもの。**nrs にそのまま使うな**。
> 使うのは「どのグローバルを立てるか」という**知識**だけ。アドレスは必ず Ghidra MCP で nrs から取り直す。

---

## 9. エミュレーション層（スタンドアロン化の参考）

`micetools` 本体は nrs を物理ハードなしで起動させる DLL フック群。`docs/standalone_launcher.md` の補強になる。

- **`dll/hooks/`**（`hooks/README.md`）:
  - `setupapi.c` … 偽デバイス注入（amPlatform/amEeprom が SetupAPI で探すデバイスを捏造）
  - `files.c` … `\\.\driver` 系ファイルと各種パスを相対パスへリダイレクト
  - `network.c` … outbound TCP ログ＋ DNS リダイレクト
  - `registry.c` / `system.c` / `time.c`(時刻系 NOP) / `com.c`(COM1=カメラ,2=NFC,3=タッチ,5-8=LED)
  - `drive/` … HDD/IRB(SEGA 独自ディスク構造)エミュ、`processes.c`(子プロセスへ再注入, 既定無効)
- **`miceboot/`** … mxstartup/mxprestartup/mxmaster 等の OS ブート段エミュ。
- **`system_dummy/`** … Madoka システムサービス（keychip/master/network/storage/installer/gdeliver）の最小ダミー。
  「最小起動用」で実機代替ではない（`mice*` 版が本実装）。
- **`dll/drivers/`** … mxjvs/mxsmbus/mxsram/mxsuperio/mxparallel/mxhwreset の SEGA ドライバ層エミュ。
- **`util/micedump/`** … cmos/dmi/eeprom/sram/superio/platform と keychip(n2/pic/mxkeychip) の**ダンプツール**。
  実機 keychip から KCF 相当を吸う際の手順の参考。

---

## 10. ディレクトリ早見表

```
src/micetools/
  lib/am/        SEGA am ライブラリ再実装（amDongle/amEeprom/amBackup/amSram/amCmos/amDipsw/
                 amSerialId/amInstall/amPlatform/amOemstring …）← nrs と同名・最重要
  lib/mxk/       keychip サーバ↔物理チップ 低レベル(mxkCrypt/mxkN2/mxkDs/mxkPacket/mxkTransport/mxkSmbus)
  lib/libpcp/    PCP プロトコル実装（pcpa=クライアント/ pcp=共通）
  lib/mice/      ローダ基盤（kcf/blowfish/des/dmi/patch/ipc/serial/solitaire/spad/da/exe）
  lib/ami/       am 内部(amiCrc/amiMd5/amiTimer/amiDebug)
  lib/nbgi/      バンナム系(bnaccardall)
  micekeychip/   ★ keychip エミュ(PCP サーバ)。callbacks/ が応答の正準
  micemaster/    mxmaster エミュ（アプリランチャ/イベントログ）
  micepatch/     パッチ適用ユーティリティ
  miceboot/      ブート段エミュ
  dll/           ゲームプロセス内フック DLL（hooks/ devices/ drivers/ gui/）
  launcher/      mice ローダ exe（locate/spawn）
  system_dummy/  各システムサービスの最小ダミー
  util/          dongleDecrypt / micedump / micereset / iatrepair / exio_test …
  segastructs.h  AM_APPBOOT 等 SEGA 構造体
  sysconf.h / amBackupStructs.h / maiBackupStructs.h
src/patches/     *.patch（VA 直書換、DebugLevel 立てが主）+ patches.index
src/system/      billing.pub / ca.crt（実バイナリ同梱）
```

---

## 11. ローカル取得・更新

ソースは `C:\src\micetools\` に clone 済（想定）。無い/古い場合のみ:
```powershell
git clone --depth 1 https://gitea.tendokyu.moe/Bottersnike/micetools.git C:\src\micetools
# WebFetch/ブラウザは 403。clone のみ。
```
**本資料に無い／曖昧な詳細は `C:\src\micetools\` の該当 `.c`/`.h` を直読する**のが正で速い。
深掘り候補: `lib/mxk/mxkN2.c`・`mxkDs.c`（物理 keychip チャレンジ）、`lib/libpcp/pcpa.c`（PCP の正確な
ワイヤフォーマット）、`micekeychip/callbacks/*`（PCP 応答の正準）、`dll/hooks/drive/*`（HDD/IRB）。
