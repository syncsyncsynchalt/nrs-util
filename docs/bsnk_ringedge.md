# bsnk RingEdge ドキュメント — SEGA RingEdge 解析（散文解説）

micetools の作者 **bsnk (Bottersnike)** が公開する SEGA Ring 系解析サイトの **RingEdge セクション**。
`docs/micetools.md`（C 実装）と**同一作者**の散文版で、コードでは読み取りづらい
「**なぜ・どういう順で・どんな値で**」を文章で補完する。**micetools のコードと往復して読む**のが正しい使い方。

- 出典: `https://sega.bsnk.me/ringedge/`（および keychip 共通部 `…/nu_alls/`、ALL.Net 部 `…/allnet/`）
- WebFetch 可（micetools 本体の gitea は 403 だがこのサイトは閲覧可）。研究用。
- 位置づけ: **値・プロトコル・構造体の正準は引き続き micetools(`docs/micetools.md`)+TeknoParrot(`docs/teknoparrot.md`)**。
  本サイトは「解説・裏取り」。一致しない箇所は両参照実装を優先する（[[feedback-reference-teknoparrot]]）。

---

## ⚠️ 世代の境界 — 混同禁止（segatools と同じ罠）

RingEdge の keychip は **DS28CN01(I2C SHA-1 チップ)＋DS2460(ExIO)＋PIC＋N2** 機構。
一方、サイトの **keychip『Introduction』(`/nu_alls/keychip/introduction/`) は Nu/ALLS 専用**で、
**USB 型 keychip(A7=A7001AG JavaCard / N2=L3.1、`LPC11U14F`＋`AT25DF041A`、`fdd.sys`/`hdd.sys`/`ssd.sys`)**
という**全く別物**。nrs.exe(BBS) には適用しない。

| | RingEdge（nrs.exe = 本プロジェクト対象） | Nu/ALLS（keychip Introduction が説明する世代） |
|---|---|---|
| keychip 物理 | DS28CN01(keychip)＋DS2460(ExIO)＋PIC＋N2 | USB keychip A7/N2(JavaCard) |
| 接続 | I2C | USB シリアル→I2C 変換(LPC11U14F) |
| ドライバ | mxkeychip.exe 経由 | fdd.sys→hdd.sys/ssd.sys |
| 本サイトの該当頁 | `/ringedge/software/security/*`, `/ringedge/software/pcp/*` | `/nu_alls/keychip/*` |

→ **`/ringedge/` 配下のみ RingEdge。`/nu_alls/` 配下の keychip は参照しない**（segatools 不参照と同趣旨 [[feedback-do-not-reference-segatools]]）。
ただし ALL.Net(`/allnet/`)はネットワークプロトコルなので世代共通で参照可。

---

## 1. PCP プロトコル（`/ringedge/software/pcp/`）

mxkeychip 等の Ring 系サービス間 IPC。micetools の PCP 実装と対応（→ `docs/micetools.md`）。

- **テキスト + CRLF 行終端**。1 ペイロード **最大 256 バイト（CRLF 含む）/ 最大 64 個の key=value**。
- ペイロードは `key=value` を `&` 連結。`#` 以降はコメント、空白許容。
- 会話シーケンス:
  1. サーバ準備完了で **`>`** 1 バイト送信
  2. consumer が CRLF 終端パケット送信
  3. サーバが CRLF 終端パケットで同期応答
  4. （任意）データ転送ありなら consumer が指定ポートへ接続し指定バイト数を受信
  5. consumer が **`$`** で受領確認
  6. 不正コマンド/パケットには **`?`**
- 例: `keychip.version=?` / `keychip.billing.cacertification=?` を投げて応答を得る。

### libpcp API（`/ringedge/software/pcp/libpcp/`）
nrs がリンクする `pcpa*` 群の挙動。Frida のフック当て先・引数解釈に直結。

- `pcpaInitStream()` / `pcpaClose()` — ストリーム確保・終了
- `pcpaSetCallbackFunc(keyword, callback)` — 先頭 keyword 一致でコールバック起動
- `pcpaOpenServerWithBinary(port, open_mode, binary_port)` — **open_mode=0→`0.0.0.0`、=1→`127.0.0.1`** に bind
- `pcpaServer(timeout_ms)` — 1 tick 処理
- 読み取り: `pcpaGetCommand(key)`（無ければ NULL）、`pcpaGetKeyword(index)`
- 応答: `pcpaSetSendPacket()`→`pcpaAddSendPacket()`、バイナリは `pcpaSetBinaryMode()`＋送受信バッファ設定＋前後コールバック

> nrs-util の `pcpaOpenServerWithBinary` の bind 確認(`project_pcpa_keychip`)と整合。
> open_mode と bind 先の対応がここで確定する。

---

## 2. keychip 物理セキュリティ — DS28CN01 / DS2460（`/ringedge/software/security/dssha/`）

「secure SHA-1 coprocessor + EEPROM」を 2 個使い keychip 真正性を検証。
**DS2460=ExIO ボード上、DS28CN01=keychip 上**。

- DS28CN01 はゲーム固有の **128 バイト EEPROM**（対応する `SXXX_Table.dat` と一致）を保持。
- boot 時 `mxkeychip.exe` が乱数チャレンジで **non-anonymous ハッシュ**を要求 →
  DS2460 が EEPROM ページ＋シリアル＋チャレンジから構築したペイロードを受け、**MAC 一致**で PIC/N2 認証へ進む。
- **開発用 keychip はハードコードされたチャレンジ/応答リスト**を使う。

### Dallas SHA-1 変種（標準 SHA-1 との差）
1. 64 バイト 1 チャンクのみ処理（通常のメッセージパディングをしない）
2. 最後のチャンクハッシュ加算を省略
3. リトルエンディアン・変数逆順で返す（＝バイト単位の反転）

### DS28CN01 メモリマップ
| Addr | R/W | 用途 |
|---|---|---|
| 00h–7Fh | R/W | User EEPROM（4 ページ×32B） |
| A0h–A7h | R | Unique serial（先頭=70h 固定、末尾=CRC-8） |
| A8h | W/R | 通信モード / ステータスレジスタ |
| A9h | W | Compute MAC コマンド |
| B0h | R | 出力 MAC（20B） |

- **Compute MAC**: A9h へ command byte＋7B チャレンジを書く。command の下位 2bit=EEPROM ページ選択、
  bit4=シリアル含有可否（**0xD0=シリアル付 / 0xE0=anonymous**）。
- MAC 入力 55B = 先頭 4B secret ＋ 32B EEPROM ページ ＋ チャレンジ先頭 4B ＋ page id ＋
  7B serial（anonymous は 7×FFh）＋ 末尾 4B secret ＋ チャレンジ末尾 3B → 64B に SHA-1 標準パディング。

### DS2460 メモリマップ
| Addr | R/W | 用途 |
|---|---|---|
| 00h–3Fh | R/W | 入力バッファ |
| 40h–53h | R | MAC 出力 |
| 54h–5Bh | W | S-Secret |
| 5Ch | W | コマンド |
| 60h–77h | W | E-Secret 1–3 |
| 80h–EFh | R/W | EEPROM |
| F0h–F7h | R | Unique serial |

- コマンド `01SSxxxx`=secret SS へデータ転送、`10GSSxDx`=secret SS で SHA-1 計算（G=汎用/Dallas、D=MAC バッファ出力）。
- DS28CN01 は 8B 内部 secret、DS2460 は E-Secret 2（8B secret＋9B パディングを内部乱数で埋め計算→送信値と比較）で認証。

---

## 3. システムセキュリティ全体フロー（`/ringedge/software/security/security/`）

boot で下層から順に適用される多層防御。**nrs-util の keychip/region/Error 系バイパスに直結する金脈**。

1. **SSD ATA パスワード** — 40B モデル番号から BIOS 関数で 32B パスワード導出。
   電源維持のまま SATA データケーブルをホットプラグすると **SEC6 モード（有効だが解錠済）**を保持して回避可能。
2. **OS 認証** — `AppUser`=`segahard`（既定オートログイン）、`SystemUser`=`<6/=U=#tpe!$*3!5`。
   `mxprestartup` にデバッガを当てると別導出 `Miflac=Ifme9Jfp0`。
3. **システムバイナリ暗号化** — TrueCrypt パーティション `C:\System\Execute\System`。
   パスワード `segahardpassword`、キーファイル=ADS `C:\System\Execute\DLL:SystemKeyFile`。
4. **keychip 通信** — region 検証・ネットワーク設定供給・ゲーム鍵導出の暗号化・チャレンジ応答認証・
   **Aime billing クレジット上限**・trace ログ。**mxkeychip.exe 以外は keychip と直接通信しない**。
   mxkeychip との通信は初回ハンドシェイクで合意した **AES** 暗号。**mxkeychip.exe を自作実装に差し替えれば回避可能**。
5. **ゲームデータ暗号化** — `original0`/`patch0`/`patch1` を TrueCrypt で O:/P: にマウント →
   `geminifs` で X: に統合。TrueCrypt キーファイル `keychip.appboot.seed` は keychip 上、ゲーム鍵で暗号化。
6. **ゲーム⇄keychip ハンドシェイク（AmLib）** — `amDongleSetAuthConfig()` で追加認証を有効化:
   - **DS28CN01 SHA1 チャレンジ**: 7B チャレンジ・4×20B 応答ページ、`[game ID]_Table.dat` 格納、固定置換表でスクランブル。
   - **SSD チャレンジ**: 16B チャレンジ・16B 応答、同様にスクランブル。
   - **開発モード**: ハードコードチャレンジ **`2CFECBC71CF1E4`** ＋既知の 4 応答。
   - 欠落エントリは modulo-100 カウンタで処理。**`code=54` を返すクエリは検証を完全バイパス**。

> **nrs-util 直結ポイント**: 4 の「mxkeychip 差し替えで AES 層回避」は micetools の keychip サーバ実装方針と一致。
> 6 の **`code=54` バイパス**と **dev チャレンジ `2CFECBC71CF1E4`** は keychip 認証バイパス
> (`boot/mxkeychip/setup.js` / 観測 `tools/runtime/frida_diag/keychip_setup_diag.js`) の有力手がかり。

---

## 4. ALL.Net ネットワーク（`/allnet/`）— 世代共通・参照可

ALL.Net = Amusement Linkage Live Network。4 サービス構成:
**Authentication=`naominet.jp`、Billing=`ib.naominet.jp`、AiMeDB=`aime.naominet.jp`、タイトルサーバ**。
店舗ルータは IPSEC トンネル(`vpn1jpn.sys-all.net`/`vpn2jpn.sys-all.net`)接続。

### 4.1 Billing（`/allnet/billing/`）
`boot/patches.json(0xA065C0)` の正準仕様。

- **単一 HTTPS エンドポイント `ib.naominet.jp:8443`**、**HTTP/1.1 + TLS 1.1** 必須。
- POST 先 `/request.php`（`/request/`・`/request` もリダイレクトなしで受理必須）。
- **HTTP プリアンブル（`HTTP/1.1` 行＋全ヘッダ）は単一ネットワークパケットに収まること**（重要）。
- **HTTPS 証明書は keychip が供給する CA 証明書で署名されていること**（信頼チェーンの起点が keychip）。
- bootleg 網は通常 **minime PKI** の RSA 鍵対を使用。
- 実装注意: 新しめの Python は openssl が TLS 1.1 を無効化済 → nginx 等の reverse proxy で TLS 終端を推奨。

### 4.2 Authentication: Cabinet Power On（`/allnet/auth/power-on/`）
- パス `/sys/servlet/PowerOn`。**リクエストは DFI エンコード必須**。
- 必須フィールド(format_ver 1): `game_id`(5)、`ver`(5)、`serial`(11)、`ip`(15)。任意: `firm_ver`/`boot_ver`/`encode`(既定 EUC-JP)/`format_ver`(既定 1.00)/`hops`。
- 応答: status(**1=成功、-1〜-3=エラー**)、`place_id`、ゲームサーバ `uri`/`host`、店名/ニックネーム、timestamp、setting フラグ、region(0–3)＋名称、country。
- 応答エンコードは Shift_JIS/EUC-JP/UTF-8。format_ver 3+ で `utc_time`(`yyyy-MM-dd'T'HH:mm:ss'Z'`)。

### 4.3 Download Instruction（`/allnet/auth/download-order/`）
- パス `/sys/servlet/DownloadOrder`。配信指示。
- 要求: `game_id`(4 桁)、`ver`、`serial`(keychip シリアル)、任意 `ip`/`encode`。
- 応答: `stat`（machine setting）、条件付き `serial`（同店マシン CSV）、`uri`（DL URL、画像は `|` プレフィクス）。
- **`stat` が 1 でなければ配信フィールドは省略** → **非 1 を返せば配信割当を抑止できる**（スタンドアロン化に有用）。

### 4.4 AiMeDB（`/allnet/aimedb/`）
カード認証 DB。`aime.naominet.jp`。アクセスコード（Amusement IC / Banapass / Classical AiMe）、
communication/common 仕様、FeliCa 変換、ログ送信(status/aimelog)、キャンペーン、拡張アカウント等。
BBS のカード周りに当たる際の仕様（`boot/devices/cardreader.js` の文脈）。

---

## 5. その他の頁（未精読・必要時に参照）

- `/ringedge/software/security/alphadvd/` — AlphaDVD(αDVD) 光学メディア保護
- `/ringedge/software/boot/` — ブートプロセス
- `/ringedge/software/drivers/` — ドライバ
- ハードウェア仕様: RingEdge **2** = Core i3-540 3.06GHz / Q57 / 2GB / 32GB SSD（※BBS は無印 RingEdge の可能性。版差注意）

---

## 関連
- `docs/micetools.md` — 同一作者の **C 実装**（このサイトの裏付け・正準値）
- `docs/teknoparrot.md` — 上位レイヤ参照
- `FACTS.md` / `BUGS.md` / `STATUS.md` — nrs 実アドレス・アンチパターン・現在地
- メモリ: [[reference-bsnk-ringedge]]、[[reference-micetools]]、[[feedback-reference-teknoparrot]]、[[feedback-do-not-reference-segatools]]
