# RingEdge System Software v63.01.10 — SEGA 純正システムイメージ 要約

**正（source of truth）はローカルの実バイナリ `C:\src\ringedge_system_63.01.10\`。本資料はその要約。**
keychip/PCP・boot・billing・platform 設定の値/フォーマット/シーケンスを使う前に、必ず該当バイナリ・設定ファイルを
**直読**して裏取りする。これは SEGA RingEdge の **OS／システム層**（nrs.exe が載る土台）であり、micetools
（クリーンルーム再実装）と bsnk 散文が「正は `mxkeychip.exe`」と指す**その実バイナリそのもの**。

- ローカル: `C:\src\ringedge_system_63.01.10\`（376MB）。世代 = **RingEdge（x86-32, `mx*`+PCP keychip）**。
  Nu/ALLS（segatools）とは別物 — 混同禁止（CLAUDE.md 鉄則2）。
- 関連: `docs/micetools.md`（am*/keychip クリーンルーム実装）、`docs/bsnk_ringedge.md`（PCP/DS28CN01 散文）、
  `docs/teknoparrot.md`（上位レイヤ）、`../boot/keychip/FACTS.md`、`../boot/keychip/server/pcpa_server.py`。

---

## 0. バージョン・世代（実体で確定）

| 項目 | 値 | 出典（実体） |
|---|---|---|
| System version | **63.01.10** | `update/SystemVersion.txt` = `00630110` |
| Platform | **RINGEDGE2** | `update/common/setting/REG_PLATFORM.reg` → `HKLM\SOFTWARE\SEGA\RING\LIBRARY\VERSION="RINGEDGE2"` |
| アーキ | x86-32 | `mx*.exe` PE ヘッダ（MZ, 32-bit） |
| アンチタンパ | **CrackProof = `Htsysm` runtime kernel ドライバ**。on-disk PE は**非パック**（後述） | `update/CrackProof/HtsysmNT.{sys,reg}`、`update/CustomCommand.conf` で導入 |

---

## 1. ディレクトリ構成

```
C:\src\ringedge_system_63.01.10\
├─ system\                 ← SEGA システムスイート（mx*.exe）＝本リポジトリ直結。下表参照
└─ update\                 ← OS アップデートパッケージ（W:\ ドライブとして展開される想定）
   ├─ SystemVersion.txt    = 00630110
   ├─ OSupdate.conf / OSupdate2.conf  ← インストール／ブート手順スクリプト
   ├─ CustomCommand.conf   ← CrackProof(HtsysmNT) 導入
   ├─ mxosupdate.exe       ← アップデータ本体
   ├─ common\              ← 共通: System(→C:\System\Execute), System32, segadriver, oem*, setting
   ├─ ringedge1\           ← RINGEDGE1 機種固有ドライバ（graphics=NVIDIA, NIC, Sound, USB 等）
   ├─ ringedge2\           ← RINGEDGE2 機種固有
   └─ CrackProof\          ← HtsysmNT.sys + HtsysmNT.reg（アンチタンパ）
```

---

## 2. `system\` — SEGA システムスイート（本リポジトリ直結）

| バイナリ | サイズ | 役割 | nrs-util での対応 |
|---|---|---|---|
| **`mxkeychip.exe`** | 738KB | **keychip デーモン**。PCP keyword ディスパッチ、物理 keychip(N2/PIC/DS2460/DS28CN01) との AES 通信、`code=54` バイパス。**非パック＝Ghidra で静的解析可（§5）**。最優先解析対象 | `boot/keychip/server/pcpa_server.py` が偽装する相手の実装の正 |
| **`mxsegaboot.exe`** (+`_2052.dll`) | 1.35MB | システム側ブートシーケンス（ゲーム起動シェル） | `boot/startup/` が RE 中の SYSTEM STARTUP SM の上位レイヤ |
| `mxnetwork.exe` | 269KB | ALL.Net / NIC / ネットワーク設定 | `boot/amnet/`, `boot/allnet/connection.js` |
| `mxgfetcher.exe` | 432KB | ゲームデータ fetch（ALL.Net 配信） | `boot/amgfetcher/getstatus.js` |
| `mxgdeliver.exe` / `mxgcatcher.exe` | 187/160KB | 配信 deliver / catcher（mx-catcher = port 40113） | `boot/allnet/`, ARCH PCPA 40113 |
| `mxauthdisc.exe` | 101KB | ディスク/イメージ認証 | billing/auth |
| `mxmaster.exe` | 218KB | foreground プロセス管理（mxmaster = port 40100） | ARCH PCPA 40100 |
| `mxstorage.exe` | 175KB | ストレージ（TrueCrypt/geminifs マウント周辺） | ゲームデータ暗号化（bsnk §5） |
| `mxinstaller.exe` / `mxshellexecute.exe` | 148/63KB | インストーラ / シェル実行 | — |
| `d3dref9.dll` | 349KB | D3D9 リファレンスラスタライザ | `default/develop_regset.txt` |

平文の即利用可能データ:
- **`ringmaster_pub.pem`** — ringmaster RSA 公開鍵（§3）。
- `lockid.txt` = `4294967295`（0xFFFFFFFF）、`default_regset.txt` / `develop_regset.txt`（D3D デバッグレベル）。

---

## 3. `ringmaster_pub.pem` — ringmaster RSA 公開鍵（実値）

```
RSA 1024-bit, Exponent 65537 (0x10001)
Modulus (先頭): 00:c7:ff:2d:0b:16:e8:95:a2:79:d4:fb:b7:ca:2c:43:a1:7d:0a:22:b8:49:41:e9:...:35:76:04:67:ef
```

`docs/micetools.md` が言及する billing.pub / ca.crt（micetools 同梱の再実装側鍵）と**別物**。これは実機
ringmaster（ALL.Net 配信/billing 署名検証のルート）の公開鍵。署名検証バイパス（`docs/bsnk_ringedge.md` の
SSD proof / RSA、`boot/keychip/setup.js`）の裏取りに使う。**全文は実ファイルを直読**。

---

## 4. ブート／インストール手順（`update/OSupdate.conf`）

実機の OS セットアップ＝ブート前提を示すスクリプト（`W:\` = update ルート）。要点:
- SEGA システムファイル → `C:\System\Execute`（`common/System` + `ringedge1/System`）、`C:\Windows\System32`。
- **SEGA ドライバ（segadriver, INF 導入）**: `geminifs`, `Columba`, `kbfilter`, `mxhwreset`, `mxparallel`,
  `mxsuperio`, `mxcmos`, `mxusbdevice`, **`mxjvs`**, `mxsram`, `mxsmbus`。
  → keychip 物理層（SMBus/parallel）と JVS の実ドライバ名。`boot/amjvs/`・keychip 物理層の裏取りに対応。
- OEM: NVIDIA graphics, Realtek NIC/Sound, DirectX(Feb/Jun 2010), GenericUSB。
- `CustomCommand.conf`: CrackProof `HtsysmNT.sys` を System32 へ、`HtsysmNT.reg` を import（`Htsysm` サービス
  Start=2/Type=1=kernel）。→ **`mx*.exe` は CrackProof 前提で動く**。

---

## 5. 解析方針（mxkeychip.exe は非パック＝静的解析可）[S] 確定 2026-06-13

当初 CrackProof による静的不可を想定したが、**実測で否定**された（`tools/static/pe_analyze.py` + 文字列抽出）:
- `.text` entropy **6.68**（パック済みは ~7.8+）、標準セクション、**完全な import 表が可視**
  （WS2_32 = PCP TCP ソケット、SETUPAPI = keychip USB/SMBus 列挙、ADVAPI32 = EventLog、OpenSSL）、
  export `OPENSSL_Applink`、**5768 個の平文文字列**。pe_analyze の "MPRESS/yC packer @offset" は entropy/import が
  矛盾するため**誤検出**。
- 先の `strings` が 0 件だったのは **Git Bash に `strings` が無かっただけ**（パックではない）。
- **CrackProof(`Htsysm`) は runtime kernel ドライバ**（実行中プロセスの anti-debug/anti-tamper）であって、
  **on-disk の `mxkeychip.exe` は素の PE**。→ **そのまま別 Ghidra プロジェクトに取り込んで静的解析できる**
  （実行時アンパック不要）。

→ 解析経路は **(a) 静的 Ghidra 取り込みが第一選択**。実行時観測(b)は CrackProof 下でのデバッガアタッチが要る場合の
  補助。確認済みの PCP キー全集合・内部ハンドラ名・暗号方式は `boot/keychip/FACTS.md`（裏取り済み）。

判明した実装事実（`boot/keychip/FACTS.md` に反映済）:
- PCP ライブラリ `libpcp Ver.1.08 Build:Nov 26 2012`（nrs.exe クライアントと同一）。
- 暗号 OpenSSL **AES-256/192/128-CBC**（`encrypt`/`decrypt` データチャネル）、RSA。
- billing 署名: nrs `amDongleBillingGetSignaturePubKey`(0x96FE50)/`GetCaCertification`(0x96FF60) が
  PCP `keychip.billing.signaturepubkey`/`cacertification` を送り、**応答 = `ringmaster_pub.pem`**（§3）。
  attract 非ブロッカー（billing 専用、現行 pcpa_server 未対応）。
- 物理層: N2/SMBus(`mxkN2Cmd*`)、DS28CN01/1-Wire(`mxkDsKeychip*`)。

> **nrs-util 直結ポイント**: `mxkeychip.exe` は `pcpa_server.py` が偽装している相手の純正実装。
> PCP keyword の応答仕様・`code=54` バイパス・AES 鍵導出を **micetools と両方を正として**裏取りし、
> `pcpa_server` を実機準拠へ寄せられる（CLAUDE.md 鉄則3）。深部 RE が要るときは Ghidra で直接 mxkeychip.exe を開く。
