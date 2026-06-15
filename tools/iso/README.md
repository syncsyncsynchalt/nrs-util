# tools/iso/ — SBVA (DVR-5001) ISO 抽出・検証ツール

SEGA RingEdge の TrueCrypt 暗号化 IS/ SSD からゲームファイルを取り出すための解析スクリプト。
背景・到達点・未解決点は [`../../docs/iso_extraction.md`](../../docs/iso_extraction.md) が正典。
ここは**実証済みの経路で使うスクリプトだけ**を置く（DVD 単体経路の行き止まり実験は削除済み。
findings は doc に記録済み）。

> 実行は Python フルパス: `%LOCALAPPDATA%\Programs\Python\Python313\python.exe`
> 依存: `pycryptodome`（`from Crypto.Cipher import AES`）。

## スクリプト

| ファイル | 役割 |
|---|---|
| `lrw.py` | TrueCrypt LRW モード実装（`gf_mul128` / `lrw_*`）。公式テストベクタで検証済みの**共有ライブラリ**。他スクリプトが import する。 |
| `decrypt_bootid.py` | Boot ID を keychip AES-128-CBC（per-sector IV リセット）で復号 → `bootid_plain.bin` を出力。`BTID`/`SBVA` 平文で keychip 暗号方式を実証。 |
| `tc_decrypt_volume.py` | **実証済みの抽出本体**。実機 SSD の TrueCrypt 4.3 AES-LRW ボリュームを丸ごと平文 NTFS イメージへ復号。`from lrw import gf_mul128` に依存。 |
| `scan_layout.py` | ISO のセクタ毎エントロピーをスキャンし暗号化領域（TrueCrypt ボリューム先頭）の境界を特定。 |
| `make_kcf.py` | micekeychip 用の SBVA KCF ファイル（`config.kcf`）を生成（AM_APPBOOT + Seed/Key/Iv + scramble）。 |

## データ成果物

| ファイル | 由来 |
|---|---|
| `bootid_plain.bin` | `decrypt_bootid.py` の出力（復号済み Boot ID） |
| `config.kcf` | `make_kcf.py` の出力（micekeychip 用 KCF） |

## 依存関係

`tc_decrypt_volume.py` は同ディレクトリの `lrw.py` を `sys.path.insert(dirname(__file__))` 経由で
import する。両者は**必ず同一ディレクトリに置く**こと。
