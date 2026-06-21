# boot/ コーディング規約（AI が新モジュールを規約準拠で生成するための拠り所）

目的: AI が grep なしで場所を引け、1 ディレクトリ閉で作業でき、トークンを最小化できる構造を保つ。

## 0. 書き方の標準（helper / データ表。token 最小・AI 編集容易）
- **単純な固定バイト patch**（無条件・固定値・`Memory.patchCode` だけ）は **`boot/patches.json`** に 1 行追加で表現する。
  `{ "va":"0xSTATIC", "bytes":<spec>, "subsys":"...", "ssot":"<subsys>/FACTS.md", "note":"..." }`。
  `bytes` は `"RET0"`(xor eax,eax;ret) / `"RET1"`(mov eax,1;ret) / `{"retImm":n}` / `{"retN":n}` / `"31 C0 C3"`(hex)。
  → ファイル新規作成も IIFE も不要。`lib/patch_table.js` が `lib/base.js` の `patch()` で適用する。
  **入れない**もの: 条件分岐つき・実行時に値を計算する patch・同一番地を hook もする衝突番地（順序が挙動になる）→ これらは `.js` のまま。
- **hook/timer を持つ複雑系**は従来どおり `.js` モジュール。base.js の helper を使う:
  `patch(staticVA, bytes, note)` / `hook(staticVA, {onEnter,onLeave}, note)` / `watch(intervalMs, fn, note)`。
  生 `Memory.patchCode`/`Interceptor.attach`/`setInterval` を直書きせず helper 経由に統一（boilerplate 削減＋不変ハーネスが全効果を捕捉できる）。
- **`<subsys>/diag.js`** = log-only(`monitor`) 専用の命名。起動修正時に AI が「読まなくてよい」と即判別できる。
- 根本原因 prose は **FACTS.md** が単一ソース（`.js` には 5 行ヘッダ＋呼出のみ。複雑系のみ簡潔な inline 可）。

## 1. 配置: ディレクトリ = RingEdge 実行ファイル/サブシステム
- 新しい patch/hook は、それが触る**実機コンポーネント**のディレクトリに置く（`mxkeychip/` `mxsegaboot/`
  `mxnetwork/` `mxgfetcher/` `amjvs/` `amdongle/` `amplatform/` `ambilling/` `amrtc/` `mxdrivers/`
  `mxstorage/` `devices/` `app/`）。対応表は `README.md`。
- 該当が無い実機サブシステムなら新ディレクトリを作る（実機の SEGA 名＝`mx*.exe`/`am*` を使う）。
- 単純固定バイト patch は §0 のとおり `patches.json` 行（ファイル配置不要）。

## 2. 命名: 名詞のみ、動詞禁止
- ディレクトリ = 実機コンポーネント名（`amjvs`）。ファイル = 機能名詞（`state.js`
  `region.js` `diag.js` `recv.js` `setup.js`）。
- `hook/patch/bypass/emulate/satisfy/inject` 等の**動詞をファイル名に使わない**（役割は dir＋ヘッダが表す）。

## 3. 1 ファイル = 単一 persistence
- patchCode/data-write だけのファイル → `persistent`。Interceptor/timer を含むファイル → `runtime`。
  混在させない（混在したら persistent な patchCode/data-write と runtime な Interceptor/timer を別ファイルに分割）。
- 番地は **static_VA** を `va(0xSTATIC)`（`lib/base.js`）で参照する。生 `nrsBase.add(...)` は禁止
  （checker が落とす）。runtime addr をログするときは `rtToVa(ptr)` で static_VA に戻す。

## 4. 5 行ヘッダ（全モジュール必須・機械可読）
```javascript
// subsys:      amjvs
// persistence: persistent   // persistent | runtime | monitor | served | na
// va:          0x67AFA0, 0x987590, 0x9883D3   // static_VA（Ghidra の番地そのもの）
// ssot:        ./FACTS.md
// role:        1 行で何をするか
```
- `va` は**そのファイルが実際に触る** static_VA（`MANIFEST.json` の `va[]` と一致させる）。
- `ssot` は事実の所在（同階層 `FACTS.md`）。

## 5. MANIFEST.json が構成の単一ソース
- モジュールの追加/削除/分割/persistence 変更は **`MANIFEST.json` の同コミット更新が必須**。
  `load_order` がロード順（`lib/base.js` 先頭固定）。
- ⚠️ **ブートはロード順に敏感**。`load_order` は**元の数値ファイル順(00..32)に忠実**に保つ
  （サブシステム別に並べ替えると keychip 前で停止＝白画面。`../BUGS.md` 参照）。追加/分割時も
  元の相対順序を崩さない。順序を「見やすさ」で変えてはならない。
- `network_role`: `local` か `serve`。将来ネットワーク対応で実サーバ応答に置き換える層は `serve`。

## 6. patchCode の作法（FACTS の横断ルール）
- `writeByteArray([...])` で書く（`code[i]=v` は QuickJS で無効）。書込後 `ptr.add(i).readU8()` で検証。
- 同一番地に `Interceptor.replace` と `patchCode` を併用しない（detach 時に replace が原本復元）。
- 詳細・アンチパターンは `../BUGS.md`、横断定数は `ARCH.md`。

## 7. 検証
- `python tools/hygiene/check_doc_sync.py` … MANIFEST↔モジュール↔FACTS の整合（va[] 実在・base 先頭・
  生 nrsBase.add 禁止・known_names が static_VA・persistence 整合）。pre-commit で自動実行。
