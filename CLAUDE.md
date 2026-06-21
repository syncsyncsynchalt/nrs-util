# nrs-util Claude 操作ガイド（ルーター）

nrs.exe (NRS, x86-32, SEGA RingEdge) を Frida でパッチ・フックして
スタンドアロン起動させる RE リポジトリ。**このファイルは索引。事実は単一ソースに置く。**

構成は2分: **`boot/`** = 成果物（nrs.exe を起動させる frida モジュール + keychip サーバ。RingEdge
サブシステム別。構成は `boot/MANIFEST.json`）／ **`tools/`** = 解析・開発ツールのみ。

## 鉄則（最優先・毎作業）

1. **ドキュメントは参考。正は実装。** docs/*.md・FACTS は要約で陳腐化しうる。値・フォーマット・
   シーケンス・アドレスは使う前に必ず**実体で裏取り**する。実体の所在:
   - **nrs.exe** → Ghidra MCP（`mcp__ghidra__*`、static_VA）。手計算・推測禁止。
   - **micetools**（RingEdge `am*`/PCP/keychip の C クリーンルーム実装＝最も低レイヤの正） →
     ローカル `C:\src\micetools\` を**直読**。`docs/micetools.md` はその要約。
   - **TeknoParrot**（BBS 設定値・JVS・起動シーケンスの正） → ローカル `C:\src\TPBootstrapper\`。
     ただし `TeknoParrot.dll` は VMProtect で静的不可 → **実行時 API フック観測**で裏取り
     （`tools/runtime/frida_diag/*.js` + `tools/runtime/*.py`）。`docs/teknoparrot.md` はその要約。
   - **RingEdge 純正システムイメージ**（v63.01.10/RINGEDGE2。`mxkeychip.exe`=keychip デーモンの実装の正、
     `mxsegaboot.exe`=ブート、ringmaster 鍵、ブート手順） → ローカル `C:\src\ringedge_system_63.01.10\`。
     `mxkeychip.exe` は**非パック＝Ghidra 静的解析可**（CrackProof=Htsysm は runtime kernel ドライバで on-disk PE は素）。
     `docs/ringedge_system.md` はその要約。
2. **segatools は参照しない**（`docs/` 化もしない）。Nu/ALLS 世代（amdaemon, x64）で RingEdge
   （x86-32, `am*`+PCP keychip）とは別物。混同は誤実装を招く（ユーザー決定）。
3. 値・プロトコルは TeknoParrot と micetools の**両方**を正として参照し、推測で決めない。

| 知りたいこと | 見る場所 |
|---|---|
| 横断定数（バイナリ base / static_VA・va() 規約 / PCP ポート / ワイヤ形式 / 静的lib） | `boot/ARCH.md` |
| サブシステム別の事実（アドレス/構造体） | `boot/<subsys>/FACTS.md`（索引は `FACTS.md`） |
| バグ・根本原因・アンチパターン（live: OPEN/RISK/ANTI-PATTERN） | `BUGS.md`（解決済み FIXED の履歴は `git log`） |
| 現在地・次の一手・起動コマンド | `STATUS.md` |
| 関数の逆コンパイル C・xref を調べる | Ghidra MCP（下記） |
| ブートシム本体（1 サブシステム=1 ディレクトリ） | `boot/<subsys>/<file>.js`（構成 `boot/MANIFEST.json`、規約 `boot/CONVENTIONS.md`） |
| ブートシムの全体像・起動コマンド | `boot/README.md` |
| keychip / PCPA サーバ | `boot/mxkeychip/server/pcpa_server.py`（応答は本体に inline 実装） |
| 独自ランチャー設計（北極星・ロードマップ） | `docs/architecture.md` / `docs/standalone_launcher.md` |
| TeknoParrot 設定値/JVS/起動の要約（正は `C:\src\TPBootstrapper\`） | `docs/teknoparrot.md` |
| keychip/amDongle/PCP/KCF の要約（正は `C:\src\micetools\` 直読） | `docs/micetools.md` |
| RingEdge 純正システムバイナリ（mxkeychip/mxsegaboot 等）・ブート手順・ringmaster鍵の要約（正は `C:\src\ringedge_system_63.01.10\` 実バイナリ） | `docs/ringedge_system.md` |
| RingEdge セキュリティ/PCP/DS28CN01/billing/ALL.Net の散文解説 | `docs/bsnk_ringedge.md`（micetools 作者の裏取り。`/nu_alls/` keychip は非該当） |
| SBVA(DVR-5001) ISO/SSD 抽出の背景（TrueCrypt 復号。正は `tools/iso/` の実出力） | `docs/iso_extraction.md` |
| 解析ツール一覧 | `tools/README.md` |

**横断的事実の正本（散在ビューは引用・編集はここを直す＝drift 防止）**:
- **起動シーケンス**（SYSTEM STARTUP `FUN_0089a010` の state→check→satisfy）＝ `boot/mxsegaboot/FACTS.md`。
  他 FACTS は自 subsystem の slice のみ持ち、全体像はそこを引用する。
- **エラー→fix 対応**（どの patch/module が満たすか）＝ 各モジュールヘッダの `// va:` ＋ `patch()` note。
  静的バイトパッチは**所属サブシステムのモジュール**に `patch()` で置く（各 note に errNo。中央テーブルなし、旧 patches.json/static_patches.js は廃止）。
  一覧監査は `python tools/static/patch_audit.py`（起動不要のオフライン横断走査）。
  STATUS/BUGS/各 FACTS の error 表は読み用ビュー。**impl 列の正はこの2つ**（過去ここが drift して stale 化した）。
- **トークン規律（AI向け）**: `docs/*.md`（計~1700行）は外部ソースの**要約で正ではない**。per-task で全読せず、
  値/フォーマット/シーケンスが要るときだけ各行「正は」の実ソースを直読する。重複表を見たら上記 SSOT を信じる。

## バイナリ定数

- Path `C:\src\bbs\nrs.exe`、x86-32、ImageBase `0x400000`、ASLR 有（nrs base は実行毎に変動）
- **番地は全て static_VA（Ghidra の番地そのもの、ImageBase 0x400000）で扱う。一方言のみ。**
  人間/ツール/コードが触る番地は全部 static_VA。RVA・runtime_VA は **`boot/lib/base.js` の `va()` helper の
  内部だけ**に存在し、境界には出さない。手計算・変換は不要（する場面が無い設計）。
- 各サーフェスの dialect（全て static_VA）:
  - **Ghidra MCP** `mcp__ghidra__*` … 引数も出力も static_VA（不変・基準）
  - **`tools/static/disasm.py`** … 引数は static_VA のみ（旧 RVA モード/自動判定は撤去）。`-b` は
    `va(0xSTATIC)`+バイト列+patch-site 相互参照（各モジュールヘッダ `// va:` 由来）を出力。`--json` で機械可読。
  - **boot シム** … `va(0xSTATIC)` で番地参照（`nrsBase.add(rva)` は checker が禁止）。番地はモジュール先頭
    ヘッダ `// va:` 行で宣言（番地の唯一ソース。MANIFEST は va を持たない）。runtime addr の
    ログは `rtToVa(ptr)` で static_VA に逆換算。
  - **モジュールヘッダ `// va:`**、**`data/known_names.json`** キー、**FACTS/ARCH/BUGS** … static_VA
  - 唯一の変換式 `runtime = (static_VA − 0x400000) + nrsBase` は `va()` の中だけ（`base.js`）。

---

## 静的解析 = Ghidra MCP 一本（推測の前に必ず使う）

全関数の逆コンパイル・xref・リネームは **`mcp__ghidra__*`** で取得する。引数は static_VA。

| やること | ツール |
|---|---|
| 番地から逆コンパイル C | `mcp__ghidra__decompile_function_by_address` (static_VA) |
| 名前で関数検索 | `mcp__ghidra__search_functions_by_name` |
| 逆コンパイル C 全文検索（エラーコード・文字列・変数名） | `mcp__ghidra__search_decompiled` |
| 呼び出し元/先・データ参照 | `mcp__ghidra__get_xrefs_to` / `get_xrefs_from` / `get_function_xrefs` |
| 文字列・インポート・データ | `mcp__ghidra__list_strings` / `list_imports` / `list_data_items` |
| 永続リネーム | `rename_function_by_address` + `data/known_names.json` に追記（下記） |

- サーバ未起動で `mcp__ghidra__*` が connection refused のときは
  `powershell -File tools\ghidra_mcp\start_headless.ps1`（冪等・既起動なら no-op）。詳細 `docs/ghidra_mcp_setup.md`。
- `search_decompiled` は初回にサーバ側で全関数を逆コンパイルしキャッシュ構築（数分）。
  "cache building: N/total" が返ったら少し待って再試行。
- **名前の永続化**: analyzeHeadless はリネームを保存しない。恒久的な名前は
  `data/known_names.json`（static_VA→名）に追記する。起動スクリプトが次回起動時に Ghidra へ適用する。
- 手作業の生バイト読み（PowerShell `$exe[$off..]` 等）は禁止。ランタイムのレジスタ/BP 確認が要る時のみ
  x32dbg（`...\WinGet\Packages\x64dbg.x64dbg_*\release\x32\x32dbg.exe`）。それ以外は MCP と Frida で足りる。

---

## Frida パッチ・フック ルール

作業前: ①該当関数を MCP で逆コンパイル ②`get_xrefs_to` で影響範囲 ③`FACTS.md` でアドレス
④`BUGS.md` でアンチパターン ⑤**`docs/teknoparrot.md` と `docs/micetools.md` の両方で正準値・プロトコル・
構造体を確認**（値/フォーマット/シーケンスは推測せず両参照実装を正とする）、を確認してから設計する。

- **patchCode = 永続**（Frida detach 後も有効）。critical fix に使う。`writeByteArray([...])` で書く
  （`code[i]=v` は QuickJS では書き込まれない）。書込後は `ptr.add(i).readU8()` で必ず検証。
- **Interceptor.attach = detach で消える**。ロギング/一時上書き専用。
- **同一番地に Interceptor.replace と patchCode を併用しない**（detach 時に replace が原本復元し patchCode を上書き）。
- 呼出規約 x86-32: stdcall（callee が `RET N` でスタック解放、N はC末尾の return 型/引数数で確認）、
  thiscall は ECX=this。`onEnter` の `args[i]` はスタック引数。
- アンチパターン全量は `BUGS.md` の `[ANTI-PATTERN]` 群。

**ドキュメント同期（必須）**: モジュールの追加・削除・分割・機構変更（Interceptor↔patchCode）は、
**同一コミットで `boot/MANIFEST.json`（subsys/persistence/network_role）・モジュール先頭ヘッダ（`// va:` 等）・
該当 `boot/<subsys>/FACTS.md` を更新**する。MANIFEST が boot 構成（構成と順序）の単一ソース、番地は各ヘッダが正。
STATUS だけ直して MANIFEST/ヘッダ/FACTS を放置すると陳腐化する（過去に commit 56cb7b2/7f69740/38ffd45 で発生）。
- 整合チェッカ: `python tools/hygiene/check_doc_sync.py`（各モジュールヘッダ `// va:`（static_VA）が当該モジュール本体に
  実在するか、base.js が先頭か、**生 `nrsBase.add(`/`nb.add(` が無いか（dialect guard）**、known_names キーが
  static_VA か、persistence と実機構が矛盾しないかを機械検証。INFO で runtime=スタンドアロン残課題、
  serve=将来ネットワーク層も併記）。
- 自動化: `git config core.hooksPath tools/git_hooks` を一度設定すると、`boot/**`(js/json)・FACTS/STATUS/BUGS.md
  を含むコミットで pre-commit が同チェッカを実行し、不整合があればコミットを止める（緊急時 `--no-verify`）。
- モジュール先頭の5行ヘッダ（subsys/persistence/va/ssot/role）を必ず付ける（規約 `boot/CONVENTIONS.md`）。

patchCode テンプレ（stdcall 引数なし → return 0。番地は static_VA を `va()` に渡す）:
```javascript
Memory.patchCode(va(0xSSSSSS), 3, code => {           // 0xSSSSSS = Ghidra static_VA
    code.writeByteArray([0x31,0xC0, 0xC3]);  // xor eax,eax; ret  （ret N なら 0xC2,N,0x00）
});
```
バイト列と `va()` 呼び出しは `python tools/static/disasm.py 0xSSSSSS -b N` がそのまま出力する。

---

## 新しい関数名が判明したとき

`data/known_names.json` の `functions` に **static_VA キー**（Ghidra の番地そのもの）で追記 → MCP 再起動で
反映（オフライン再構築は不要）。`ApplyKnownNames.java` がキーを絶対 VA として適用する。
