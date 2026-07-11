# tools/ghidra_mcp/：静的解析 MCP 基盤のレイアウト

nrs.exe の逆コンパイル/xref/全文検索を `mcp__ghidra__*` で提供する基盤。**正典は直下のファイル**で、
`src/` は上流 GhidraMCP の vendor スナップショット（jar をビルドするためだけに存在）。

## 直下（使う・保守する正典）

| file | 役割 |
|---|---|
| `bridge_mcp_ghidra.py` | **正典のブリッジ**。Claude ──`mcp__ghidra__*`──▶ これ ──HTTP:8080──▶ Ghidra。`search_decompiled` 等の自前拡張を含む（上流 fork）。MCP が起動するのはこれ。 |
| `ghidra_scripts/GhidraMCPHeadless.java` | headless で HTTP サーバを立てるエントリ（`build_headless.py` の生成物・手編集しない）。graceful shutdown で終了時に DB 保存 |
| `build_headless.py` | `src/` の GUI 用 `GhidraMCPPlugin.java` を headless 版 `GhidraMCPHeadless.java` に**コード生成**（jar ビルドではない） |
| `export_symbols.py` | 稼働中サーバから named 関数を `data/re_symbols.json` へ**一方向ダンプ**（DR バックアップ・手編集禁止） |
| `start_headless.ps1` | サーバ起動/停止（冪等・GUI 不要・readiness まで待って exit 0）。`-Stop` は graceful（DB 保存）。connection refused 時に叩く |

## `src/`（vendor の上流スナップショット。触らない）

[lauriewired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) の素のコピー。**プラグイン jar の
ビルド元としてのみ**保持する。ビルド成果物（`target/`・`lib/*.jar`）は `.gitignore` 済み。

- ここの Python/JS を runtime で使わない。ランタイムのブリッジは上記**直下の `bridge_mcp_ghidra.py`** 一本。
  （以前は `src/bridge_mcp_ghidra.py` が上流の素のまま同梱され「どちらが正か」不明瞭だったため削除した。
  python ブリッジの単一ソースは直下のみ。）
- `src/.github/modernize/` 配下は Java upgrade ワークフローのスクラッチで gitignore 対象。RE には無関係。

## 永続化（重要）

MCP の rename/型/コメントは **Ghidra DB に永続**する。仕組みは「analyzeHeadless の正常終了時保存」で、
`start_headless.ps1 -Stop`（sentinel ファイルで `GhidraMCPHeadless.run()` を抜けさせる）が到達させる。
**force-kill するとそのセッションの書き戻しは保存されない。** スクリプト内 `program.save()` は外側トランザクションで
失敗するため使わない。`.gpr` は git 非追跡なので、名前は `export_symbols.py` で `data/re_symbols.json` に定期バックアップする。
