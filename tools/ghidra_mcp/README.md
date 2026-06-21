# tools/ghidra_mcp/：静的解析 MCP 基盤のレイアウト

nrs.exe の逆コンパイル/xref/全文検索を `mcp__ghidra__*` で提供する基盤。**正典は直下のファイル**で、
`src/` は上流 GhidraMCP の vendor スナップショット（jar をビルドするためだけに存在）。

## 直下（使う・保守する正典）

| file | 役割 |
|---|---|
| `bridge_mcp_ghidra.py` | **正典のブリッジ**。Claude ──`mcp__ghidra__*`──▶ これ ──HTTP:8080──▶ Ghidra。`search_decompiled` 等の自前拡張を含む（上流 fork）。MCP が起動するのはこれ。 |
| `ghidra_scripts/ApplyKnownNames.java` | `data/known_names.json`（static_VA→名）を毎起動時に適用 |
| `ghidra_scripts/GhidraMCPHeadless.java` | headless で HTTP サーバを立てるエントリ |
| `build_headless.py` | プラグイン jar をビルド（`src/` を入力にする） |
| `start_headless.ps1` | サーバ起動（冪等・GUI 不要）。connection refused 時に叩く |

## `src/`（vendor の上流スナップショット。触らない）

[lauriewired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) の素のコピー。**プラグイン jar の
ビルド元としてのみ**保持する。ビルド成果物（`target/`・`lib/*.jar`）は `.gitignore` 済み。

- ここの Python/JS を runtime で使わない。ランタイムのブリッジは上記**直下の `bridge_mcp_ghidra.py`** 一本。
  （以前は `src/bridge_mcp_ghidra.py` が上流の素のまま同梱され「どちらが正か」不明瞭だったため削除した。
  python ブリッジの単一ソースは直下のみ。）
- `src/.github/modernize/` 配下は Java upgrade ワークフローのスクラッチで gitignore 対象。RE には無関係。

詳細な起動・トラブルシュートは `../../docs/ghidra_mcp_setup.md`。
