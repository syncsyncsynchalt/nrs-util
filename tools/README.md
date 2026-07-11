# tools/：解析ツール索引（成果物ではない）

nrs.exe (NRS / Border Break) を**解析・観測する**スクリプト群。**Frida は使わない**（旧 Frida/boot 実装は破棄済み）。
無改変起動の実体は host + reloadable logic（`../src/`、ビルドは `../CMakeLists.txt` / `loader.exe`）。

> Python の実行はフルパス推奨（`python.exe` は Windows Store スタブで失敗）:
> `%LOCALAPPDATA%\Programs\Python\Python313\python.exe`

## ディレクトリ

| dir | 用途 | 主なもの |
|---|---|---|
| `ghidra_mcp/` | **静的解析 MCP 基盤**（唯一の入口）。逆コンパイル/xref/全文検索/書き戻しを `mcp__ghidra__*` で提供 | `bridge_mcp_ghidra.py`（正典ブリッジ）、`start_headless.ps1`（起動/停止）、`build_headless.py`（codegen）、`export_symbols.py`（DR ダンプ）、`ghidra_scripts/`、`src/`（vendor スナップショット）。詳細 `ghidra_mcp/README.md` |
| `static/` | nrs.exe の offline 静的解析 | `nrs_strings.c`（文字列抽出 native exe。`cmake --build … --target nrs_strings` → `build/Debug/nrs_strings.exe [--all]`） |
| `test/` | 動的観測ハーネス | `touch_test.ps1` 等 |

## 静的解析 = Ghidra MCP（唯一の入口）

逆コンパイル C・xref・全文検索・リネーム/型/コメントの**書き戻し**は `mcp__ghidra__*`（`../CLAUDE.md` の表）。
サーバは `ghidra_mcp/start_headless.ps1`（冪等・GUI 不要・readiness まで待って exit 0）。connection refused なら起動する。
番地は **static_VA**（ImageBase 0x400000、Ghidra と同方言）。全文検索 `mcp__ghidra__search_decompiled` は初回キャッシュ構築に数分。

**書き戻しは Ghidra DB に永続**する（analyzeHeadless の終了時保存）。停止は必ず `start_headless.ps1 -Stop`（graceful）で。
force-kill するとそのセッションの書き戻しが失われる。詳細は `ghidra_mcp/README.md`。

文字列抽出だけ offline native exe が残る: `build/Debug/nrs_strings.exe [--all]`。逆アセンブル/xref/imports/segments は
`mcp__ghidra__disassemble_function_by_address` / `get_xrefs_to` / `list_imports` / `list_segments`。
