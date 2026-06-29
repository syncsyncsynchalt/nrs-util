# tools/：解析と開発のツール索引（成果物ではない）

nrs.exe (NRS) を**解析・観測する**スクリプト群。ゲームを起動させる実体（frida モジュール +
keychip サーバ + ランチャ）は **`../boot/`**（→ `../boot/README.md`）。

> 実行は必ず Python フルパス（`python.exe` は Windows Store スタブで失敗）:
> `%LOCALAPPDATA%\Programs\Python\Python313\python.exe`

## ディレクトリ（役割別）

| dir | 用途 | 主なスクリプト |
|---|---|---|
| `static/` | **nrs.exe** の静的解析（実行不要） | `nrs_strings.c`（文字列抽出・native exe、`cmake --build … --target nrs_strings` → `build/Debug/nrs_strings.exe`）。逆アセンブル/xref/imports は Ghidra MCP（下記） |
| `re/` | **nrs.exe 以外**の静的/メモリ解析（TP.dll・実行中プロセスのダンプ） | `tp_re.py`（TeknoParrot.dll PE 解析）、`memscan.py`、`dump_tp.ps1` + `pe-sieve32.exe` |
| `runtime/` | 実行中プロセスの観測（attach 専用） | `screenshot_window.py`（実写検証・**必須**）、`jvs_trace.py`、`jvsstate_capture.py`、`trace_dongle.py`、`thread_inspect.py`、`list_modules.py`、`frida_diag/`（観測専用 .js。本番ロードに含めない） |
| `logs/` | ログ後処理 | `read_log.py`（正規表現フィルタ）、`session_summary.py`、`log_analyzer.py` |
| `hygiene/` | リポ衛生 | `check_doc_sync.py`（`boot/MANIFEST.json`↔モジュール↔FACTS の整合） |
| `ghidra_mcp/` | 静的解析 MCP 基盤（直下 `bridge_mcp_ghidra.py`=**正典**ブリッジ。`src/`=上流の vendor スナップショット＝プラグイン jar のビルド元のみ。詳細 `ghidra_mcp/README.md`） | `bridge_mcp_ghidra.py`、`ghidra_scripts/`、`build_headless.py`、`start_headless.ps1` |
| `git_hooks/` | pre-commit | `pre-commit`（`git config core.hooksPath tools/git_hooks` で有効化） |
| `iso/` | **SBVA(DVR-5001) ISO/SSD 抽出**（TrueCrypt 復号・検証。背景は `../docs/iso_extraction.md`） | `tc_decrypt_volume.py`（TC4.3 AES-LRW 復号本体）、`lrw.py`（LRW ライブラリ）、`decrypt_bootid.py`、`scan_layout.py`、`make_kcf.py`（→ `iso/README.md`） |

## 静的解析 = Ghidra MCP（唯一の入口）

逆コンパイル C・xref・全文検索・リネームは **`mcp__ghidra__*`**（`../CLAUDE.md` の表）。
サーバは `ghidra_mcp/start_headless.ps1`（冪等・GUI 不要）。connection refused なら起動する。
全文検索 `mcp__ghidra__search_decompiled` は初回キャッシュ構築に数分。詳細 `../docs/ghidra_mcp_setup.md`。

## 静的解析（逆アセンブル/xref/imports/segments）= Ghidra MCP
disasm.py は廃止（脱Python）。逆アセンブル・xref・imports・segments は **`mcp__ghidra__*`** で取得する
（番地は static_VA、ImageBase 0x400000、Ghidra と同方言）:
- 逆アセンブル: `mcp__ghidra__disassemble_function_by_address`（static_VA）
- xref: `mcp__ghidra__get_xrefs_to`
- imports / segments: `mcp__ghidra__list_imports` / `list_segments`

文字列抽出だけは offline native exe が残る: `build/Debug/nrs_strings.exe [--all]`（`cmake --build … --target nrs_strings`）。

## 観測 attach（本番ロードと混ぜない）
`runtime/jvsstate_capture.py` 等は単体 `--pid`/`--wait` で attach。`runtime/frida_diag/*.js` は観測専用で
`boot/MANIFEST.json` には載せない（本番ロードに混入させない）。

`boot/launch.py --diag <PATH>` で観測 .js を boot バンドル末尾に連結注入できる（繰り返し可）。boot ゲート通過後にしか
来ない初期化（描画など）を、ブートと同じ spawn-suspended セッションで観測する用途。

```powershell
# OpenGL/WGL 初期化診断（採用 GL_RENDERER / pixel format / context 成否 / SwapBuffers 回数）
# nrs.exe は OpenGL レンダラ。"GDI Generic" が出れば ベンダ ICD 未ロード＝黒画面の主因。
& $py boot\launch.py --spawn --diag tools\runtime\frida_diag\gl_init_diag.js --duration 120
```

起動コマンドの定本は `../boot/README.md` と `../STATUS.md`。
