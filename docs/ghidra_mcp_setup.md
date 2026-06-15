# Ghidra MCP（ヘッドレス・GUI不要）

Claude が `nrs.exe` の Ghidra プロジェクトに対し、**対話的に**逆コンパイル取得・
リネーム伝播・xref（データ参照含む）・型適用を行うための MCP サーバー。

**静的解析の唯一の入口**（旧 `nrs_query.py` + `data/decompile/` 静的 dump は退役）。
常に最新の逆コンパイル結果が得られ、リネーム/型付けは Ghidra の伝播が効く。
逆コンパイル C 全文検索は `search_decompiled`。**Ghidra GUI は不要**（`analyzeHeadless` で常駐）。

---

## 仕組み

```
Claude ──mcp__ghidra__*──▶ bridge_mcp_ghidra.py ──HTTP:8080──▶ GhidraMCPHeadless.java
  (.mcp.json が bridge を起動)                      (analyzeHeadless で nrs.exe を開いて常駐)
```

- `ghidra_scripts/GhidraMCPHeadless.java` … upstream GhidraMCP plugin を **GhidraScript 化**したもの。
  GUI(PluginTool/Swing/CodeViewer)依存を除去し `currentProgram` で動作。HTTP サーバーを 8080 で起動して常駐。
- `analyzeHeadless` が既存プロジェクト `data/ghidra_nrs`（program=`nrs.exe`）を `-noanalysis` で開く。
- `.mcp.json`（リポジトリ root）が bridge を MCP サーバーとして登録済み。

## 構成済み（このリポジトリ）

| 項目 | 状態 |
|---|---|
| bridge `tools/ghidra_mcp/bridge_mcp_ghidra.py` | ✅ |
| headless server `tools/ghidra_mcp/ghidra_scripts/GhidraMCPHeadless.java` | ✅ Ghidra 12.1.2 でコンパイル確認済み |
| launcher `tools/ghidra_mcp/start_headless.ps1` | ✅ |
| MCP 登録 `.mcp.json` | ✅ trust 済み |
| Python 依存 (`mcp`, `requests`) | ✅ |

## 使い方

```powershell
# 起動（GUI不要。8080 で待受開始まで数十秒）
powershell -File tools\ghidra_mcp\start_headless.ps1
# 停止
powershell -File tools\ghidra_mcp\start_headless.ps1 -Stop
```

`captures\ghidra_headless.log` に `HTTP server listening on port 8080` が出れば準備完了。
以後 Claude の `mcp__ghidra__*` ツールがそのまま使える（接続先 `127.0.0.1:8080`）。

> サーバー未起動時は MCP ツールが connection refused になる。その場合は上記 launcher を実行する。
> launcher は冪等（既起動なら no-op）。`-preScript ApplyKnownNames.java` が起動時に
> `data/known_names.json` を program へ適用する。`search_decompiled` は初回呼び出しで全関数を
> 逆コンパイルしキャッシュ構築（数分）— "cache building" が返ったら再試行。

## 再生成（upstream 更新時 / 別 Ghidra バージョン）

`GhidraMCPHeadless.java` は upstream の `tools/ghidra_mcp/src/.../GhidraMCPPlugin.java` から
`build_headless.py` で機械生成している（GUI 依存箇所のみ差し替え。各置換は件数アサート付き）。

```powershell
python tools\ghidra_mcp\build_headless.py     # GhidraMCPPlugin.java → ghidra_scripts\GhidraMCPHeadless.java
```

別の Ghidra バージョンに移行する場合は、`analyzeHeadless` が起動時に
スクリプトを自前のクラスパスで再コンパイルするため、通常そのまま動く
（API 破壊があった場合のみ `build_headless.py` の置換か元ソースを調整）。

## 注意

- リネーム/型付けはセッション中メモリに反映される。`analyzeHeadless` は常駐中は保存しないため、
  サーバー再起動で既定名に戻る。永続化したい場合は別途プロジェクト保存処理が必要。
- 同じプロジェクトを Ghidra GUI で同時に開くとロック競合する。ヘッドレス常駐中は GUI で開かない。
