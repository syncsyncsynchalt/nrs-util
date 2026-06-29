# nrs-edge — Claude 操作ガイド（ルーター）

`nrs.exe`（**Border Break / BBS**, x86-32, SEGA RingEdge）を**無改変**でスタンドアロン起動させる
**native C** プロジェクト。**OS 境界で RingEdge ハードウェアを仮想化**する（ゲームメモリパッチは原則ゼロ＝
CrackProof 残置のみ）。**Frida は使わない。** 旧 Frida 実装は破棄済み（git 履歴に残る）。

## 鉄則（最優先）

1. **ドキュメントは参考。正は実装。** 値/アドレス/フォーマット/シーケンスは使う前に必ず実体で裏取り:
   - **nrs.exe** → Ghidra MCP（`mcp__ghidra__*`, static_VA）。手計算・推測禁止。
   - **micetools**（RingEdge クリーンルームの正。lift 元） → `C:\src\micetools\` 直読。所在は `ref.md`。
   - **TeknoParrot / RingEdge 純正イメージ** → `ref.md` 参照。
2. **二層写像を守る**: `src/logic/system/`=mx* デーモン（PCP/TCP 傍受）、`src/logic/driver/`=segadriver+
   シリアル（DeviceIoControl/シリアル傍受）。実 RingEdge の境界＝エミュ戦略の境界。
3. **値・プロトコルは micetools と TeknoParrot の両方を正として参照**し推測で決めない。

## 構成

| 知りたいこと | 場所 |
|---|---|
| RE で確定した事実（アドレス/構造体/プロトコル/COM map） | `facts/<subsys>.md`（索引 `facts/_index.md`、live bug `facts/bugs.md`）|
| 関数名/型（Ghidra へ適用される正） | `data/known_names.json` |
| 外部オラクルの所在と権威範囲 | `ref.md` |
| 製品ソース（host + reloadable logic） | `src/`（下記） |
| ビルド/反復/起動 | `CMakeLists.txt` / VSCode タスク(`.vscode/tasks.json`) / `loader.exe`(GUI＋CLI) / 下記 |
| 現在地・次の一手 | `STATUS.md` |

```
src/
  host/    安定層（注入一度）: host.c hook.c log.c reload.c ／ loader.c=統合 GUI（in-process 注入+ログ tail+設定+入力）
  logic/   差し替え対象(logic.dll)= 実 RingEdge 二層写像
    abi.h api.c crackproof.c
    driver/  mxjvs.c [columba.c dipsw.c smbus.c superio.c hwreset.c touch.c card.c]  (DeviceIoControl/serial)
    system/  [mxkeychip.c mxnetwork.c mxmaster.c mxgfetcher.c]                        (PCP/TCP)
```

## アーキテクチャ（host + reloadable logic）

- **host**（注入時一度ロード）: MinHook で Win32 API を**一度だけ**フック。**状態アリーナ(arena)を所有**。
  `logic.dll` をロードし `LogicApi` テーブルを保持。フック発火時 `api->on_*(state,…)` を呼ぶ。
  `reload.c` が `logic.dll` 変更を検知し **FreeLibrary→LoadLibrary→テーブル差し替え**（ゲーム起動したまま swap）。
- **logic**（差し替え対象）: `abi.h` の契約**のみ**に依存。`logic_get_api()` だけを export。
  状態は host から渡される arena に置く（**永続 global を持たない**）。device handler を実装。
- **契約 `abi.h`**: HostServices(log/arena/orig) + LogicApi(bind/on_create_file/on_read_file/on_device_iocontrol…)。
  **`abi.h` を変えると host+logic 両方再ビルド＋restart**。それ以外の logic 変更は **hot-reload**。

## ビルド・反復（Frida 無し）

- **ビルド**: CMake + **MSBuild(VS2022)**, **Win32(x86)**, 静的CRT。
  `cmake -B build -G "Visual Studio 17 2022" -A Win32` → `cmake --build build --config Debug --target logic`。
- **反復ループ**:
  - 人間: VSCode タスク **「👤 ビルドして GUI を開く」**（全ビルド→統合 GUI `loader.exe` 起動）。GUI が ▶起動=in-process 注入 / ログタブ=JSONL tail を担う。
  - 自律テスト: **`loader.exe start --wait` / `status` / `stop`**（headless CLI。JSON+exit code。`facts/workflow.md`「自律ゲームテスト」）。logic 変更は **host が auto-swap**（再起動不要）。
  - 観測は **logic の JSONL ログ**（自前コードを自由に計装）＋集約 `nrsedge.status.json`。ゲーム内部は Ghidra 静的 + 稀に cdb。
- 制約: 永続 struct レイアウト変更時のみ restart。MinHook を `third_party/` に vendor（host のみ依存）。

## 静的解析 = Ghidra MCP 一本（推測の前に必ず使う・書き戻す）

| やること | ツール |
|---|---|
| 逆コンパイル C / xref / 文字列 | `mcp__ghidra__decompile_function_by_address`(static_VA) / `get_xrefs_to` / `list_strings` |
| 逆コンパイル全文検索 | `mcp__ghidra__search_decompiled` |
| **書き戻し**（複利化・小コンテキスト化） | `rename_function_by_address` / `set_function_prototype` / `set_local_variable_type` / `set_decompiler_comment` |
| 地金 disasm / imports / segments | `mcp__ghidra__disassemble_function_by_address`(static_VA) / `list_imports` / `list_segments` |

- **RE 効率の核 = Ghidra DB への書き戻し**。解いた関数は名前/型/コメントを即 DB へ → 次の decompile が
  自己説明的になり読む量が減る。恒久名は **`data/known_names.json`**（static_VA→名）に追記
  （`tools/ghidra_mcp/start_headless.ps1` が次回適用）。表せない事実だけ `facts/<subsys>.md` に terse 追記。**二度解かない。**
- サーバ起動: `powershell -File tools\ghidra_mcp\start_headless.ps1`（冪等）。bridge は `.mcp.json`。
- 1 関数単位で取得、全読み禁止、grep 先行。decompiler が reg/暗黙引数を隠したら `disassemble_function_by_address` + `set_function_prototype`。

## RE ループ

```
位置特定: facts/ と data/known_names.json を grep → 無ければ Ghidra search_decompiled/list_strings
読む:    decompile（1関数）。隠れたら mcp__ghidra__disassemble_function_by_address
確証:    micetools/ringedge を狙い撃ち grep（ref.md）。必要時のみ cdb
書き戻し: Ghidra rename + set_function_prototype/型 + comment、data/known_names.json に追記
記録:    名前で表せない事実だけ facts/<subsys>.md に terse 追記
```

## 確定済みの要点（詳細は facts/）

- **JVS = シリアル COM4**（115200 8N1 overlapped, `amJvstThreadInit` 0x989B10, 文字列 "COM4"@0xAE11F0）。
- **COM map**: touch=COM1(kdserial で COM3) / card=COM2 / JVS=COM4。選択器 `serial_select_com_index`(0x67C360)。
- **columba = DMI/物理メモリ読取**ドライバ（JVS ではない）。
- ネイティブ JVS 経路は**実データを与えれば安全**（旧クラッシュは捏造成功の自滅。`facts/bugs.md`）。
- 実バトル開始ブロッカー = **タッチ device**（COM1）。
