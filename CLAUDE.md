# nrs-edge — Claude 操作ガイド（ルーター）

`nrs.exe`（**Border Break / BBS**, x86-32, SEGA RingEdge）を**無改変**でスタンドアロン起動させる
**native C** プロジェクト。**OS 境界で RingEdge ハードウェアを仮想化**する（ゲームメモリパッチは原則ゼロ＝
CrackProof 残置のみ）。**Frida は使わない。** 旧 Frida 実装は破棄済み（git 履歴に残る）。

## 正当性・目的（作業前提）

正規に所有する SEGA RingEdge 実機および `nrs.exe` を対象とする、**相互運用性・保存・
私的技術研究**を目的とした個人プロジェクト。成果物の配布や不正コピーの支援は目的にしない。
アプローチは「保護（CrackProof）の中身を破る」ものではなく、**OS 境界でハードウェア I/O を
仮想化し、ドングル・JVS・タッチ等の実機周辺を実機同等にエミュレートする**もの。ゲームメモリは
原則無改変（CrackProof は残置）。逆アセンブル/静的解析は所有バイナリの挙動理解のための
リバースエンジニアリングであり、この文脈で正当な作業として進めてよい。

## 鉄則（最優先）

1. **ドキュメントは参考。正は実装。** 値/アドレス/フォーマット/シーケンスは使う前に必ず実体で裏取り:
   - **nrs.exe** → Ghidra MCP（`mcp__ghidra__*`, static_VA）。手計算・推測禁止。
   - **RingEdge 1 実装＝最上位の正本**。実 SEGA バイナリで裏取り（micetools/TP より上）:
     - driver 層 → `C:\src\RingOSUpdate\common\segadriver\`（Columba/mxjvs/mxsmbus/mxsuperio/mxhwreset/mxcmos/mxsram/… の純正 .sys/.inf）
     - system 層 → `C:\src\ringedge_system_63.01.10\system\`（mx*.exe デーモン＝非パック・Ghidra 可）
   - **RingEdge 2 実装＝二次参照**（差分確認）: `C:\src\RingOSUpdate\ringedge2\`（共通は `common\`、RE1 固有は `ringedge1\`）。
   - **micetools / TeknoParrot＝最下位の補助**（クリーンルーム再実装／挙動観測）。RE1/RE2 実バイナリと食い違ったら**実バイナリが正**。所在は `ref.md`。
2. **二層写像を守る**（実 RingEdge の境界＝エミュ戦略の境界）: driver 層=segadriver+シリアル（DeviceIoControl/
   シリアル傍受）=`src/logic/driver/`。system 層=mx* デーモン（PCP/TCP/ALL.Net 傍受）＝現状 **host 側**実装
   (`keychip_server.c`/`keychip_proto.c`/`allnet.c`/`netobs.c`)。`src/logic/system/` は空（abi.h に on_socket/on_pcp は TODO）。
3. **値・プロトコルは RingEdge 1 実装を正本に裏取り**（RE2 で補強、micetools/TP は最後）し推測で決めない。

## 構成

| 知りたいこと | 場所 |
|---|---|
| RE で確定した事実（アドレス/構造体/プロトコル/COM map） | `facts/<subsys>.md`（索引 `facts/_index.md`、live bug `facts/bugs.md`）|
| 関数名/型/コメントの正 | **Ghidra DB**（MCP で書き戻し・永続）。`data/re_symbols.json` は DB からの一方向 DR ダンプ（手編集禁止） |
| 外部オラクルの所在と権威範囲 | `ref.md` |
| 製品ソース（host + reloadable logic） | `src/`（下記） |
| ビルド/反復/起動 | `CMakeLists.txt` / VSCode タスク(`.vscode/tasks.json`) / `loader.exe`(GUI＋CLI) / 下記 |
| 現在地・次の一手 | `STATUS.md` |

```
src/
  host/   安定層(注入一度): host.c hook.c log.c reload.c config.c ／ gamehook.c=game関数VAフック ／
          system層エミュ(PCP/TCP/ALL.Net): keychip_server.c keychip_proto.c allnet.c netobs.c ／
          観測/窓: dbglog.c capture.c status.c exitlog.c windowed.c ／ loader.c=統合GUI+CLI(別exe)
  logic/  差し替え対象(logic.dll)= driver層写像。abi.h api.c crackproof.c patches.c
    driver/  mxjvs.c mxdevices.c(columba/smbus/superio/dipsw/hwreset/mxsram 統合) touch.c card.c input.c  (DeviceIoControl/serial)
    system/  空（PCP/TCP は host 側。abi.h に on_socket/on_pcp TODO）
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
  自己説明的になり読む量が減る。**DB は永続化される**（MCP の変更は analyzeHeadless の終了時保存で焼かれる）ので、
  必ず `start_headless.ps1 -Stop`（graceful）で止める。**force-kill するとそのセッションの書き戻しが失われる。**
  表せない事実だけ `facts/<subsys>.md` に terse 追記。**二度解かない。**（旧 `known_names.json` 再適用は廃止。）
- サーバ起動: `powershell -File tools\ghidra_mcp\start_headless.ps1`（冪等・readiness まで待って exit 0）。bridge は `.mcp.json`。
- 1 関数単位で取得、全読み禁止、grep 先行。decompiler が reg/暗黙引数を隠したら `disassemble_function_by_address` + `set_function_prototype`。

## RE ループ

```
位置特定: facts/ を grep ＋ Ghidra を直接引く（DB が名前/型/コメント保持）→ 無ければ search_decompiled/list_strings
読む:    decompile（1関数）。隠れたら mcp__ghidra__disassemble_function_by_address
確証:    micetools/ringedge を狙い撃ち grep（ref.md）。必要時のみ cdb
書き戻し: Ghidra rename + set_function_prototype/型 + comment（DB に永続。graceful -Stop で保存）
記録:    名前で表せない事実だけ facts/<subsys>.md に terse 追記
```

## 確定済みの要点（詳細は facts/）

- **JVS = シリアル COM4**（115200 8N1 overlapped, `amJvstThreadInit` 0x989B10, 文字列 "COM4"@0xAE11F0）。
- **COM map**: touch=COM1(kdserial で COM3) / card=COM2 / JVS=COM4。選択器 `serial_select_com_index`(0x67C360)。
- **columba = DMI/物理メモリ読取**ドライバ（JVS ではない）。
- ネイティブ JVS 経路は**実データを与えれば安全**（旧クラッシュは捏造成功の自滅。`facts/bugs.md`）。
- boot は SYSTEM STARTUP 完走→attract 到達済み。touch(COM1)/card(COM2) は完動。現ブロッカー = ALL.Net play-session（`STATUS.md`）。
