# TeknoParrot リファレンス（BBS / nrs.exe）— 要約

**正（source of truth）は実機 TeknoParrot インストール `C:\src\TPBootstrapper\` と nrs.exe 原本 `C:\src\bbs\`。**
本資料はその要約で陳腐化しうる。設定値・プロトコル・シーケンスを使う前に、上記の実ファイル、または
実行時フック観測（`tools/runtime/frida_diag/*.js` + `tools/runtime/*.py`）で裏取りする。
`TeknoParrot.dll` は VMProtect 保護で**静的デコンパイル不可** → 観測は実行時 API フックに限る（§8.5）。

> 関連: 横断定数/TP パッチ → `../boot/ARCH.md` ／ サブシステム事実 → `../boot/<subsys>/FACTS.md` ／
> バグ・失敗 → `../BUGS.md` ／ 現在地 → `../STATUS.md` ／ 北極星 → `architecture.md` ／ 低レイヤ正 → `micetools.md`

---

## 1. 概要・構成

TeknoParrot は SEGA 他のアーケード基板（RingEdge/RingWide/Lindbergh/Nu 等）を PC で起動させるローダ。
ゲーム EXE に DLL を注入し、ドングル・keychip・JVS I/O・ネットワーク・ハード検査を肩代わりする。
BBS では nrs.exe を**改変せず**注入で起動（本プロジェクトの Frida 方式と目的同じ・手段違い）。

インストール構成（`C:\src\TPBootstrapper\`）の要点:
| 要素 | ファイル | 役割 |
|---|---|---|
| UI/ランチャ | `TeknoParrotUi.exe` (1.0.0.1987) | プロファイル選択・設定・起動（.NET, 文字列暗号化） |
| インジェクタ | `OpenParrotWin32/OpenParrotLoader.exe` | nrs.exe を spawn し DLL 注入（§2） |
| 注入 DLL (32bit) | `TeknoParrot/TeknoParrot.dll` (63MB, VMProtect) | **注入実体**。BBS は 32bit を使用 |
| グラフィック/音 | `glut32.dll`/`regal32.dll`/`Opensegaapi.dll` 等 | OpenGL/segaapi 差し替え |

グローバル設定 `ParrotData.xml`: `ExitGameKey=0x1B`(Esc)/`PauseGameKey=0x13`/`ScoreCollapseGUIKey=0x79`(F10)。
バージョンは `tpcache.json`（TeknoParrot core 1.0.0.3699 / OpenParrotWin32 32.1.0.0.773 等、teknogods release zip）。

## 2. 起動・インジェクションの流れ（実測確定）

TeknoParrotUi の Launch が起動するのは `OpenParrotLoader.exe`。実測コマンドライン:
```
cwd=C:\src\TPBootstrapper
.\OpenParrotWin32\OpenParrotLoader.exe  .\TeknoParrot\TeknoParrot  "C:\src\bbs\nrs.exe"
                                        └─注入DLLパス接頭辞(.dll付与)  └─ゲームEXE(引数なし)
```
→ OpenParrotLoader が汎用インジェクタとして nrs.exe を spawn し `TeknoParrot.dll` を注入。注入後:
JVS は SHM `TeknoParrot_JvsState`(8B) + pipe `\\.\pipe\teknoparrot_jvs`（§5）、ドングル/keychip/region 検査を
フックで通過、glut32/segaapi をフック、amNet/PCPA をプロファイル IP で応答。

> **ヘッドレス起動（UI 不要）**: 上記コマンドを直接実行すれば UI を介さず BBS を起動できる。
> ⚠️ TeknoParrot.dll は VMProtect 下のサードパーティ実装。実行は正規ローダ経由に限る。
> 本プロジェクトは OpenParrotLoader/TeknoParrot.dll を使わず `boot/launch.py` が直接 spawn/attach し
> 相当機能を `boot/*.js` で自前実装する（§9）。

## 3. BBS GameProfile 設定値（設定値の正＝ TP の NRS 用 `UserProfiles/<NRS>.xml`）

メタ: EmulatorType=`TeknoParrot` / EmulationProfile=`<NRS>` / ExecutableName=`nrs.exe` /
GamePath=`C:\src\bbs\nrs.exe` / Is64Bit=`false` / TestMenuParameter=`-test`。

General:
| Field | Value | 備考 |
|---|---|---|
| Input API | `DirectInput` | DirectInput / XInput / MergedInput |
| DongleRegion | `JAPAN` | JAPAN/USA/JAP2N/EXPORT/CHINA |
| PcbRegion | `JAPAN` | 本プロジェクト Error 0903 の region と一致（§6） |
| FreePlay / Windowed | `1` / `1` | |
| CustomBotMap | `5` | BBS 固有 |

Network: Dhcp=`1` / Ip=`192.168.168.103` / Mask=`255.255.255.0` / Gateway=`192.168.168.1` /
Dns1=`192.168.168.1` / BroadcastIP=`192.168.168.255`。
> ⚠️ TP は `192.168.168.0/24`。本プロジェクトの amNet bind 先は `192.168.1.209`（`../boot/mxnetwork/FACTS.md`）で
> **サブネットが異なる**。TP 値をそのまま流用せず amNet の実 bind 先を正とする。

## 4. 入力マッピング（`<JoystickButtons>` が JVS 割当の正）

Test→Test / Service→Service1 / Coin→Coin1 / Start→P1ButtonStart / Joystick X→Analog0(AnalogJoystick) /
Joystick Y→Analog2(AnalogJoystickReverse) / Jump→P1Button1 / Dash→P1Button2 / Action→P1Button3。
Up/Down/Left/Right は Analog0/Analog2 の Special1/2(Max/Min)。
論理ボタンが JVS READ_SWITCHES（cmd 0x20）のどのビットに乗るかは §5 の SHM 実測で確定する。
本プロジェクトは `sw643=0x40/0x80`(SERVICE/START) を観測し phase=4 到達を確認済（`../boot/amjvs/FACTS.md`）。

## 5. JVS I/O と `TeknoParrot_JvsState` 共有メモリ

- nrs.exe の JVS 接続試行順: `\\.\pipe\teknoparrot_jvs`（TP 生成 named pipe）→ `COM2` → `COM1`。
- IOCTL（columba 互換）: HELLO=0x80006004 / SENSE=0x8000600C / TRANSACT=0x8000E008。
- `TeknoParrot_JvsState`/`<NRS>` 等のプロファイル名文字列の**平文は全バイナリに非存在**（VMProtect 文字列暗号化、§8.5）。
  発生源は実行時 API フックでのみ確定できる。

### 実測で確定した発生源・レイアウト
正規起動した nrs.exe（TeknoParrot.dll 注入下）へ観測スクリプトを attach して実証:
- **JvsState の生成者は `TeknoParrot.dll`(32bit)**。最深フレームは静的特定した VMProtect エントリ RVA と一致。
- **4 か所**から同名で `CreateFileMappingW`（同一カーネルオブジェクト、4 view にマップ）。
- アイドル 8 バイト = `01 00 00 00 00 00 00 00`（byte0=0x01 固定=JVS-present 相当、byte1..7=入力状態）。
- **ビット→ボタン割当は未確定**: BBS プロファイルの JoystickButtons に物理束縛が無く、キー送出では JvsState が
  変化しない。確定には **先に TP UI で入力束縛**してから観測する。

### 観測 runbook（本番ロードと混ぜない）
1. 観測 attach を先に起動（別ターミナル、nrs.exe 出現を待つ）:
   `tools\runtime\jvsstate_capture.py --wait 200 --duration 180`（純観測 `frida_diag/jvsstate_trace.js` 単体）。
2. BBS を起動（§2 のヘッドレス、または TeknoParrotUi の Launch）。
3. TP UI の入力設定で Test/Service/Coin/Start/Jump/Dash/Action とスティックを束縛 → 各操作で byte/bit 変化を観測。
4. ログ `captures/jvsstate-*.txt`。
> ⚠️ `boot/launch.py` 全体を attach してはいけない（boot の patchCode が TP のフックと二重適用で破綻）。
> 観測は `tools/runtime/jvsstate_capture.py`（観測 .js 単体ロード）を使う。JvsState は BudgieLoader 注入下で
> 生成されるため、boot/launch.py の spawn 経路（注入なし）では出ない。

## 6. region / keychip / amNet の扱い（本プロジェクトとの対比）

| サブシステム | TeknoParrot | 本プロジェクト（Frida） |
|---|---|---|
| region | プロファイル `DongleRegion`/`PcbRegion=JAPAN` を注入時に供給 | `pcpa_server.py` で `keychip.appboot.region`=01、`boot/mxkeychip/region.js` で setter 無力化（Error 0903） |
| keychip | TP が keychip 応答をエミュレート | `pcpa_server.py` + keychipSM 完走（`../boot/mxkeychip/FACTS.md`） |
| amNet | プロファイル IP(192.168.168.x) で応答 | bind 先を INADDR_ANY 化、`pcpa_server.py` の `&` 区切り応答（`../boot/mxnetwork/FACTS.md`） |
| ドングル | TP がドングル検査を通過 | `boot/amdongle/diag.js` / `patch.js`（amDongleBusy のみ維持） |

region 値（JAPAN）は一致。**ネットワークのサブネットだけ相違**（§3 注記）。
TP は検査を**フックで通過**（データを正そうとしない）＝本プロジェクトが基板値供給源の無い場面で採る方式。

## 7. 元 RingEdge 起動環境（TP が代替している対象。原本 `C:\src\bbs\`）

- `game.bat`: `mxGetHwInfo.exe -s HwInfo.ini`（基板ハード検査）→ ERRORLEVEL 0 で `nrs.bat -img`。
- `nrs.bat`: `option=-wsvga -full`、`PATH+=lib\win32\bin`、build 切替 `--Develop`(既定) 等で `build\nrs.exe`。
- `HwInfo.ini`: board-type=RINGEDGE_NEC 等 / graphic=`10de:0623`(NVIDIA) / sound=`11d4:1882` /
  mem=1024MB・sram=2048KB / resolution=`1024 x 600`。TP の `Windowed=1` は `-wsvga -full` の窓化。
TP/本プロジェクトはこのハード検査自体を回避する（本プロジェクトは amPlatform/JVS バイパス）。

## 8.5 クローズド実装の解析（注入実体＝`TeknoParrot.dll` 32bit）

`OpenParrotLoader`/`BudgieLoader.exe` が nrs.exe に `TeknoParrot.dll` を注入しエクスポートを呼ぶ。
静的 RE は `tools/re/tp_re.py`（pefile+capstone）。

- **VMProtect 系**: `.text`/`.rdata`/`.data` が rawsz=0（実行時アンパック）、`teknoGod` セクション（vsz≈53MB,
  entropy 7.94=暗号化）、エントリ RVA 0x736b778 が暗号化セクション内で難読化 prolog。IAT 剥離（各 import 1 関数）。
- **エクスポート**: `InitKonami`(0x2fbf30) / `InitLinux`(0x2fbfd0) / `InitializeASI`(0x2fc060)。BudgieLoader が呼ぶ。
- **帰結**: 静的デコンパイル不可・文字列は per-use 復号でメモリダンプも困難。
  「実際に呼ばれる実装」を読む唯一の現実手段は **実行時 API フック**（packing 非依存の kernel32 側で観測）:
  `CreateFileMappingW`/`MapViewOfFile`/`CreateNamedPipeW` を nrs.exe 内でフック → `Thread.backtrace` で
  caller が `TeknoParrot.dll+offset` を確認（= §5 の `tools/runtime/jvsstate_capture.py` + 観測 .js がこれ）。
- ⚠️ TeknoParrot.dll を `rundll32` 等で単体実行してアンパック誘発するのは見送る（未署名パック DLL のコンテキスト外実行）。
> ヘルパ: `tools/re/tp_re.py <pe> --all`（セクション/エントロピー/IAT/エクスポート/エントリ逆アセンブル）、
> `tools/re/memscan.py <pid> <needle...>`。

## 9. 本プロジェクト Frida 実装との対応（詳細は MANIFEST / 各 FACTS / BUGS）

「抑制」ではなく各サブシステムを実際に**満たす(satisfy)**ことで amlib SYSTEM STARTUP(`FUN_0089a010`)が
state10(DONE)まで完走し ATTRACT 描画に到達。satisfy チェーンの一覧は `../STATUS.md`、機構は `../boot/MANIFEST.json`。

| TeknoParrot の肩代わり | 本プロジェクト実装 |
|---|---|
| DLL 注入の共通フック（File/Net/IPC ログ） | `boot/lib/base.js` |
| amNet 応答・bind 先供給 | `boot/mxnetwork/diag.js` + `pcpa_server.py` |
| ドングル/amPlatform/region 検査通過 | `boot/amdongle/*` / `boot/amplatform/identity.js` / `boot/mxkeychip/region.js` |
| amGfetcher / get_status | `boot/mxgfetcher/getstatus.js` |
| JVS バイパス・デバイス擬装 | `boot/amjvs/*` / `boot/mxdrivers/devices.js` |
| keychip/PCPA・billing offline | `pcpa_server.py` / `boot/mxkeychip/setup.js` / `boot/patches.json(0xA065C0)` |
| IC Card/USB I/O/Touch/Network type/EXTEND/ALL.Net/P-ras | `boot/devices/*` / `boot/patches.json(0x6FF1B3)` / `boot/mxsegaboot/*` / `boot/patches.json(0x72DCE0)` |
| JvsState SHM（調査中） | `tools/runtime/frida_diag/jvsstate_trace.js`（§5） |
| boot 全体診断 | `tools/runtime/frida_diag/*`（error1000_trace / amlib_init_diag / keychip_scene_diag 等）+ `screenshot_window.py` |

> ⚠️ 検証鉄則: errNo=0 等のログだけでクリーン判断しない。必ず `tools/runtime/screenshot_window.py` で実写確認。
