# 独自ランチャー設計（TeknoParrot 置換）

RE 事実（アドレス・ポート・プロトコル）は `../FACTS.md`。ここは**実装設計のみ**。

## ゲームフォルダ `C:\src\bbs\`

```
nrs.exe             ← 本体
teknoparrot.ini     ← 起動前に生成（下記設定を amNet/amDongle が参照）
SBVA_Table.dat      ← SEGA 基板認証テーブル
HwInfo.ini          ← RingEdge HW 仕様 (解像度 1024x600)
lib\win32\bin\      ← RingEdge 専用 DLL（エミュでは実質不使用）
ram\, rom\          ← ゲームデータ
```

主要設定（TP の設定値の正＝`UserProfiles/<NRS>.xml`。要約と相違は `docs/teknoparrot.md` §3 を正とする）:
| 設定 | 値 | 効果 |
|---|---|---|
| DongleRegion / PcbRegion | `JAPAN` | → `keychip.appboot.region`=01（Error 0903 の region） |
| FreePlay / Windowed | `1` / `1` | クレジット不要・窓化 |
| Auth Server IP | 未設定 | NAOMI Net 認証スキップ |

> ⚠️ **ネットワーク IP は TP 値をそのまま流用しない。** TP プロファイルは `192.168.168.0/24`
> (`Ip=192.168.168.103`)。本プロジェクトの amNet bind 先は `192.168.1.209`（現在は INADDR_ANY 化）で
> **サブネットが異なる**。正は `boot/amnet/FACTS.md` と `docs/teknoparrot.md` §3 の注記。

## DLL 注入方式（OpenParrotLoader 系）

```cpp
// 1. CWD=C:\src\bbs で CREATE_SUSPENDED 起動
CreateProcessW(L"C:\\src\\bbs\\nrs.exe", ..., CREATE_SUSPENDED|CREATE_NEW_PROCESS_GROUP,
               ..., L"C:\\src\\bbs", &si, &pi);
// 2. OEP (static_VA 0xA7DAD4 = `entry`、Ghidra MCP 確認済) まで RunTo（EB FE ポーリング）
// 3. VirtualAllocEx → LoadLibraryW shellcode で hooks DLL 注入
// 4. DllMain で PCPA サーバー + フック起動 → ResumeThread
```

## 実装フック一覧（TeknoParrot が提供するもの）

| # | フック | 実装要点 |
|---|---|---|
| 必須 | mxGetHwInfo バイパス | nrs.exe を game.bat 経由でなく直接起動 → mxGetHwInfo.exe 不実行 |
| 必須 | PCPA サーバー群 | 127.0.0.1 の各ポートで listen（ポート/応答は FACTS） |
| 必須 | amNet サービス | 40104。query_nic_status の IP に bind 成功でループ脱出 |
| 必須 | JVS エミュ | Named Pipe `\\.\pipe\teknoparrot_jvs` + COM API を GetProcAddress+MinHook で intercept |
| 必須 | RingEdge ドライババイパス | `\\.\mxsram`→`%APPDATA%\TeknoParrot\SBVA_sram.bin`、`mxsuperio`→固定センサ値、`mxhwreset`→偽ハンドル |
| 必須 | NAOMI Net 認証バイパス | Auth Server IP 未設定（追加フック不要） |
| 推奨 | OpenGL ウィンドウモード | `ChangeDisplaySettingsA` ブロック + `CreateWindowExA` WS_POPUP→WS_OVERLAPPEDWINDOW |
| 推奨 | RTC | `amRtcGetServerTime`→PC ローカル時刻、`SetServerTime`→無視 |
| 推奨 | amPlatform | `GetOsVersion`/`GetPlatformId`/`GetBoardType`（値は FACTS Frida Hook 節） |
| 任意 | LAN 設定 | `IPHLPAPI: ConvertLengthToIpv4Mask` に [Network] 反映 |

COM フック対象 13 関数（GetProcAddress+MinHook）:
`CreateFileA/W, Get/SetCommState, Get/SetCommTimeouts, Get/SetCommMask, SetupComm, PurgeComm,
EscapeCommFunction, ClearCommError, GetCommModemStatus`

## TeknoParrot.dll 内部（参考）

teknoGod カスタムプロテクター（AES, エントロピー 8.00）、OEP は保護セクション内で静的逆コンパイル不可。
エクスポート: InitKonami / InitLinux / InitializeASI（VMProtect 風スタブ）。
静的インポート手がかり: d3d9!Direct3DCreate9, OPENGL32!glOrtho, WS2_32!inet_ntoa,
WINHTTP!WinHttpConnect, ntdll!NtQueryInformationProcess（OEP 計算）, IPHLPAPI!ConvertLengthToIpv4Mask。
自己検証: WINTRUST!WinVerifyTrust, PSAPI!EnumProcessModules, dbghelp!ImageNtHeader（GetProcAddress 動的解決）。

## 参照元（値・プロトコルの正）

> ⚠️ **segatools は参照しない**（鉄則#2: Nu/ALLS 世代で RingEdge とは別物、混同は誤実装）。
> JVS/JvsState/PCP は下表の RingEdge 系参照実装＋本プロジェクト実測を正とする。

| 機能 | ソース | 備考 |
|---|---|---|
| JVS フレーム/コマンド・IOCTL | `boot/amjvs/FACTS.md`（実測）＋ micetools `dll/drivers/`（`docs/micetools.md`） | columba 互換 IOCTL は teknoparrot.md §5 |
| PCP プロトコル | micetools `lib/libpcp/`（`docs/micetools.md` §3）＋ `docs/bsnk_ringedge.md` §1 | keyword/code 表が正準 |
| TeknoParrot_JvsState レイアウト | `docs/teknoparrot.md` §5（実行時フック実測、BBS は 8B） | byte0=0x01 固定=JVS-present |
| API フック | MinHook (TsudaKageyu) | BSD 2-Clause（帰属表示必要） |
