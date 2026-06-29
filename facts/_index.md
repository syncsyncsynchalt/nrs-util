# FACTS 索引

nrs.exe で確定した事実（アドレス/構造体/プロトコル）をサブシステム別に置く。
1 サブシステムの作業は当該ファイル閉で完結する（全読み不要）。**正は実装**＝値は使う前に
Ghidra(static_VA)／micetools／実走ログで裏取りする（`../CLAUDE.md` 鉄則）。

confidence 凡例: [S]=静的解析(Ghidra) [L]=ライブ実走確認 [I]=推論
[F]=旧 Frida 計装で確認（**履歴的来歴**。Frida は破棄済み＝再取得は Ghidra/実走で行う）

## 横断

- [workflow.md](workflow.md)：作業方法論・運用知見（自律ゲームテスト起動法 / 実体再導出 / パッチ監査 read-fake vs action-block / 静的パッチ clobber / パッチ削減の定石 / 日本語清書 / 脱 Python 移植）
- [bugs.md](bugs.md)：live bug / RISK / ANTI-PATTERN（解決済みは `git log`）
- [port_status.md](port_status.md)：旧 Frida 動的群を native で移植「しなかった」理由（serve-it / root-cause 静的化）

## サブシステム別

| subsys | facts | 主な native 実装 |
|---|---|---|
| amJvs / amJvsp（JVS over COM4） | [amjvs.md](amjvs.md) | `src/logic/driver/mxjvs.c` `input.c` ＋ `api.c` |
| 周辺デバイス presence・COM map（touch/card/dipsw） | [devices.md](devices.md) | `src/logic/patches.c` `driver/touch.c` ＋ `api.c` |
| mx ドライバ層 / amBackup（columba/mxsram/mxsmbus eeprom） | [mxdrivers.md](mxdrivers.md) | `src/logic/driver/mxdevices.c` ＋ host `on_set_file_pointer` |
| keychip / PCP | [mxkeychip.md](mxkeychip.md) | `src/host/keychip_server.c` ＋ `patches.c`（region） |
| amNet（DHCP/NIC/ALL.Net 接続段） | [mxnetwork.md](mxnetwork.md) | `src/logic/patches.c` |
| amlib SYSTEM STARTUP | [mxsegaboot.md](mxsegaboot.md) | `src/logic/patches.c` |
| amPlatform（platform id / os version） | [amplatform.md](amplatform.md) | `api.c`（columba DMI / 仮想 SystemVersion.txt） |
| amGfetcher（get_status） | [mxgfetcher.md](mxgfetcher.md) | `keychip_server.c`（40113 serve-it） |
| ALL.Net Plus Billing（alpbEx） | [ambilling.md](ambilling.md) | `src/logic/patches.c`（stub→5） |
| storage presence | [mxstorage.md](mxstorage.md) | `src/logic/patches.c` |
| amDongle | [amdongle.md](amdongle.md) | `src/logic/patches.c` |
| amRtc | [amrtc.md](amrtc.md) | `gamehook.c` ＋ `api.c on_rtc_get` |
| amDebug ロギング | [amdebug.md](amdebug.md) | `src/host/dbglog.c` |
| ゲーム窓 / self-shutdown | [app.md](app.md) | `src/host/windowed.c` ＋ `patches.c` |

## 外部オラクル・ツール

- 外部オラクル（micetools / TeknoParrot / RingEdge 純正イメージ）の所在 → `../ref.md`
- 関数名/型の正（Ghidra へ適用） → `../data/known_names.json`
- 静的解析 = Ghidra MCP（`mcp__ghidra__*`, static_VA）。起動 `tools/ghidra_mcp/start_headless.ps1`
