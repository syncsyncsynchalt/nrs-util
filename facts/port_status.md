# 旧 Frida 実装 → native 移植トラッキング（欠落ゼロの台帳）

旧 `boot/*` 全モジュール（git 履歴）を native へ移植。**monitor(diag) は RE 観測専用で boot 不要**＝対象外。
正準は git の旧モジュール内容。✅=移植済(ビルド通過) / ⏳=未移植 / —=対象外。

| 旧モジュール | persistence | native 移植先 | 状態 |
|---|---|---|---|
| lib/base.js | na | host(va 計算)/patches.c | ✅ 概念移植 |
| devices/presence.js | persistent | patches.c（IC card/touch/USB/dipsw byte2,3=board index） | ✅ |
| mxstorage/presence.js | persistent | patches.c（is-DVD-boot→0） | ✅ |
| mxsegaboot/startup.js | persistent | patches.c（extend_image_status/P-ras ready） | ✅ |
| mxnetwork/state.js | persistent+serve | patches.c（LAN flag/device status→2） | ✅ |
| ambilling/status.js | persistent | patches.c（alpbExGetExecStatus→5） | ✅ |
| amjvs/state.js | persistent | patches.c（JVS forgery + node 初期化 data write） | ✅ |
| amdongle/patch.js | persistent | patches.c（amDongleBusy→0 / state4 helper→0） | ✅ |
| mxkeychip/region.js | runtime | patches.c（region jne→nop / jl→jmp / errCode store nop / region=JAPAN） | ✅ 静的4層。watchdog/re-force は root-cause 静的化で代替・対象外（下記） |
| mxgfetcher/getstatus.js | runtime | patches.c（FUN_006ff980→ret1 + JL2JMP 0x97588A/0x97595F/0x975A1F）他 patchCode | ✅ serve-it で代替（下記）。旧の fake-it 群は原則不要 |
| **amplatform/identity.js** | persistent | patches.c（GetPlatformId="AAL" / GetOsVersion="WindowsXP" 静的 patchCode） | ✅ |
| **amrtc/rtc.js** | runtime | gamehook.c d_rtc_get + api.c on_rtc_get（abi v2） | ✅ 移植（ビルド/ctest通過・実機未検証）。amRtcGetServerTime(0x974040, **__stdcall longlong**(timeStructOut, dstFlagOut), 失敗 -1)→only-on-failure で GetLocalTime フォールバック。SetServerTime(0x9742C0)は未実装（cosmetic・呼ばれない見込み）|
| **mxdrivers/devices.js** | runtime | `src/logic/driver/mxdevices.c`（columba DMI=RINGEDGE2 / mxsram / mxsuperio HWMON W83791D / mxsmbus AT24C64AN eeprom / mxhwreset。CreateFile→擬似h、DeviceIoControl→各応答） | ✅ 移植（eeprom/sram は in-mem・実機未検証）|
| mxkeychip/setup.js | runtime | on_keychip_hold（game-fn hook 0x6F0A80, present flag 保持） | ✅（server 前提で発火）|
| **mxkeychip/server/pcpa_server.py** | serve | `src/host/keychip_server.c`（winsock 7 ポートサーバ・認証バイパス code=54・mxmaster/amNet/billing 応答。host 常駐 reload-safe） | ✅ 移植（ビルド通過・実機未検証）|
| mxkeychip/client.js | serve | keychip_server.c（全7ポート bind） | ✅ serve-it で代替・対象外（下記）。接続拒否が無い→負戻り無し→回復 hook 不要 |
| **mxgfetcher/recv.js** | runtime | keychip_server.c（40113 応答） | ✅ serve-it で代替（下記）。recv 完了の動的強制は不要 |
| **app/no_selfshutdown.js** | persistent | patches.c（je→jmp、条件付き） | ✅ |
| app/windowed.js | runtime | `src/host/windowed.c`（ChangeDisplaySettings ブロック + CreateWindowEx WS_POPUP 除去） | ✅ |
| app/exit.js | monitor | — | — 診断専用・不要 |
| **amjvs/input.js**（未追跡・削除済/内容把握） | runtime | on_jvs_tick(node-BSS-write)+on_sys_override(TEST/SERVICE), game-fn hook 経由 | ✅ 移植（ビルド通過・実機未検証）|
| **amjvs/freeplay.js**（未追跡・削除済/内容把握） | runtime | on_jvs_tick 内で per-frame に 0x128855A=1（init 済時） | ✅ |
| **amdebug/diag.js** | monitor | patches.c（logLevel/logMask 開放）+ `src/host/dbglog.c`（sink 0x55C800 + amDebugOut 0x55C7E0 hook→host ログ転送） | ✅ 移植（ゲーム本体ログを窓へ復活。一度 "不要" 除外→ログ量激減の回帰を解消）|
| *_diag.js（amdongle/mxkeychip/mxnetwork/mxgfetcher） | monitor | — | — RE 観測専用・不要 |

## 移植済の本質（patches.c で再現した旧 impl 静的部分）
ambilling/amdongle/amjvs(forgery)/devices(board index 0xa/0xb 解消, touch/card presence)/mxnetwork/
mxsegaboot/mxstorage/region/mxgfetcher(gate) の**全静的パッチ + node/region データ書込み**を
`patches_apply()` が bind 時に nrs.exe へ適用。**旧 impl の「attract 到達」静的基盤を native で再現**。

## mxgfetcher get_status: fake-it → serve-it（2026-06-28 Ghidra 再解析で確定）

旧 getstatus.js/recv.js の動的群は **native では移植不要**。理由は戦略が異なるため:

- 旧 Frida = **fake-it**: ストリーム不在前提で、パーサ群(0x9746C0/974760/9747A0/975140)を `xor eax,eax;ret`、
  0x9744F0 を hang-safe スタブ、0x98ADC0+recv で完了を動的強制し SM を騙す。
- 新 native = **serve-it**: HLSM(0x457FE0) の state5/6/9 と FUN_009744f0/975830/975a70/975700 は全て
  **`DAT_01286ff0`（PCP ストリームptr）依存**。唯一の WRITE = `FUN_009743f0`(amGfetcherInit) で
  **127.0.0.1:0x9cb1(=40113)** 接続成功時に `=1`。`keychip_server.c` が 40113 を bind 済 → 本物の
  get_status 交換で SM が自然前進。`patches.c` は 0x6FF980→ret1（state0 gate）+ JL2JMP 3 個のみで足りる。

実機裏取り（未）: 起動ログで `DAT_01286ff0==1`（40113 接続成立）と HLSM state9→next=0（attract 到達）を確認。
**フォールバック**: 実機で 40113 接続が失敗し state5 が get_status を無限リトライ（→ "Error 1000" watchdog）する場合のみ、
旧 fake-it 群（上記 4 パーサ→`33 C0 C3`、0x9744F0 hang-safe、0x975857→`EB 06`）を patches.c へ移植。

## region 条件 hook / keychip client: root-cause 静的化で代替（2026-06-28 Ghidra 再解析で確定）

**region.js watchdog/re-force → 対象外。** master errCode `DAT_016f5af0` には ~14 writer
（FUN_004591b0/0045a7f0/amlib_reset_init/amlib_master_init/0045a320/0045a6f0/storage_board_check/
backup_check_err0x18/alpbEx_billing_poll/008b2e00/init_sm_SYSTEM_STARTUP×4/usbio_errCode_mapper/
keychip_errCode1_latcher）。旧は 250ms watchdog で反応的全クリア。native は各源を root-cause で潰す
（region NOP / AAL platform / board index dipsw / USB I/O imm / is-DVD→0 / billing→5 / segaboot / keychip-hold）。
`PcbRegion`(0x16014C4) は binary 内 writer 無し（全 xref READ）→ bind 時 data-write 永続 ＝ re-force hook 冗長。
attract 実機到達がカバレッジを実証。残存 setter が実機で発火したら **その setter を個別 root-cause パッチ**
（watchdog 移植はアンチパターン＝どのチェックが落ちたか隠す）。

**client.js → 対象外。** pcpaOpenClient(0x98AEA0) は connect→pcpa_recv_poll() 結果を返す。負戻りは
stream/IP=null か接続拒否時のみ。`keychip_server.c` が全7ポート(40100–40113) bind 済 → 接続拒否なし →
負戻りなし → 回復 hook(orig<0→0) 不要。

## 残り（動的サブシステム）
1. ~~host の game-function hook 機構~~ **✅ 整備済**（`src/host/gamehook.c`, reload-safe: detour=host／logic=g_api 経由）。
   これで input(node-write)=移植済。rtc 動的が同型で移植可。
   （getstatus 動的・region 条件 hook・client は serve-it/root-cause 静的化で代替確定＝対象外。上記節参照）
2. ~~keychip(PCP)~~ **✅ keychip_server.c に移植**（実機未検証）。
3. **mxdrivers**（smbus/columba/drive/eeprom/sram の DeviceIoControl）を logic（on_create_file/on_device_iocontrol）へ ← **残る最大の動的**。
4. rtc / amplatform identity / freeplay / app(exit,windowed) — game-fn hook or 簡易移植。
   （getstatus 動的は serve-it で代替確定＝対象外。上記 mxgfetcher 節参照）
5. 上記は**実機 nrs.exe 起動でのログ確認**が最終裏取り（このサンドボックスでは GPU/安全性ゆえ不可）。
