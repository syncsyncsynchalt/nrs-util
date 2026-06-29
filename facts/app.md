# app（ゲーム窓/プロセス）FACTS（co-located）

索引 `_index.md` / 横断知見 `workflow.md`。

- 窓化（QoL, `src/host/windowed.c`）: フルスクリーン抑止・1024x600 固定窓化。`ChangeDisplaySettings*` をブロックし、
  `CreateWindowExA/W` の dwStyle から `WS_POPUP`/`WS_THICKFRAME`/`WS_MAXIMIZEBOX` を除去して
  `WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX`(0x00CA0000) を強制（リサイズ/最大化不可）。
  `AdjustWindowRectEx` で client=1024x600（RingEdge HW 仕様）の外寸を逆算し w/h を上書き。
- self-shutdown 無力化（`src/logic/patches.c`）: 0x6C3F20 je→jmp patch（下記「ルートシーン self-shutdown」）。
- 終了/exit ログは `src/host/exitlog.c`。

## ログ集約

ゲーム本体ログ（amiDebug A/B 系統・生 stdio・SEH crash）は `src/host/dbglog.c` が窓/JSONL へ転送する（詳細 `amdebug.md`）。
人間は統合 GUI（`loader.exe`）のログタブ、自律は `loader.exe logs`。旧 Frida launcher（`launch.py` の frida `send`→print）は破棄済み。

## ルートシーン self-shutdown [S/F]

| static_VA | 内容 |
|---|---|
| 0x6C3F10 | ルートシステムシーンの毎フレーム callback（scene_list_init 0x89D690 が設定） |
| 0x6C3F20 | `je 0x6C3F41`→`jmp` に patch（self-shutdown 無力化、`src/logic/patches.c`） |
| 0x89E880 | `FUN_0089e880` shutdown 判断（制御フラグ DAT_0227fe6c/fe70&4/DAT_02282a64 を読む） |
| 0x89DF40 | `FUN_0089df40` 無条件 shutdown（DAT_016f5aa0=1） |
| 0x644D40 | メインループ。DAT_016f5aa0!=0 で抜けて ExitProcess |
| 0x16F5AA0 | shutdown flag。0x16F5A9C = shutdown state |

amBackup/eeprom 成功でゲームが実機運用パスに進むと FUN_0089e880 が true→shutdown となるため、
0x6C3F20 の `je`→`jmp` patch で無力化する。詳細は `mxdrivers.md` の ENABLE_EEPROM 節。
