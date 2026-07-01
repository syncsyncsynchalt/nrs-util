# app（ゲーム窓/プロセス）FACTS（co-located）

索引 `_index.md` / 横断知見 `workflow.md`。

- 窓化（QoL, `src/host/windowed.c`）: フルスクリーン抑止・1024x600 固定窓化。`ChangeDisplaySettings*` をブロックし、
  `CreateWindowExA/W` の dwStyle から `WS_POPUP`/`WS_THICKFRAME`/`WS_MAXIMIZEBOX` を除去して
  `WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX`(0x00CA0000) を強制（リサイズ/最大化不可）。
  `AdjustWindowRectEx` で client=1024x600（RingEdge HW 仕様）の外寸を逆算し w/h を上書き。
- self-shutdown 無力化（`src/logic/patches.c`）: 0x6C3F20 je→jmp patch（下記「ルートシーン self-shutdown」）。
- 終了/exit ログは `src/host/exitlog.c`。

## present / 描画スレッド [S/L]（チラつき・オブジェクト未描画の真因）

ゲームは固定機能 OpenGL（glBegin/glEnd・display list）+ **専用レンダースレッドの分離レンダリング**。

| static_VA | 名称 | 内容 |
|---|---|---|
| 0x801E80 | `render_thread_main` | レンダースレッドのループ。毎フレ: 描画23パス(FUN_008026a0)→glFlush→`SwapBuffers(gl_hdc)`→`SetEvent(render_done_event)`→InterlockedCompareExchange(state@ctx+0x20)→**自己 SuspendThread**。main が resume |
| 0x89CB80 | `frame_present_main` | メイン present+ペーシング。`(*wglSwapIntervalEXT_ptr)(interval)` で vsync 設定（`swap_interval_cur/min` クランプ）、`render_threaded_flag`!=0 で `WaitForSingleObject(render_done_event)`+spin、=0 で直接 SwapBuffers |
| 0x644A60 | `set_vsync_on` | `wglSwapIntervalEXT(1)` |
| globals | `gl_hdc`0x20F3E3C / `gl_hglrc`0x20F3E44 / `render_done_event`0x2254E1C / `render_threaded_flag`0x22548C8 / `wglSwapIntervalEXT_ptr`0x16F5388 | |

**真因（2026-07-01 実測で確定）= Optimus/ハイブリッド GPU のクロスアダプタ読戻しストール**。
症状: チラつき・オブジェクト点滅（特にロード画面で激しい点滅）。`src/host/capture.c`+`gamehook.c` の計装で段階的に局在化:
- present.stats: avg≈16.6ms だが 300 中 stalls(>25ms)≈150 + doubles(<8ms)≈150＝`[~0µs,~33ms]`交互ビート＝実効 30fps・2 回 present（1 枚は捨てられる）。ロード画面は片バッファにしか絵が無く点滅。
- **vsync/DWM/窓は無罪**（実証）: vsync 強制 OFF(`NRSEDGE_SWAP_INTERVAL=0`)でも fullscreen(`NRSEDGE_WINDOWED=0`)でも 150/150 ビート不変。`present.swapblock` で **SwapBuffers 自体は速い**（run 全体で >20ms は 1 回のみ）と確認。
- pace.main 計時: **36ms の per-frame は丸ごと `FUN_006c3930`(present 駆動=`frame_present_main` の `WaitForSingleObject(render_done_event)` 待ち)**。scene dispatch は 0.17ms。⇒ レンダースレッドの 23 パス描画(GPU)が 36ms。
- **GPU 切替で確定**: `gl.info`=NVIDIA dGPU で frame=36ms/stalls=150。**`nrs.exe` を iGPU(AMD) に固定(GpuPreference=1)すると frame=8ms/stalls=0**＝4.5 倍速・ビート完全消失。機構=毎フレーム `glReadPixels`/`glCopyTexSubImage2D`(自動露出/輝度等のフレームバッファ読戻し: `FUN_0060f480`16x16 ほか)が、dGPU で描くと PCIe 越し読戻し≈30ms に化け CPU-GPU 直列化。表示出力を持つ iGPU なら読戻しが安く 8ms。TP が windowed でも綺麗なのは iGPU 経路ゆえ。
- **恒久対応**: `nrs.exe` を iGPU 固定。HKCU\Software\Microsoft\DirectX\UserGpuPreferences の `<exe path>=GpuPreference=1;`（1=省電力/iGPU）。loader が起動前にこのキーを書けば in-project 自動化可。
- 計装（確認後は間引き/撤去可）: `present.stats`/`present.spike`/`present.swapblock`/`gl.info`(capture.c) ・`pace.main`(gamehook.c d_frametick/d_present_drive/d_scene_dispatch)。env レバー `NRSEDGE_SWAP_INTERVAL`/`NRSEDGE_WINDOWED`。

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
