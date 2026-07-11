# app（ゲーム窓/プロセス）FACTS（co-located）

索引 `_index.md` / 横断知見 `workflow.md`。

- 窓化（QoL, `src/host/windowed.c`）[S 実装確認]: `ChangeDisplaySettings*A/W/ExA/ExW` を原関数非呼出で成功(0)化＝モード切替阻止。`CreateWindowExA/W` は `should_convert`(WS_POPUP かつ !WS_DISABLED かつ !(w==0&&h==0)) のフルスクリーン窓のみ `WS_POPUP→WS_OVERLAPPEDWINDOW(0x00CF0000)`＋`WS_EX_TOPMOST` 除去（＝枠付き・リサイズ可）。**client サイズ reshape/AdjustWindowRectEx/1024x600 強制は無い**（1024x600 は api.c の touch 座標スケール前提のみ）。
- self-shutdown 無力化（`src/logic/patches.c`）: 0x6C3F20 `je(0x74)→jmp(0xEB)`（je のときだけ）patch（下記「ルートシーン self-shutdown」）。
- 終了/exit ログは `src/host/exitlog.c`。

## present / 描画スレッド [S/L]（チラつき・オブジェクト点滅：解決済み）

固定機能 OpenGL + 専用レンダースレッド分離レンダリング。VA（名は doc-local、Ghidra DB 未登録）:
| static_VA | 名称 | 内容 |
|---|---|---|
| 0x801E80 | `render_thread_main` | 描画23パス(FUN_008026a0)→glFlush→`SwapBuffers(gl_hdc)`→`SetEvent(render_done_event)`→state CAS(ctx+0x20)→自己 SuspendThread（main が resume）|
| 0x89CB80 | `frame_present_main` | present+ペーシング。`wglSwapIntervalEXT(interval)`、`render_threaded_flag`!=0 で `WaitForSingleObject(render_done_event)`+spin、=0 で直接 SwapBuffers |
| 0x644A60 | `set_vsync_on` | `wglSwapIntervalEXT(1)` |
| globals | `gl_hdc`0x20F3E3C / `gl_hglrc`0x20F3E44 / `render_done_event`0x2254E1C / `render_threaded_flag`0x22548C8 / `wglSwapIntervalEXT_ptr`0x16F5388 | |

**根因確定 = ハイブリッド GPU クロスアダプタ読戻しストール**（vsync/DWM/窓は無罪＝実証済）。毎フレ `glReadPixels`/`glCopyTexSubImage2D`（自動露出等の FB 読戻し, `FUN_0060f480` 16x16 ほか）が dGPU 描画時 PCIe 越しで≈30ms→CPU-GPU 直列化→30fps・二重 present でロード画面点滅。**恒久対応 = nrs.exe を iGPU 固定**: `HKCU\Software\Microsoft\DirectX\UserGpuPreferences` に `<exe path>=GpuPreference=1;`（frame 36→8ms, stalls 150→0）。loader が起動前に書けば自動化可。
計装（撤去可）: `present.stats`/`present.swapblock`/`gl.info`(capture.c)・`pace.main`(gamehook.c)。env: `NRSEDGE_SWAP_INTERVAL`/`NRSEDGE_WINDOWED`。

## ログ集約

ゲーム本体ログ（amiDebug A/B 系統・生 stdio・SEH crash）は `src/host/dbglog.c` が窓/JSONL へ転送する（詳細 `amdebug.md`）。
人間は統合 GUI（`loader.exe`）のログタブ、自律は `loader.exe logs`。

## ルートシーン self-shutdown [S/F]

| static_VA | 内容 |
|---|---|
| 0x6C3F10 | ルートシステムシーンの毎フレーム callback（scene_list_init 0x89D690 が設定） |
| 0x6C3F20 | `je 0x6C3F41`→`jmp` に patch（self-shutdown 無力化、`src/logic/patches.c`） |
| 0x89E880 | `amApp_shouldShutdown` 判断（制御フラグ DAT_0227fe6c/fe70&4/DAT_02282a64 を読む） |
| 0x89DF40 | `amApp_shutdown_now` 無条件 shutdown（DAT_016f5aa0=1） |
| 0x644D40 | メインループ。DAT_016f5aa0!=0 で抜けて ExitProcess |
| 0x16F5AA0 | shutdown flag。0x16F5A9C = shutdown state |

amBackup/eeprom 成功でゲームが実機運用パスに進むと amApp_shouldShutdown が true→shutdown となるため、
0x6C3F20 の `je`→`jmp` patch で無力化する。詳細は `mxdrivers.md` の ENABLE_EEPROM 節。
