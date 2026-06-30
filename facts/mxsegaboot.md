# amlib SYSTEM STARTUP FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。索引 `_index.md` / 横断知見 `workflow.md`。
confidence: [S]=静的解析 [L]=ライブ実走 [I]=推論 [F]=旧 Frida 計装(履歴・再取得は Ghidra/実走)

---

## ★Boot = amlib SYSTEM STARTUP シーケンス `FUN_0089a010` (RVA 0x49a010) [S+F]

ブートは画面に "SYSTEM STARTUP" を出し、`FUN_0089a010`(`param_1+4`=state, `+8`=substate)が各段階を順に
チェックする。実写で各 state の結果("CHECKING X ... OK/NG/NA")が見える。**これを全て満たすとゲームが
ATTRACT 起動する**。

| state | 画面 | チェック関数 | 満たし方(satisfy) | 実装 |
|---|---|---|---|---|
| 2 | CHECKING IC CARD R/W | `FUN_004f6310`(ready bit1)/`FUN_004f6330`(err bit4), dev type 0x21 | ready→1（ready が立てば通過、err bit は不参照） | `patches.c`(0x4F6310 / `devices.md`) |
| 3 | CHECKING TOUCH PANEL | `FUN_008b3b00`(resp)/`FUN_008b3b40`(err), dev type 0x22 | resp→1（resp が立てば通過、err bit は不参照） | `patches.c`(0x8B3B00 / `devices.md`) |
| 4 | CHECKING NETWORK | network flags `DAT_0210b50a/b/c`(`FUN_006ff140`) + deviceMgr+0x1ec | b50c=LAN(IP一致). 早期 init 0→1 | `patches.c`(0x6FF1B3 b50c が &0x5f3 の gate / 0x72DCE0, `mxnetwork.md`) |
| 5 | CHECKING EXTEND IMAGE | substate1 `DAT_01601b23`(image-present gate) / `extend_image_install_status`(0x72b3a0) / `FUN_004fda50`(is-DVD-boot) | **gate=1 で "OK" skip→state6**（install 不実行）＋ DVD-boot→0 | host gamehook `d_extimg_gate_probe`(gate=1 force, primary) ＋ `d_ext_install_kick`(install_ctx 完了 provision, fallback) / `patches.c`(0x4FDA50, `mxstorage.md`)。旧 0x72B3A0 静的パッチ(P_extimg)撤去済（下記★）。⚠️両 gamehook を消すと "EXTEND IMAGE … NG / INSTALLING … WAITING"。**BOOT_DONE(HLSM `FUN_00457FE0`) は SYSTEM STARTUP SM と別物**でこの停止を検出できない |
| 6 | CHECKING CONNECTION (ALL.NET AUTH/UPLOAD/GAME SERVER/LOCAL) | `FUN_0072dce0`(server status, deviceMgr+0x1d4[1..4]) | status≠1(resolved)に保持(=2 ready 固定) | `patches.c`(0x72DCE0, `mxnetwork.md`) |
| 7 | INITIALIZING P-ras | `FUN_00701280` = `b611!=0 \|\| b610==0`(billing-ready/offline) | →true 強制(FreePlay) | `patches.c`(0x701280) |
| 8→10 | (DONE) | `FUN_0089de10` | — state10 で SYSTEM STARTUP 完了 → ATTRACT | — |
| 9 | ERROR | — | errCode を立て error scene(0903 等) | 回避=各 state を満たす |

- 各 device-wait substep は `(probe_ready() \|\| probe_err())` が真になるまで待つ＝デバイス無応答だと hang。
  ready 述語を 1、error 述語を 0 にする(`23/26`)か、状態を resolve する(`30/31/32`)。
- **region 0903**: state を進めると、keychip setup 前の早期に dongle region(`DAT_01601989`)=0 で errCode4 → sticky
  "0903 Wrong Region" シーンが表面化する。`08` で `DAT_01601989=0x01` を**早期から**強制して回避。
- **"Error 0949 Keychip Not Found" の正体**: keychip presence(`FUN_0096c5d0`=ctx+4&&ctx+8)は安定 1。0949 は
  state5(EXTEND IMAGE)install 失敗時の終端表示。keychip 問題ではない。
- ⚠️ **検証鉄則**: errNo=0 等のログだけでクリーン判断しない。必ず実写（統合 GUI のスクリーンショット等）で確認。

---

## ★EXTEND IMAGE (state5) = ALL.Net 配信 install タスク → host gamehook で「導入済み」境界供給 [S]

state5「CHECKING EXTEND IMAGE」の正体 = **ALL.Net 経由の extend-image install**（解像度や DVD とは別系統）。
- **install_ctx = `devMgr+0x258`**（`amlib_device_manager_ptr` 0x72b450 が返す devMgr の +0x258 = `field[0x96]`）。
  実体は **NetworkTask**（`NetworkTask_ctor` 0x72b490 が `NetworkTask::vftable`/`SvrTaskMng`/`NetForm_GameServerStatus` を構築し
  `puVar1[0x96]=0` で install state を 0 初期化）。トリガフラグは install_ctx+0x15/+0x16(=devMgr+0x26d/0x26e)。
- **getter `extend_image_install_status`(0x72b3a0)** = `__fastcall(ECX, EDX=install_ctx)`。state→status マップ:
  state 1–6→**1**(Install Waiting) / 7–10→**2**(Installing %、`*EDI=param_2[0xd]`) / 0xb→**3**(Completed) / 0xc→**4**(done、`*ESI=param_2[0xb]`=devMgr+0x284=install error)。
- **boot SM 消費（state5 substate2→3 は同 tick fall-through, disasm 0x89a4c8 kicker→0x89a4eb 読取）**:
  `extend_image_install_begin`(0x72eaf0, install kicker＝substate2 の唯一 caller)が devMgr+0x26d/0x26e=1 を立てて install 開始 →
  fall-through した substate3 が getter を呼ぶ → **return>3(==4) なら `+0x1c=*ESI`(install error)→substate100: error==0→state6 前進 / error≠0→errCode latch→state9**。
- **OK/NG 文字列**（実体・state2/3 で極性確証）: `0xc43524`="OK" / `0xb953fc`="NG"。getter 経由で attract に抜ける唯一路は
  **state 0xc(=Install Error, FUN_008a5ed0 が case4="Install Error" と命名)+error0**で、done 経路が `0xb953fc`="NG" を出す＝旧 `P_extimg`/初回 gamehook の
  「EXTEND IMAGE NG だが前進」の正体（STATUS の「NG は正常」）。state 0xb(=Completed) は `FUN_0089ccb0`=**REBOOT**、state1-6→Waiting/7-10→Installing% は loop。
- **★image-present gate `DAT_01601b23`（substate1 の唯一 OK 路）**: `keychip_appdata_delete_gate_probe`(0x45a8f0, `amlib_master_init` 0x45907e/88 から call＝
  SYSTEM STARTUP SM より前)が extend-image/appdata ファイルの存在(`__stat64i32`)＋検証(`FUN_00969a00`)で立てる本物の gate（"delete" 名は誤導、実体は
  **image-present＝install skip**）。≠0 なら substate1 が "CHECKING EXTEND IMAGE … **OK**"→substate100(error0)→state6（INSTALLING 行なし・install 完全 skip）。
  state1 case1 で gate≠0 は extended リソース再ロード(`FUN_007416e0` 列＝glColorMask 等の resource reload, bounds-check 付き graceful)を誘発＝image-present 時の genuine 挙動。
- **純正化（patches 16→15, P_extimg 撤去, ライブ実証スクショ確認）**:
  - **primary**: host gamehook `d_extimg_gate_probe`（probe 0x45A8F0 POST）が `DAT_01601b23=1` を force → EXTEND IMAGE **OK** skip。TP の extend-image 提供と等価。
  - **fallback（多層防御）**: `d_ext_install_kick`（`extend_image_install_begin` 0x72eaf0=install kicker, boot SM 唯一 caller を POST）が install_ctx
    (devMgr+0x258) に state=0xc/error(devMgr+0x284)=0 を provision＝万一 gate 経路を通らず install 試行に入っても "NG"だが state6 前進（旧 P_extimg 相当）。
  - 実証: SYSTEM STARTUP **全行 OK**（EXTEND IMAGE OK・NG/INSTALLING 行ゼロ）・errors=0・attract 到達。
- **真の genuine 化（実 install SM 完走＝実配信）は ALL.Net 層エミュ＝Phase B2 前提**。回帰時は gamehook 2 本撤去＋`patches.c` の P_extimg(0x72B3A0→return4) 復活で即フォールバック可。

---
