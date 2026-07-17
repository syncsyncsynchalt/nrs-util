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
| 2 | CHECKING IC CARD R/W | `FUN_004f6310`(ready bit1)/`FUN_004f6330`(err bit4), dev type 0x21 | ready→1（ready が立てば通過、err bit は不参照） | genuine device emu（check 0x4F6310 / `devices.md`。patches.c 不介入） |
| 3 | CHECKING TOUCH PANEL | `FUN_008b3b00`(resp)/`FUN_008b3b40`(err), dev type 0x22 | resp→1（resp が立てば通過、err bit は不参照） | genuine device emu（check 0x8B3B00 / `devices.md`。patches.c 不介入） |
| 4 | CHECKING NETWORK | network flags `DAT_0210b50a/b/c`(`FUN_006ff140`) + deviceMgr+0x1ec | b50c=LAN(IP一致). 早期 init 0→1 | genuine ALL.Net（旧 patch 0x6FF1B3 b50c gate / 0x72DCE0 は撤去済, `mxnetwork.md`） |
| 5 | CHECKING EXTEND IMAGE | substate1 `DAT_01601b23`(image-present gate) / `extend_image_install_status`(0x72b3a0) / `FUN_004fda50`(is-DVD-boot) | **gate=1 で "OK" skip→state6**（install 不実行）＋ DVD-boot→0 | host gamehook `d_extimg_gate_probe`(gate=1 force, primary) ＋ `d_ext_install_kick`(install_ctx 完了 provision, fallback) / `patches.c`(0x4FDA50, `mxstorage.md`)。⚠️両 gamehook を消すと "EXTEND IMAGE … NG / INSTALLING … WAITING"。**BOOT_DONE(HLSM `FUN_00457FE0`) は SYSTEM STARTUP SM と別物**でこの停止を検出できない |
| 6 | CHECKING CONNECTION (ALL.NET AUTH/UPLOAD/GAME SERVER/LOCAL) | `FUN_0072dce0`(server status, deviceMgr+0x1d4[1..4]) | status≠1(resolved)に保持(=2 ready 固定) | genuine ALL.Net host `allnet.c`（旧 patch 0x72DCE0 は撤去済, `mxnetwork.md`） |
| 7 | INITIALIZING P-ras | `FUN_00701280` = `b611!=0 \|\| b610==0`(billing-ready/offline) | →true 強制(FreePlay) | billing stub 0xA065C0=8 が ready を自成立させ通過（旧 0x701280 patch 撤去済, `ambilling.md`） |
| 8→10 | (DONE) | `FUN_0089de10` | — state10 で SYSTEM STARTUP 完了 → ATTRACT | — |
| 9 | ERROR | — | errCode を立て error scene(0903 等) | 回避=各 state を満たす |

- 各 device-wait substep は `(probe_ready() \|\| probe_err())` が真になるまで待つ＝デバイス無応答だと hang。
  ready 述語を 1、error 述語を 0 にする(`23/26`)か、状態を resolve する(`30/31/32`)。
- **region 0903**: state を進めると、keychip setup 前の早期に dongle region(`DAT_01601989`)=0 で errCode4 → sticky
  "0903 Wrong Region" シーンが表面化する。`08` で `DAT_01601989=0x01` を**早期から**強制して回避（※現行 genuine 化では data-write force は撤去済＝keychip PCP `appboot.region` 供給に置換。`mxkeychip.md` region 節/line 88）。
- **"Error 0949 Keychip Not Found" の正体**: keychip presence(`FUN_0096c5d0`=ctx+4&&ctx+8)は安定 1。0949 は
  state5(EXTEND IMAGE)install 失敗時の終端表示。keychip 問題ではない。
- ⚠️ **検証鉄則**: errNo=0 等のログだけでクリーン判断しない。必ず実写（統合 GUI のスクリーンショット等）で確認。

- **各チェックの JSONL 観測 `boot.check`/`boot.state`（host gamehook `d_boot_sm`, `gamehook.c`）**: SM `0x89a010`(__cdecl, 末尾 RET)を
  POST フックし state(mgr+4)/sub-index(mgr+0x14) 遷移を read-only 観測。前進=OK / →state9=NG(+errCode)。
  `boot.state{from,to,state}` は**全遷移の生トレース**で画面にチェック行が出ない state（0=init/8=COMPLETE/10=done, エラー時9）も残す。
  **state1(appdata-reload) は case0 からの fall-through** で 0→1→2 が同一呼出内に起き休止 state にならない＝観測不能（trace は `0→2`）。
  ラベルは実文字列定数（state=`0xC811A0..`、CONNECTION sub=char* 配列 `0xCF5464[idx]`）を実行時読取。
  結果 OK/NG は state 遷移方向、EXTEND IMAGE は gate `0x1601b23`、CONNECTION sub は getter 値(`deviceMgr+0x1d4+idx*4`, 2=OK/3=NG/0=NA/1=待機)。
  実写と byte 一致で検証済（IC CARD/TOUCH/NETWORK/EXTEND=OK, AUTH=OK/UPLOAD=NG/GAMESERVER=NG/LOCAL=OK, P-ras=OK, boot.complete）。
- **CONNECTION(state6) の sub-index は 1 始まり**（substate0 が `[mgr+0x14]=ESI=1` で初期化）: 配列 `0xCF5464[0]`="INITIALIZING"(P-ras 用・CONNECTION 未使用)、
  `[1]`=ALL.NET AUTH / `[2]`=ALL.NET UPLOAD / `[3]`=ALL.NET GAME SERVER / `[4]`=LOCAL GAME SERVER。idx0 を解決扱いすると偽の "INITIALIZING" 行が出る（要 `idx>=1` ガード）。

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
- OK/NG 文字列: `0xc43524`="OK" / `0xb953fc`="NG"（state2/3 で極性確証）。getter 経由 attract 唯一路= **state 0xc(=Install Error, `FUN_008a5ed0` case4)+error0**（done 経路が "NG" を出す＝旧「NG だが前進」の正体）。state 0xb(=Completed)=`FUN_0089ccb0`=REBOOT、state1-6→Waiting/7-10→Installing% は loop。
- **★image-present gate `DAT_01601b23`（substate1 の唯一 OK 路）**: `keychip_appdata_delete_gate_probe`(0x45a8f0, `amlib_master_init` 0x45907e/88 から call＝SYSTEM STARTUP SM より前) が extend-image/appdata ファイル存在(`__stat64i32`)＋検証(`FUN_00969a00`)で立てる（"delete" 名は誤導＝image-present=install skip）。≠0→substate1 "…**OK**"→substate100(error0)→state6（INSTALLING 行なし）。gate≠0 で state1 case1 は extended リソース再ロード(`FUN_007416e0` 列, graceful)。
- **純正化（host gamehook, P_extimg 静的パッチ撤去）**: primary= `d_extimg_gate_probe`(probe 0x45A8F0 POST) が `DAT_01601b23=1` force→OK skip。fallback= `d_ext_install_kick`(`extend_image_install_begin` 0x72eaf0 POST) が install_ctx(devMgr+0x258) に state=0xc/error(devMgr+0x284)=0 provision（install 試行に入っても NG だが state6 前進）。
- 実 install 完走(実配信)は ALL.Net 層エミュ=Phase B2。回帰時は gamehook 2 本撤去＋`patches.c` P_extimg(0x72B3A0→return4) 復活で即フォールバック。

---
