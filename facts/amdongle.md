# amDongle FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。横断定数は `../ARCH.md`、索引は repo ルート `FACTS.md`。
confidence: [F]=Frida確認 [S]=静的解析 [I]=推論

---

### bypassAmDongle IIFE (`boot/amdongle/patch.js`)（persistent）

| 種別 | static_VA | Function | 内容 |
|---|---|---|---|
| patchCode | 0x975E00 | amDongleBusy | `xor eax,eax; ret`（永続。"not busy" 固定。outerSM even-state 前進に必須） |
| patchCode | 0x457AF0 | keychipSM case4 が呼ぶ appdata 再帰削除（FindFirstFile/DeleteFile/RemoveDirectory） | entry→`xor eax,eax; ret 8`（standalone で appdata 削除を skip）。**__thiscall・stack 引数 8B**（call site 0x4579F4 は add esp 無し＝callee clean＝本来 `ret 8`）。⚠ bare `ret`(旧 RET0) は 8B スタック破壊で発火時クラッシュ＝2026-06-28 修正。発火は `DAT_016014b0==0 && DAT_01601b23!=0 && DAT_016014af==0` のみ（clean boot 非発火）。旧「auth/DLL クラッシュ helper」は誤帰属で訂正 |

keychip が pcpa_server.py で genuine satisfy するため、amDongleBusy のみ維持する
（PCPA async layer の recv-completion gap を埋める TP 相当の assert）。
⚠ 0x975E00 は `amdongle/diag.js` も観測 hook する衝突番地 → load 順は diag.js の後を維持（順序依存）。


## hookAmDongle Monitor static_VA (`boot/amdongle/diag.js`、log only, no modification)

am* getter（無改変ログ）:

| static_VA | Function |
|---|---|
| 0x96EEC0 | amDongleGetGameId |
| 0x96F1A0 | amDongleGetRegion |
| 0x96EFC0 | amDongleGetSystemFlag |
| 0x96F290 | amDongleGetVersion |

dongle/keychip ステートマシン（無改変ログ）:

| static_VA | Function |
|---|---|
| 0x457500 | amDongle_top_level_init |
| 0x457810 | outerSM_tick_dispatcher |
| 0x457822 | outerSM_6state_FSM |
| 0x457910 | keychipSM_FSM |
| 0x978450 | amDongle7_dispatcher (reads [CCF0EC]+0x18) |
| 0x975E00 | amDongleBusy（patch.js でも patchCode 済み＝衝突番地） |

keychipSM expected flow: state0→state1→state2→state3→state4→state5→state6→state7(done)

---
