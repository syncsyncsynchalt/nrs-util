# amDongle — FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。横断定数は `../ARCH.md`、索引は repo ルート `FACTS.md`。
confidence: [F]=Frida確認 [S]=静的解析 [I]=推論

---

### bypassAmDongle IIFE (`boot/amdongle/patch.js`)

| 種別 | RVA | Function | 内容 |
|---|---|---|---|
| patchCode | 0x575E00 | amDongleBusy | `xor eax,eax; ret`（永続。"not busy" 固定。outerSM even-state 前進に必須。commit 7f69740 で onLeave→patchCode 化） |

Phase A (2026-06-12) 確定: keychip が pcpa_server.py で genuine satisfy 済みのため 5 SM action 関数
(0x578590/0x5784F0/0x5788A0/0x578640/0x5786F0) の force-0 は冗長と実機ラン2回で確定し削除済。
amDongleBusy のみ維持（PCPA async layer の recv-completion gap を埋める TP 相当の assert）。


## hookAmDongleSM Monitor RVAs (log only, no modification)

| RVA | Function |
|---|---|
| 0x057500 | amDongle_top_level_init |
| 0x057810 | outerSM_tick_dispatcher |
| 0x057822 | outerSM_6state_FSM |
| 0x057910 | keychipSM_FSM |
| 0x578450 | amDongle7_dispatcher (reads [CCF0EC]+0x18) |

keychipSM expected flow: state0→state1→state2→state3→state4→state5→state6→state7(done)

---
