# amDongle — FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。横断定数は `../ARCH.md`、索引は repo ルート `FACTS.md`。
confidence: [F]=Frida確認 [S]=静的解析 [I]=推論

---

### bypassAmDongle IIFE (`boot/amdongle/patch.js`)

| 種別 | RVA | Function | 内容 |
|---|---|---|---|
| patchCode | 0x575E00 | amDongleBusy | `xor eax,eax; ret`（永続。"not busy" 固定。outerSM even-state 前進に必須） |

keychip が pcpa_server.py で genuine satisfy するため、amDongleBusy のみ維持する
（PCPA async layer の recv-completion gap を埋める TP 相当の assert）。


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
