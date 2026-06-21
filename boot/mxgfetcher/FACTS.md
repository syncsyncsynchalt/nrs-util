# amGfetcher — FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。横断定数は `../ARCH.md`、索引は repo ルート `FACTS.md`。
confidence: [F]=Frida確認 [S]=静的解析 [I]=推論

---

### patchAmGfetcher IIFE — get_status recv completion fix [S]

番地は static_VA。load-bearing は `boot/mxgfetcher/getstatus.js`、純診断は `boot/mxgfetcher/diag.js`。

get_status (port 40113) uses raw winsock recv(), NOT pcpaRecvResponse. The normal PCPA completion
state ([stream+0x21C]) is never updated → 0x98B260 never returns 1 → SM loops endlessly.

Call chain: `0x974510 → 0x98B260(stream, tid) → 0x98DAB0(stream) → 0x98ADC0(eax_from_DAB0)`
- 0x98ADC0: jump table dispatcher. input=1 → output=1 (ret 1 = "recv complete").
- Jump table @ 0x98AE48: index=(input+0x10); index=17 → 0x98ADD2 = `mov eax,1; ret`.
- 0x974510: when 0x98B260=0 (pending), copies [esi+8]→[esi+4] (reset to re-send state). When =1 → success path.

Fix: `getStatusRecvDone` flag (set in recv hook) → 0x98ADC0 onLeave forces ret=1 once.

call-chain（参照のみ。patch 対象は下表）:

| static_VA | Function | Role |
|---|---|---|
| 0x974510 | get_status SM tick | calls 0x98B260; returns 1 always (pending OR done) |
| 0x98B260 | PCPA recv checker | calls 0x98DAB0→0x98ADC0; writes [stream+0x21C]=ret; returns 1 iff 0x98ADC0=1 |
| 0x98DAB0 | PCPA recv state reader | reads recv buffer state; returns 1 iff recv complete |

load-bearing patch/hook（`getstatus.js`。runtime; detach で revert）:

| static_VA | 機構 | Function | 内容 |
|---|---|---|---|
| 0x457FE0 | Interceptor onEnter | HLSM (FUN_00457FE0) | next=7&&tcpBusy==0 のとき ctx+0x18=8 を書き state7 を丸ごと飛ばす（case7 副作用クラッシュ回避） |
| 0x9746C0 | patchCode | resume parser | `xor eax,eax; ret`（応答パーサ→0。-5 が Error 0903 を誘発するのを防ぐ） |
| 0x974760 | patchCode | isrelease case5 | 同上→0 |
| 0x9747A0 | patchCode | isrelease case10 | 同上→0 |
| 0x975140 | patchCode | result= field checker | →0（unpatched は -5 で get_status パーサを塞ぐ） |
| 0x6FF980 | patchCode | hlsm_region_check | `mov eax,1; ret`（state0 condition-A 発火用。HW フラグ未設定でも 1） |
| 0x9744F0 | patchCode | TCP SM done check | hang-safe 手アセンブル: stream==0→ret0; r!=0→ret1; r==0→reset+ret0 |
| 0x975857 | patchCode | pause SM strBusy | `jmp +6`(EB 06) で strBusy チェックを飛ばし常に send 経路へ |
| 0x98ADC0 | Interceptor onLeave | PCPA recv poll | getStatusRecvDone フラグで ret=1 を一度だけ強制 → 同 tick で [0x1287000]=0 + 0x458271 NOP×3 を適用 |
| 0x458271 | patchCode (動的) | state=0 advance | `NOP×3`（`89 5D 18`=ctx.next=1 を塞ぐ。DAT_210B508 + counter-timeout の再 boot 防止。0x98ADC0 hook 内で適用） |

gfetcherDiag Monitor static_VA（`diag.js`、log only, no modification）:

| static_VA | Function |
|---|---|
| 0x974B00 | get_status result パーサ |
| 0x974820 | status 文字列→int |
| 0x975A70 | get_status sender |
| 0x975320 | TCP sub-state 4 パーサ |
| 0x975700 | TCP SM step（busy=1 経路。[0x1286FF4] も読む） |
| 0x975830 | state-9 pause request SM |
| 0x974560 | pause done チェック（0x975830 から呼ばれる） |

Stream struct offsets (ptr at static_VA 0x1287004):
- [stream+0x21C]: recv completion state (1=done, 0=pending) — written by 0x98B260
- [stream+0x220]: recv phase state (5=in-progress, 0=idle)

---
