# amGfetcher — FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。横断定数は `../ARCH.md`、索引は repo ルート `FACTS.md`。
confidence: [F]=Frida確認 [S]=静的解析 [I]=推論

---

### patchAmGfetcher IIFE — get_status recv completion fix [S]

すべて RVA 表記（= static_VA − 0x400000）。実装は `boot/boot/amgfetcher/getstatus.js`。

get_status (port 40113) uses raw winsock recv(), NOT pcpaRecvResponse. The normal PCPA completion
state ([stream+0x21C]) is never updated → 0x58B260 never returns 1 → SM loops endlessly.

Call chain: `0x574510 → 0x58B260(stream, tid) → 0x58DAB0(stream) → 0x58ADC0(eax_from_DAB0)`
- 0x58ADC0: jump table dispatcher. input=1 → output=1 (ret 1 = "recv complete").
- Jump table @ 0x58AE48: index=(input+0x10); index=17 → 0x58ADD2 = `mov eax,1; ret`.
- 0x574510: when 0x58B260=0 (pending), copies [esi+8]→[esi+4] (reset to re-send state). When =1 → success path.

Fix: `getStatusRecvDone` flag (set in recv hook) → 0x58ADC0 onLeave forces ret=1 once.

| RVA | Function | Role |
|---|---|---|
| 0x574510 | get_status SM tick | calls 0x58B260; returns 1 always (pending OR done) |
| 0x58B260 | PCPA recv checker | calls 0x58DAB0→0x58ADC0; writes [stream+0x21C]=ret; returns 1 iff 0x58ADC0=1 |
| 0x58DAB0 | PCPA recv state reader | reads recv buffer state; returns 1 iff recv complete |
| 0x58ADC0 | PCPA recv poll (jump table) | input=1 → ret 1; **hooked: getStatusRecvDone flag → force ret=1** |
| 0x575140 | result= field checker | patched → always return 0 (was: always -5 → blocked get_status parser) |
| 0x574B00 | get_status result parser | parses status= field; called only after 0x575140 patch |

Stream struct offsets (ptr at RVA 0xE87004):
- [stream+0x21C]: recv completion state (1=done, 0=pending) — written by 0x58B260
- [stream+0x220]: recv phase state (5=in-progress, 0=idle)

---
