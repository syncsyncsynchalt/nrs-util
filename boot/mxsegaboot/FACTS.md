# amlib SYSTEM STARTUP FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。横断定数は `../ARCH.md`、索引は repo ルート `FACTS.md`。
confidence: [F]=Frida確認 [S]=静的解析 [I]=推論

---

## ★Boot = amlib SYSTEM STARTUP シーケンス `FUN_0089a010` (RVA 0x49a010) [S+F]

ブートは画面に "SYSTEM STARTUP" を出し、`FUN_0089a010`(`param_1+4`=state, `+8`=substate)が各段階を順に
チェックする。実写で各 state の結果("CHECKING X ... OK/NG/NA")が見える。**これを全て満たすとゲームが
ATTRACT 起動する**。

| state | 画面 | チェック関数 | 満たし方(satisfy) | 実装 |
|---|---|---|---|---|
| 2 | CHECKING IC CARD R/W | `FUN_004f6310`(ready bit1)/`FUN_004f6330`(err bit4), dev type 0x21 | ready→1（ready が立てば通過、err bit は不参照） | `../devices/presence.js` 0x4F6310 |
| 3 | CHECKING TOUCH PANEL | `FUN_008b3b00`(resp)/`FUN_008b3b40`(err), dev type 0x22 | resp→1（resp が立てば通過、err bit は不参照） | `../devices/presence.js` 0x8B3B00 |
| 4 | CHECKING NETWORK | network flags `DAT_0210b50a/b/c`(`FUN_006ff140`) + deviceMgr+0x1ec | b50c=LAN(IP一致). 早期 init 0→1 | `../mxnetwork/state.js` 0x6FF1B3（b50c のみが &0x5f3 の gate）+ 0x72DCE0 |
| 5 | CHECKING EXTEND IMAGE | `FUN_0072b3a0`(install status) / `FUN_004fda50`(is-DVD-boot, case1) | →4(done)+*ESI=0 で install skip ＋ DVD-boot→0 | `./startup.js` 0x72B3A0 + `../mxstorage/presence.js` 0x4FDA50。⚠️0x72B3A0 を消すと画面が "EXTEND IMAGE … NG / INSTALLING … WAITING" で停止する。**BOOT_DONE(HLSM `FUN_00457FE0`) は SYSTEM STARTUP SM と別物**でこの停止を検出できない |
| 6 | CHECKING CONNECTION (ALL.NET AUTH/UPLOAD/GAME SERVER/LOCAL) | `FUN_0072dce0`(server status, deviceMgr+0x1d4[1..4]) | status≠1(resolved)に保持(=2 ready 固定) | `../mxnetwork/state.js` 0x72DCE0 |
| 7 | INITIALIZING P-ras | `FUN_00701280` = `b611!=0 \|\| b610==0`(billing-ready/offline) | →true 強制(FreePlay) | `./startup.js` 0x701280 |
| 8→10 | (DONE) | `FUN_0089de10` | — state10 で SYSTEM STARTUP 完了 → ATTRACT | — |
| 9 | ERROR | — | errCode を立て error scene(0903 等) | 回避=各 state を満たす |

- 各 device-wait substep は `(probe_ready() \|\| probe_err())` が真になるまで待つ＝デバイス無応答だと hang。
  ready 述語を 1、error 述語を 0 にする(`23/26`)か、状態を resolve する(`30/31/32`)。
- **region 0903**: state を進めると、keychip setup 前の早期に dongle region(`DAT_01601989`)=0 で errCode4 → sticky
  "0903 Wrong Region" シーンが表面化する。`08` で `DAT_01601989=0x01` を**早期から**強制して回避。
- **"Error 0949 Keychip Not Found" の正体**: keychip presence(`FUN_0096c5d0`=ctx+4&&ctx+8)は安定 1。0949 は
  state5(EXTEND IMAGE)install 失敗時の終端表示。keychip 問題ではない。
- ⚠️ **検証鉄則**: errNo=0 等のログだけでクリーン判断しない。必ず `tools/runtime/screenshot_window.py`(PrintWindow)で実写確認。

---
