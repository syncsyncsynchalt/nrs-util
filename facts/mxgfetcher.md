# amGfetcher FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。索引 `_index.md` / 横断知見 `workflow.md`。
confidence: [S]=静的解析 [L]=ライブ実走 [I]=推論 [F]=旧 Frida 計装(履歴・再取得は Ghidra/実走)

---

### ★amGfetcher get_status 無限ループの真因＝result≠success（live capture 確定 2026-07-01）[L]

**症状**: `card_force_present`(api.c) で presence を供給すると 40113 で get_status/set_auth_params が無限再接続
（旧記述の「黒いサーバ接続中・2138回/3分」）。旧仮説「raw recv/[stream+0x21C] 未更新の PCPP フレーム未成立」は
**live capture(kc.wire, keychip_server 一時計装)で棄却**：応答は正常フレーム(`body\r\n>`)で届き、ゲームは受信後に
**リトライで再接続**していた＝フレーム問題ではなく**応答内容**。

**真因（Ghidra 実体）**: amGfetcher の全応答は `amgfetcher_response_dispatch`(0x975320) 入口で **`result_field_checker`(0x975140)**
を必ず通る。この checker は `result`=="success"→0、`invalid_parameter`/`invalid_request`/`error`→各負値、
**それ以外（我々の `result=0`）→ fall-through で -5**。∴ `result=0` は毎回 -5 エラー→トランザクション失敗→リトライ。
amInstall(40102)は既に `result=success` 化済みだったが、**amGfetcher 応答(keychip_proto.c)だけ `result=0` のまま取り残されていた**。

**修正（keychip_proto.c・静的パッチ追加ゼロ）**:
- get_status → `result=success&status=uptodate&work_version=0&work_time=0&order_time=0&release_time=0`
  （uptodate=最新＝取得不要の standalone 正解。status 9 は parser 0x974B00 case7/9 で work_*4 フィールドの存在を要求）
- set_auth_params/isrelease/resume/pause/stopcatcher → `result=success`（resume は加えて **`firstreq=0`**、
  `amgfetcher_resume_parser`0x9746c0 が firstreq="1"/"0" のみ受理・無/他は -150 loop。値は nrs.exe 実バイトで "1"/"0" 確定）
- **ライブ実証**: 40113 が `pause→set_auth_params→resume→isrelease→get_status` を**各1回で settle**（633回→1回）、
  errors=0。`card_force_present` 復帰＋テスト card(nrsedge.card.json present=1)注入下でも 40113 ループ再発なし・
  `card.force_present`(ds+0x5628=1) 発火・`card.read` 応答＝**カード挿入検出信号がシーンへ供給される**。

**HLSM 消費（`hlsm_boot_network_sm`0x457fe0, state=[param_1+0x14]）**: 4→5(get_status送出)→6(結果; status∉{2,4,5}で
next=7)→7(alabex_auth_ready 待ち)→8→9。get_status が完走しないと state5↔リトライで presence gate に到達しない。

---

### amGfetcher get_status（旧 serve-it 記述・参考）[S]

**現行 native は serve-it**: `src/host/keychip_server.c` が 40113 を bind し本物の get_status 交換で SM を自然前進させ、
`src/logic/patches.c` は 0x6FF980→ret1（state0 gate）＋ JL2JMP 3 個のみ。下の fake-it パッチ群は **native 未使用**
（旧 Frida `getstatus.js`。実機で 40113 接続が失敗した場合のフォールバック記録。詳細 `port_status.md`「fake-it → serve-it」）。

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

fake-it パッチ群（旧 Frida `getstatus.js`、**native 未使用＝フォールバック参照**）:

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

get_status SM 関数（参考・RE 観測用）:

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
