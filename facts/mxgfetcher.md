# amGfetcher FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。索引 `_index.md` / 横断知見 `workflow.md`。
confidence: [S]=静的解析 [L]=ライブ実走 [I]=推論 [F]=旧 Frida 計装(履歴・再取得は Ghidra/実走)

---

### amGfetcher get_status 無限ループの真因＝result≠success（live capture 確定）[L]

**症状**: `card_force_present`(api.c) で presence を供給すると 40113 で get_status/set_auth_params が無限再接続。応答は正常フレーム(`body\r\n>`)で届くが、ゲームは受信後にリトライで再接続する＝フレーム問題ではなく応答内容。

**真因（Ghidra 実体）**: amGfetcher の全応答は `FUN_00975320`(0x975320, response dispatch) 入口で **`FUN_00975140`(0x975140, result field checker)** を必ず通る。checker: `result`=="success"→0、`invalid_parameter`/`invalid_request`/`error`→各負値、**それ以外（`result=0`）→ fall-through で -5**。∴ `result=0` は毎回 -5→txn 失敗→リトライ。amInstall(40102)は success 化済みだが amGfetcher 応答(keychip_proto.c)だけ `result=0` 残存だった。

**修正**: 応答は `keychip_proto.c`（40113 群, 静的パッチ追加ゼロ）。非自明な parser 要求だけ記録:
- get_status: `status=uptodate`(最新＝取得不要)＋`work_version/work_time/order_time/release_time`(値0)。parser `get_status_result_parser`(0x974B00) case7/9 が work_*4 の存在を要求（欠くと -150）。
- resume: `firstreq=0` 必須。`FUN_009746c0`(0x9746c0) が firstreq="1"/"0" のみ受理（無/他 -150 loop）。
- settle: `pause→set_auth_params→resume→isrelease→get_status` 各1回, errors=0, card_force_present 下でもループ再発なし。

**HLSM 消費（`hlsm_boot_network_sm`0x457fe0, state=[param_1+0x14]）**: 4→5(get_status送出)→6(結果; status∉{2,4,5}で
next=7)→7(alabex_auth_ready 待ち)→8→9。get_status が完走しないと state5↔リトライで presence gate に到達しない。

---

### get_status SM の RE 参照（現行 = serve-it）[S]

現行 native は serve-it: `src/host/keychip_server.c` が 40113 を bind し本物の get_status 交換で SM を自然前進させ、`src/logic/patches.c` は JL2JMP 3 個（0x97588A/0x97595F/0x975A1F）のみ。旧 0x6FF980（`hlsm_region_check`）→ret1 gate は撤去済（src に不在＝genuine 化）。

recv completion 機構: get_status(40113) は raw winsock recv() を使い pcpaRecvResponse を通らない。PCPA completion state([stream+0x21C]) は 0x98B260 が書く。

| static_VA | Function | Role |
|---|---|---|
| 0x974510 | get_status SM tick | calls 0x98B260。pending 時 [esi+8]→[esi+4] で re-send 状態へ reset |
| 0x98B260 | PCPA recv checker | calls 0x98DAB0→0x98ADC0；[stream+0x21C]=ret を書く。0x98ADC0=1 のとき 1 |
| 0x98DAB0 | PCPA recv state reader | recv buffer state を読み、recv complete で 1 |
| 0x98ADC0 | jump table dispatcher | input=1→output=1（recv complete）。table @0x98AE48, index=input+0x10 |
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
