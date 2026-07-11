# 旧 Frida 動的群を native へ移植「しなかった」根拠（設計判断 + fallback）

戦略差で native 移植不要と確定した旧 `boot/*`(Frida) 動的群。正は実装(`src/`)＋Ghidra。移植状態は git log(`187c93c`)。

## mxgfetcher get_status: fake-it → serve-it

- 旧 Frida = fake-it: パーサ(0x9746C0/974760/9747A0/975140)を `33 C0 C3`、0x9744F0 hang-safe スタブ、0x98ADC0+recv で完了強制し SM を騙す。
- native = serve-it: HLSM(hlsm_boot_network_sm 0x457FE0) state5/6/9 と FUN_009744f0/975830/975a70/975700 は全て `DAT_01286ff0`(PCP stream ptr)依存。唯一の WRITE=FUN_009743f0(amGfetcherInit) が 127.0.0.1:40113(0x9cb1) 接続成功時 `=1`。`keychip_server.c` が 40113 bind 済 → 本物 get_status 交換で SM 自然前進。`patches.c` は hlsm_region_check(0x6FF980)→ret1(state0 gate)+JL2JMP×3 のみ。
- **fallback**: 実機で 40113 接続失敗し state5 が get_status 無限リトライ("Error 1000" watchdog)する場合のみ、旧 fake-it 群（4 パーサ→`33 C0 C3`, 0x9744F0 hang-safe, 0x975857→`EB 06`）を patches.c へ移植。

## region watchdog / keychip client → root-cause 静的化で代替

- **region.js watchdog/re-force → 対象外。** master errCode `DAT_016f5af0` に ~14 writer（FUN_004591b0/0045a7f0/amlib_reset_init/amlib_master_init/0045a320/0045a6f0/storage_board_check/backup_check_err0x18/alpbEx_billing_poll/008b2e00/init_sm_SYSTEM_STARTUP×4/usbio_errCode_mapper/keychip_errCode1_latcher）。旧=250ms watchdog で反応的全クリア。native は各源を root-cause で潰す（region NOP/AAL platform/board index dipsw/USB I/O imm/is-DVD→0/billing→5/segaboot/keychip-hold）。`PcbRegion`(0x16014C4) は writer 無し(全 xref READ)→bind 時 data-write 永続＝re-force hook 冗長。残存 setter が実機で発火したら**その setter を個別 root-cause パッチ**（watchdog 移植はアンチパターン＝どのチェックが落ちたか隠す）。
- **client.js → 対象外。** pcpaOpenClient(0x98AEA0) は connect→pcpa_recv_poll() 結果を返す。負戻り=stream/IP=null か接続拒否のみ。`keychip_server.c` が全7ポート(40100–40113) bind 済 → 接続拒否なし → 回復 hook(orig<0→0) 不要。
