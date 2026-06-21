# amJvs / amJvsp FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。横断定数は `../ARCH.md`、索引は repo ルート `FACTS.md`。
confidence: [F]=Frida確認 [S]=静的解析 [I]=推論

---

## Frida Hook static_VA

番地は static_VA（`va()` 経由で参照、ASLR 非依存）。[F] unless noted.


### bypassJvs IIFE (`boot/amjvs/state.js`)（patchCode + 初期 state write）

patchCode 永続 + ロード時の state 直接書き込みで構成する。

| 種別 | static_VA | 内容 |
|---|---|---|
| patchCode | 0x67AFA0 | FUN_0067afa0 (JVS reinit) → `ret`（memset+amJvspInit fail path を無効化。-4→errState=-101 を防ぐ） |
| patchCode | 0x987590 | specCheck → `xor eax,eax; ret 8`（[[0xCCF54C]] guard が必ず成功） |
| patchCode | 0x9883D3 | amJvspAckSwInput 内 `MOV EAX,EDI`(8B C7)→`XOR EAX,EAX`(33 C0)。GetReport(-11) failure path を 0 返しに＝JVS polling 維持 |
| data write | 0x16B7858 | jvs_initialized_flag = 1 |
| data write | 0x16B785C | jvs_node_count = 1 |
| data write | 0x16B7860 | node[0].id = 1 |
| data write | 0x16B8668 | jvs_p1_device_id = 1 |
| data write | 0x16B7EA0 | node[0].poll_state=1（+0x16B7EA1 node_valid=1） |
| data write | 0xCCF54C | [[ptr]][0]=1（sub1 ctx — specCheck guard 用、ロード時） |

FUN_0067afa0 patchCode で nodeInfo version-check 経路に到達しないため、以下の node_info_buf 値は強制不要:
+0x101=0x14 / +0x108=0x02 / +0x124=0x0d / +0x134=0x13 / +0x138=0x00
（ゲーム側チェック: 0x67B041≥0x0e / 0x67B054≥0x02 / 0x67B05D≥0x0d / 0x67B066≥0x13 / 0x67B283）。


### 入力注入の扱い

JVS 入力注入（SERVICE/START/coin）は **boot では実装していない**。JVS は SYSTEM STARTUP SM の gate では
なく、ATTRACT 到達に入力は不要。`amjvs/` は `state.js`（init + 初期 state write + 上記 0x9883D3 polling patch）のみ。
プレイアブル化（入力受付）が必要になった段階で、TeknoParrot 方式の named pipe `\\.\pipe\teknoparrot_jvs` +
共有メモリ `TeknoParrot_JvsState`（下記 JVS I/O Subsystem 節）で実装する。

---


## Global Variables [S+F]

| static_VA | RVA | Name | Type | Notes |
|---|---|---|---|---|
| 0xCCF548 | 0x8CF548 | amJvs_main_ctx_ptr | U32* | pointer to amJvs main context |
| 0xCCF54C | 0x8CF54C | amJvs_sub1_ctx_ptr | U32* | pre-forced: [[ptr]][0]=1 at script load |
| 0x16B7858 | 0x12B7858 | jvs_initialized_flag | U8 | ≥1 = JVS init done |
| 0x16B785C | 0x12B785C | jvs_node_count | U32 | polling loop: `for(i=0;i<nodeCnt;i++)` — must be ≥1 |
| 0x16B7860 | 0x12B7860 | jvs_node0_base | - | stride 0x65C per node |
| 0x16B8668 | 0x12B8668 | jvs_p1_device_id | U32 | compared vs node[0] in credit handler |
| 0x16B866C | 0x12B866C | jvs_p2_device_id | U32 | |
| 0x16B8670 | 0x12B8670 | jvs_error_state | S32 | 0=OK, -101=err6401, -102=err6402 |
| 0x16B8674 | 0x12B8674 | jvs_error_counter | U32 | |

---


## JVS Node Memory Layout

Base: `nrsBase + 0x12B7860`, stride per node: `0x65C`

| offset | type | name | notes |
|---|---|---|---|
| +0x000 | U32 | node_id | compared vs jvs_p1_device_id |
| +0x004 | - | report_buf | passed as amJvspAckSwInput arg0 |
| +0x306 | - | node_0x306 | passed as amJvspAckSwInput arg1 |
| +0x640 | U8 | poll_state | ≥1 required for fn A to call amJvspAckSwInput |
| +0x641 | U8 | node_valid | |
| +0x642 | U8 | sys_switch | 0xFF = panel present |
| +0x643 | U8 | p1_switch1 | bit7=START bit6=SERVICE bit5=UP bit4=DOWN bit3=LEFT bit2=RIGHT bit1=B1 bit0=B2 |
| +0x645 | U8 | p2_switch1 | same layout |
| +0x648 | U16 | coin_count_chute0 | cumulative count |

---


## Game Functions [S]

| static_VA | RVA | Name | Notes |
|---|---|---|---|
| 0x67B150 | 0x27B150 | jvs_update_main | called every frame; checks jvs_initialized_flag first |
| 0x67B280 | 0x27B280 | per_node_output_fn | edi=node_ptr; writes solenoid/JVS output |
| 0x67B330 | 0x27B330 | per_node_input_fn | esi=node_ptr; calls inner_input |
| 0x67B3A0 | 0x27B3A0 | inner_input | calls amJvspAckSwInput + amJvspGetCoinCount |
| 0x67B450 | 0x27B450 | credit_handler | requires node[0]==jvs_p1_device_id |
| 0x67B41E | 0x27B41E | device_id_check | `cmp node[0], [0x16B8668]`; branch to credit_handler |

---


## JVS I/O Subsystem [F+S]

nrs.exe JVS connection attempt order:
1. `CreateFileA("\\.\pipe\teknoparrot_jvs")` — TeknoParrot creates this named pipe
2. `CreateFileA("COM2")` — COM API intercepted via GetProcAddress + MinHook
3. `CreateFileA("COM1")` — same

Shared memory: `TeknoParrot_JvsState` (8 bytes) — **生成者=`TeknoParrot.dll`(32bit)** [F]
（`jvsstate_capture.py` attach。caller=`TeknoParrot.dll+0x4265` 他、最深=VMProtect entry `+0x736b778`）。
同名で **4 回生成**(off +0x4265/+0x58d8/+0xa1b5/+0x14a28)＝同一オブジェクトを 4 view にマップ。
アイドル 8 バイト=`01 00 00 00 00 00 00 00`(byte0=JVS-present 固定, 入力で byte1+ が変化)。ビット割当は
入力束縛が前提(プロファイル未束縛)。平文文字列が無いのは VMProtect 文字列暗号化が理由（静的デコンパイル不可,
`tools/re/tp_re.py` / 詳細 `docs/teknoparrot.md` §5・§8.5）。
ヘッドレス起動: `OpenParrotLoader.exe .\TeknoParrot\TeknoParrot "C:\src\bbs\nrs.exe"` (cwd C:\src\TPBootstrapper)。

IOCTL codes (columba driver compatible):
- `JVS_IOCTL_HELLO    = 0x80006004`
- `JVS_IOCTL_SENSE    = 0x8000600C`
- `JVS_IOCTL_TRANSACT = 0x8000E008`

JVS frame format (segatools, Unlicense):
```
byte 0:    0xE0 (SYNC)
byte 1:    dest addr (0xFF=broadcast)
byte 2:    payload length + 1
byte 3..n: command bytes
byte n+1:  checksum (sum of addr+cmd bytes, LSB + 1)
escape:    0xD0/0xE0 in payload → 0xD0 + (byte XOR 0xFF)
```
JVS commands: 0x10=IOIDENT 0x11=GET_CMD_VER 0x12=GET_JVS_VER 0x13=GET_COMM_VER 0x14=GET_FEATURES
0x20=READ_SWITCHES 0x21=READ_COIN 0x22=READ_ANALOGS 0x32=WRITE_GPIO 0xF0=RESET 0xF1=ASSIGN_ADDR

---
