# mxnetwork（旧 amNet + ALL.Net connection）— FACTS（co-located）

mxnetwork.exe（ALL.Net / NIC 設定）相当。amNet クエリ＋ ALL.Net 接続段(state6)を扱う。
横断定数は `../ARCH.md`、索引は repo ルート `FACTS.md`。confidence: [F]=Frida確認 [S]=静的解析 [I]=推論

---

## ALL.Net 接続段 — 実装は `../patches.json`（旧 `allnet/connection.js` / `patches.json 0x6FF18A/AC/B3`）

| static_VA | 内容 |
|---|---|
| 0x72DCE0 | `FUN_0072dce0`(ALL.Net server status, amlib_device_status_getter) → 2(ready) 固定。SYSTEM STARTUP state4(network) + state6(allnet) 両立（詳細 `../mxsegaboot/FACTS.md`） |
| 0x6FF18A/AC/B3 | `FUN_006ff140` LAN フラグ b50a/b/c init 0→1（Error 8005 WAN 抑止, state4） |

将来ネットワーク対応（ALL.Net 4 サービス: Authentication PowerOn / DownloadOrder / Billing / AiMeDB と BBS
タイトルサーバ）の設計は `README.md`、仕様は `../../docs/bsnk_ringedge.md §4`。**network_role=serve**（実サーバ
応答へ移す層）。billing は `../ambilling/`、storage は `../mxstorage/` に分離済。

---

## amNet Queries (port 40104)

| Request | Required Response Keys | Notes |
|---|---|---|
| `request=query_dhcp_status&if=0` | `result=0`, `dhcp_status=3` | dhcp_status: 0=disabled 1=obtaining 2=failed 3=obtained |
| `request=query_nic_status&if=0` | `result=0`, `status=1`, `ip_address`, `subnetmask`, `gateway`, `primary_dns`, `secondary_dns` | status: 0=no link 1=connected. game calls bind(ip:23456) |

### PCPA wire format for amNet — fields are `&`-separated [F] (確定 2026-06-13)

**区切りは `&`。`\r` または `\n` を見た時点でパースが打ち切られる。** パーサ `pcppChangeRequest`
(static 0x98bb30): `&`→新 key=value ペア / `=`→key/value 区切り / `\r`|`\n`→**パース終了**。
key/value テーブルは stream+0x100(keyword 群)/+0x140(command 群)/+0x180(件数)に格納し、
`pcpaGetCommand` (FUN_0098aae0→FUN_0098b610) が引く。
```
response=query_dhcp_status&result=0&dhcp_status=3&ip_address=...&...   ← 1行・& 区切り。末尾に \r\n> を付ける
```
- `response=<req>` を**先頭キー**に必須。無いと抽出器が -6。
- `result=0` 必須（atoi("0")=0 が成功パスを選ぶ）。**無いと抽出器が -1**。

**[FIXED] Error 8006 の真因 = pcpa_server が amNet 応答だけ `\r\n` 区切りにしていた**。最初の `\r` で
パースが止まり `response` ペアのみ登録 → 抽出器が `result` を見つけられず -1 → SM ループ → 8006。
`boot/mxkeychip/server/pcpa_server.py` を `&` 区切りに直して native 成功（ret=0, dhcp_status=3, nic_ready=1）を
実機実証。旧 `0x5814E0` force-patch は撤去（`mxnetwork/diag.js` は log-only monitor 化）。詳細 `BUGS.md`。

### 応答抽出と nic プロパティ連鎖 [S]

- **`amNetworkResponseCheck`** (static 0x9814E0 / RVA 0x5814E0): `response`/`result` を見て ctx+0x10
  (req_type_idx) で分岐。dhcp=case1/2、nic=**case9/10 → `FUN_009807f0` に委譲**、mac=case0xd/0xe。
  `result` 欠落 or 非0で switch default → **-1**。
- **`amNetworkRequestPropertySub`** (static 0x9807f0): nic プロパティ取得の連鎖 SM。`query_nic_status` の
  `status` 値を `DAT_00b9b32c` と比較。**不一致**→`FUN_00980640` を5回呼び `ip_address`/`subnetmask`/
  `gateway`/`primary_dns`/`secondary_dns` を**応答からインライン解析**して nic_ready=1（nrs-util 実機はこの経路）。
  **一致**→`query_ip_address`→`query_subnetmask`→`query_gateway`→`query_primary_dns`→`query_secondary_dns`
  を順次送信し各応答を解析（pcpa_server 未対応。現状この経路には入らない）。
- **`FUN_00980640`**: `pcpaGetCommand(stream, <field>)` の値を `inet_addr` して ctx の nic フィールドへ格納
  （値が無い/`DAT_00c828cc` 一致なら 0）。inline 経路の格納先: ip→ctx+0x3c, mask→ctx+0x40, gw→0x44, dns1→0x48, dns2→0x4c。
- **`amNet_nic_status_reader`** (static 0x980700): ctx+0x69(nic_ready)=1 を要求し ctx+0x38..0x4c を out-param へ。
  SM(0x459d80) case4 が **ctx+0x3c=IP / ctx+0x40=mask** を文字列化（DAT_016019a7/c7）し `ip_match_check`
  (0x45a000) で `(mask&ip)==(ref&mask)` を計算 → DAT_016019a6。`FUN_006fe040`(network 接続 SM)は
  DAT_016019a5(nic解決)&&DAT_016019a6(ip_match) が真のときだけ前進する。

bind は INADDR_ANY 化（`boot/lib/base.js` の bind フック）で任意 NIC に bind 可。

---


## amNet State Machine [S]

Outer SM at static_VA 0x459D80 (RVA 0x059D80). State variable: `[0x160199c]`.

### State flow

```
init: if [0x1601700]&1 == 0 → start at state 3 (DHCP already known)
      if [0x1601700]&1 == 1 → start at state 0 (need DHCP query)

state 0: initiate DHCP async query
  ↓  (transition when ctx+0x14==0 and [0x16019a0]≥0)
state 1: read dhcp_status via 0x5806C0 (needs ctx+0x68=1, returns ctx+0x30)
  ↓  (SM tick: if [0x160199b]==0 → advance)
state 3: initiate NIC async query (via 0x581C40 → pcpaSetSendPacket + async)
  ↓  (transition when ctx+0x14==0 and [0x16019a0]≥0)
state 4: read NIC status via 0x580700 (needs ctx+0x69=1, returns ctx+0x38 as IP)
         → sprintf IPs → [0x16019a5]=1 → triggers bind() attempt
```

### Global state variables [S]

| static_VA | RVA | Name | Notes |
|---|---|---|---|
| 0x160199C | 0x120199C | amNet_state | outer SM state: 0/1/2/3/4 |
| 0x160199B | 0x120199B | amNet_pending | pending-transition flag; set by state handlers |
| 0x16019A0 | 0x12019A0 | amNet_result | last ctx+0x14 result; -6 causes loop restart |
| 0x16019A5 | 0x12019A5 | amNet_async_active | 1=async driver running; bypass dispatch table |
| 0x16019A6 | 0x12019A6 | amNet_ip_match | return from 0x45A000 (IP subnet check) |
| 0x16019A7 | 0x12019A7 | amNet_ip_str | IP address as ASCII string (16 bytes) |
| 0x16019B7 | 0x12019B7 | amNet_gw_str | gateway as ASCII string |
| 0x16019C7 | 0x12019C7 | amNet_mask_str | subnet mask as ASCII string |
| 0x1601700 | 0x1201700 | amNet_dhcp_known | &1==0 → DHCP result known (skip to state 3) |

### amNet PCPA context struct (ptr at [0xCCF448] / RVA 0x8CF448) [S]

| offset | type | name | notes |
|---|---|---|---|
| +0x00 | U32 | init_flag | 0=not init; 0x5814E0 checks this |
| +0x08 | U32 | async_state | ctx+8: 1=send 2=recv 3=parse 4=extract(→0x5814E0) 5=done(→0x580440) |
| +0x10 | U32 | req_type_idx | set by state handlers (esi+9); identifies which request |
| +0x14 | S32 | transition_trigger | 0=advance SM; 1=async busy; negative=error; read by 0x580300 |
| +0x30 | S32 | dhcp_status | set by 0x5814E0 (dhcp query): 3=obtained; read by 0x5806C0 |
| +0x38 | U32 | nic_ip_le | set by 0x5814E0 (nic query): IP little-endian; read by 0x580700 |
| +0x68 | U8 | dhcp_ready | 1=ctx+0x30 valid; checked by 0x5806C0 |
| +0x69 | U8 | nic_ready | 1=ctx+0x38 valid; checked by 0x580700 |
| +0x70 | ptr | pcpa_stream | stream handle passed to pcpaSetSendPacket etc. |

### amNet function RVAs [S]

| RVA | Name | Notes |
|---|---|---|
| 0x059D80 | amNet_SM_tick | outer SM dispatcher; called each frame |
| 0x059E2D | state0_handler | calls 0x581D00 → pcpaOpenClient → initiates DHCP async |
| 0x059E50 | state1_handler | calls 0x5806C0 → reads ctx+0x68/ctx+0x30 |
| 0x059EBE | state3_handler | calls 0x581D40 → 0x581C40 → initiates NIC async |
| 0x059EE1 | state4_handler | calls 0x580700 → reads ctx+0x69/ctx+0x38 → sprintf IPs |
| 0x581A30 | async_driver | dispatches on ctx+8 (1→2→3→5); calls 0x5814E0 when ctx+8=4 |
| 0x5814E0 | response_extractor | parses PCPA response; expects "response=" key first |
| 0x580300 | ctx14_reader | returns ctx+0x14; SM compares with 1 for transition |
| 0x580440 | async_complete | called when ctx+8=5; sets ctx+0x14=0 (enables transition) |
| 0x5806C0 | dhcp_status_reader | checks ctx+0x68; returns ctx+0x30 via out-param |
| 0x580700 | nic_status_reader | checks ctx+0x69; returns ctx+0x38 (IP LE) via out-param |
| 0x581C40 | nic_query_init | initiates query_nic_status async; sets ctx+0x10, ctx+0x38..0x4C=0 |
| 0x045A000 | ip_match_check | calls inet_addr on 3 IP strings; returns 1 if same subnet |

### SM transition mechanism [S]

1. `async_driver` (0x581A30): runs each tick when `[0x16019A5]!=0` or `[0x160199B]!=0`.  
   Drives ctx+8: 1→send 2→recv 3→parse **4→call 0x5814E0** 5→call 0x580440.
2. `0x580440`: sets `ctx+0x14=0` → on next tick SM reads 0 via `0x580300`.
3. SM tick: ctx+0x14==0 AND `[0x16019A0]≥0` → enter transition block → state 0→1 or 3→4.
4. ctx+0x14 negative (e.g. -6 from 0x5814E0 failure): `[0x16019A0]=-6 < 0` → jl clears `[0x160199B]` → dispatch re-runs state handler → loop.

---
