# ambilling FACTS（co-located）

ALL.Net Plus Billing（alpbEx）クライアント。**単独 exe を持たず nrs.exe にリンクされる am* ライブラリ**。
索引 `_index.md` / 横断知見 `workflow.md`。confidence: [S]=静的 [L]=実走 [I]=推論。

## 現状（stub）。実装 `src/logic/patches.c`
| static_VA | 内容 |
|---|---|
| 0xA065C0 | `alpbExGetExecStatus` → **8**(ready, accounting 無し) 固定。Error 1000(amlib errCode 0x15) 回避＋`alpbEx_billing_poll` case8 で `alpbEx_billing_ready=1` を game 自身に立てさせる。device-presence 連鎖は `devices.md` |

status 8 が ready=1 を立てるため `pras_billing_ready_check`(=`ready!=0 || enabled==0`)が自然に通り、readiness ゲート patch は不要（state7 サイレントハング解消）。

`FUN_007000c0`(alpbEx_billing_poll)が 0xA065C0 の戻り -2("Not initialized")を default 分岐 → `DAT_016f5af0=0x15` →
表示 1000。status **8** は: poll→`alpbEx_billing_ready=1`(case8, accounting 開始せず) / debug dump→印字のみ(gate 内) /
credit executor(FUN_00700380)→request queue 処理だが **attract では queue 空＝no-op**(kind0-3 は status!=1/7 で return,
kind4/5 のみ無条件だが queue 空)。**実 credit 計上を配線する際は status 8 の再評価要**(executor の早期 return 挙動が変わる)。
**network_role=serve**（将来 billing サーバ化で実応答へ）。

`alpbEx_billing_enabled` は**無条件 1 で OFF 経路がコード上存在しない**(全数確認)ため `enabled=0` での回避は不可能、status 8 で
ready を立てる方式に一本化。freeplay flag(0x128855A)とは無関係。

## 将来（実 billing）＝ パッチ撤去 path B（billing サーバエミュ）

`ib.naominet.jp:8443`(HTTPS/TLS1.1, keychip 署名 CA)。仕様は ALL.Net billing 層＝**正本＝RingEdge 1 純正 `system\`（mxnetwork.exe 等）**、TeknoParrot は補助（`ref.md` 階層）として要再 RE。

### status の出所（撤去の鍵）
- `alpbExGetExecStatus`(0xA065C0) = `alpb_get_init_flag(obj+0x558)!=0 ? alpb_get_status_field(obj+0x1c) : -2`。
  status は **alpb client 内部 SM の状態フィールド obj+0x1c**。1..10 を取り、`alpbEx_billing_poll`(0x7000C0) が分岐:
  **2**=ready=1 ＋ accounting report 開始 / **8**=ready=1 のみ(traffic 無し) / 1,5,6,7,10=break(ready 立てず) /
  4=ready=0 / default=errCode 0x15(Error 1000)。現行 0xA065C0 パッチは status→**8**（`mov eax,8; ret`）で ready のみ立て、B 撤去には内部 SM を実駆動して +0x1c=8 へ。
- init は `alpb_main_initialize`(0xA16FF0, src/alpb_main.cpp ALPB_MAIN::Initialize)。keychip/serial param table(全フィールド非0要求)を
  検証し `accounting-report.host=ib.naominet.jp` を設定、内部 init 連鎖成功で *param_1=1。

### enabled の出所（安価撤去は不可能）[S]
- `alpbEx_billing_enabled` を 1 にするのは `alpbEx_reset_state`(0x6FFC50) と `alpbExInitialize`(0x6FFD60)、いずれも無条件。**`=0` にする経路はコード上どこにも無い**（全 xref が `==0` 読み or `=1` 書き）＝billing OFF スイッチ非存在。
- ⇒ `pras_billing_ready_check` = `ready||（enabled==0）` の第二項は永久に偽＝厳密に `ready!=0` 必須。`ready=1` は `alpbEx_billing_poll` の status 2/8 のみ。

### B（正攻法・重）
byte patch を完全撤去するには billing プロトコル(TLS:8443, PowerOn 認証→billing session req/res)を実装し内部 SM を +0x1c=8 へ駆動する。boot/attract 未接続ゆえ起動到達だけなら過剰。U2(TLS1.1 keychip 署名 CA の trust store 構築経路)・U3(alpb req/res 列)は正本=`system\`, TP 補助で要再 RE。
