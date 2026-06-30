# ambilling FACTS（co-located）

ALL.Net Plus Billing（alpbEx）クライアント。**単独 exe を持たず nrs.exe にリンクされる am* ライブラリ**。
索引 `_index.md` / 横断知見 `workflow.md`。confidence: [S]=静的 [L]=実走 [I]=推論。

## 現状（stub）。実装 `src/logic/patches.c`
| static_VA | 内容 |
|---|---|
| 0xA065C0 | `alpbExGetExecStatus` → **8**(ready, accounting 無し) 固定。Error 1000(amlib errCode 0x15) 回避＋`alpbEx_billing_poll` case8 で `alpbEx_billing_ready=1` を game 自身に立てさせ、旧 0x701280 を不要化（2026-06-30, A 統合）。device-presence 連鎖は `devices.md` |
| ~~0x701280~~ | **撤去済**（2026-06-30, A 統合）。上の status 8 が ready=1 を立てるため `pras_billing_ready_check`(=`ready!=0 \|\| enabled==0`)が自然に通る。state7 サイレントハングは解消（差分ライブ実証: patches 23→22, SYSTEM_STARTUP 完走=scene 稼働）。 |

`FUN_007000c0`(alpbEx_billing_poll)が 0xA065C0 の戻り -2("Not initialized")を default 分岐 → `DAT_016f5af0=0x15` →
表示 1000。status **8** は: poll→`alpbEx_billing_ready=1`(case8, accounting 開始せず) / debug dump→印字のみ(gate 内) /
credit executor(FUN_00700380)→request queue 処理だが **attract では queue 空＝no-op**(kind0-3 は status!=1/7 で return,
kind4/5 のみ無条件だが queue 空)。**実 credit 計上を配線する際は status 8↔5 を再評価**(executor の早期 return 挙動が変わる)。
**network_role=serve**（将来 billing サーバ化で実応答へ）。

**0x701280 vs 0xA065C0**: 701280=ブートゲート(readiness, state7)だったが撤去。A065C0=ランタイム(exec status)。
`alpbEx_billing_enabled` は**無条件 1 で OFF 経路がコード上存在しない**(全数確認)ため `enabled=0` での回避は不可能、status 8 で
ready を立てる方式に一本化。freeplay flag(0x128855A)とは無関係。

## 将来（実 billing）＝ パッチ撤去 path B（billing サーバエミュ）

`ib.naominet.jp:8443`(HTTPS/TLS1.1, keychip 署名 CA)。仕様は ALL.Net billing 層＝**正本＝RingEdge 1 純正 `system\`（mxnetwork.exe 等）**、TeknoParrot は補助（`ref.md` 階層）として要再 RE。

### status の出所（撤去の鍵）
- `alpbExGetExecStatus`(0xA065C0) = `alpb_get_init_flag(obj+0x558)!=0 ? alpb_get_status_field(obj+0x1c) : -2`。
  status は **alpb client 内部 SM の状態フィールド obj+0x1c**。1..10 を取り、`alpbEx_billing_poll`(0x7000C0) が分岐:
  **2**=ready=1 ＋ accounting report 開始 / **8**=ready=1 のみ(traffic 無し) / 1,5,6,7,10=break(ready 立てず) /
  4=ready=0 / default=errCode 0x15(Error 1000)。
- 現行 0xA065C0 パッチは status→**5**＝Error 1000 は避けるが ready を立てない→`pras_billing_ready_check`(0x701280)
  パッチが**不可避に連動**。両撤去には内部 SM を実駆動して **+0x1c=8**(ready のみ・accounting 無しが standalone 理想)へ。
- init は `alpb_main_initialize`(0xA16FF0, src/alpb_main.cpp ALPB_MAIN::Initialize)。keychip/serial param table(全フィールド非0要求)を
  検証し `accounting-report.host=ib.naominet.jp` を設定、内部 init 連鎖成功で *param_1=1。

### B の未知数（U1 がクリティカルパス）
- **U1 socket/DNS 境界**: client は :8443 へ connect するが host に socket フック無し(mxnetwork.md 参照, PCPA 40104 とは別チャネル)。
  この境界エミュ層が未存在＝B の主工事。最初のスパイク = connect/getaddrinfo を**観測フック**(傍受せず log)し
  ライブで connect 試行の有無/停止点を確定。
  - **[L] 2026-06-30 確定（src/host/netobs.c 観測スパイク）**: billing init は到達し client は
    `getaddrinfo("naominet.jp")`→`getaddrinfo("ib.naominet.jp")` を**各1回**呼ぶ（svc 無=node のみ）。
    **だが解決失敗→:8443 への connect は一度も発生せず**（全 net.connect は 127.0.0.1 の amNet/title 系
    40102/40106/40110/40113/40114 のみ。8443 も非 localhost も皆無）。
    ⇒ **billing SM は DNS 段で死んでいる**＝status field(+0x1c) が ready(2/8) に進まない根本原因。
    最小次手 = getaddrinfo/gethostbyname を**観測→リダイレクト**化し `ib.naominet.jp`→127.0.0.1 を返す
    （netobs.c のフックを再利用）。これで connect 127.0.0.1:8443 が出れば U1 完了→U2(TLS)へ。
    関連: `bbrouter.loc`/`tenporouter.loc`(BBS title server) も ~10s 周期で解決試行、同様に未応答。
- **[L] 2026-06-30 U2 観測（netobs.c リダイレクト＋8443 listener）= 想定外**:
  - DNS リダイレクトは成功(`net.resolve.redirect` naominet→127.0.0.1)、8443 listener も up(nrs.exe in-process)。
  - **にも関わらず billing は 8443 へ connect してこない**（net.connect/tls.accept/tls.hello 皆無）。
  - 観測される connect は全て keychip_server.c の localhost PCPA 群 **40100–40113**(40113 が支配的, keychip/amNet ポーリング)。
    これは keychip/amNet の PCPA(`>` 区切り `k=v&\r\n`)で **HTTP でも TLS でもない別チャネル**。billing はここに乗っていない。
  - ⇒ 「resolve は通るが TLS session を張らない」。残る仮説:
    (1) billing が `connect` でなく **WSAConnect/ConnectEx**(未フック)を使う、
    (2) billing 接続が **ALL.Net PowerOn 認証**(naominet.jp servlet, FUN_00a021d0)成功に gate され、その結果を keychip PCPA emu が満たせていない、
    (3) **accounting は実 billing 活動(credit transaction)時のみ TLS を張る**＝attract/boot では resolve のみの preflight で idle が正常。
  - **見立ての転換**: billing ready は TLS:8443 session ではなく **ALL.Net PowerOn 認証完了で立つ可能性**が高い(仮説3が有力。
    `alpbEx_billing_poll` case2 の StartAccountingReport は報告事象がある時のみ)。だとすれば B の本丸は TLS server ではなく
    **PowerOn 認証経路の完備**(keychip/amNet PCPA 側)になる。次probe = WSAConnect/ConnectEx フック追加(仮説1否定)
    ＋ localhost PCPA で PowerOn servlet 交換が起きているか/billing-enable を返しているか観測。
- **U2 TLS 信頼**: TLS1.1 keychip 署名 CA。client の trust store 構築経路を RE。keychip エミュ(mxkeychip.c)が CA を握れれば自前 cert 受理。
- **U3 alpb プロトコル**: PowerOn 認証→billing session の req/res 列が +0x1c を 8 へ駆動。純正(`system\`)を正に、TeknoParrot は補助で再 RE。

### [S] 2026-06-30 仮説3 決着（enabled の出所を全数確認）= 安価撤去は不可能
- `alpbEx_billing_enabled` を **1 にするのは `alpbEx_reset_state`(0x6FFC50) と `alpbExInitialize`(0x6FFD60)、いずれも無条件**。
  **`=0` にする経路はコード上どこにも無い**（全 xref が `==0` 読み or `=1` 書き）。billing OFF スイッチ非存在。
- ⇒ `pras_billing_ready_check` = `ready||（enabled==0）` の第二項は永久に偽＝厳密に `ready!=0` 必須。
  `ready=1` は `alpbEx_billing_poll` の **status 2/8 のみ**（network 駆動 obj+0x1c。PowerOn 経路は無い）。
- **結論**: `enabled=0` による安価撤去は不可能。両パッチ撤去は (B) billing プロトコルを実装し status→8 へ駆動するしか無い。
  U2 観測で boot/attract では TLS session 自体が張られない事も判明済＝B は protocol RE を伴う重い道。

### 撤去オプション整理（コスト昇順）
- **A**（✅実施済 2026-06-30）: `0xA065C0` を 5→**8**。status 8 が `alpbEx_billing_poll` case8 で ready=1 を立て(accounting 開始せず)、
  `0x701280` 撤去・**パッチ 23→22**。差分ライブ実証済(SYSTEM_STARTUP 完走=scene 稼働, billing/state7 エラー無し)。byte patch は1個残る。
- **C**（中間）: `alpb_get_status_field`(0x9CEEF0) or `alpbExGetExecStatus`(0xA065C0) を host hook で 8 返し。両 byte patch 撤去だが host hook 1個増。
- **B**（正攻法・重）: TLS:8443 billing server emu で内部 SM を status 8 へ。両パッチ撤去＝billing メモリ無改変。U2(TLS cert/keychip CA)+U3(alpb protocol) の再 RE 必須。boot/attract では未接続のため、起動到達だけが目的なら過剰。
