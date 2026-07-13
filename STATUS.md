# STATUS — 現在地と次の一手

> 履歴は `git log` を正とする。本ファイルは現在地・到達点・次の一手のみを保つ（完了フェーズの逐次記録は残さない）。

## 現在の作業ツリー

ALL.Net 層の bring-up に着手中。未追跡 `src/host/allnet.c` ＋ `src/host/gamehook.c`/`host.c`/`host.h`・`src/logic/api.c` を変更中。
直近コミット `card in`/`broken` は WIP でツリー未確定。

## 到達点（実写確認済み）

boot は SYSTEM STARTUP を全行 OK で完走し（IC CARD/TOUCH/NETWORK/EXTEND IMAGE OK/ALL.NET AUTH/UPLOAD/GAME SERVER/LOCAL）、
COMPLETE → WARNING → BORDER BREAK Scramble タイトル → attract「画面をタッチしてください」(FREE PLAY) に到達する。
タッチ → GP 購入画面（260/520/1300 GP・SYSTEM OPERATOR FIONA）も確認済み。

- **touch（COM1）完動**: serial プロトコルを実エミュ（`src/logic/driver/touch.c`）。handshake 完了で "touch panel ok"、押下・座標・離しまで正常消費（`facts/devices.md`）。
- **card reader（COM2）完動**: SEGA 独自 IC Card R/W を byte-exact でエミュ（`src/logic/driver/card.c`）。init handshake 完走で "card slot ok"、SEARCH→select→read→commit→halt が完走（`facts/devices.md`）。
- **errCode カスケード解消**: 0910(board-table)/0951(keychip)/region/billing/extend-image を genuine 供給で通過。error scene は latch 後に消えないため未然防止で断つ。
- **genuine 化の方針**: host gamehook ＋ keychip PCP 応答のみで解き、ゲームメモリの静的パッチは追加しない。現在 `patches.applied=15`。

## 残 15 パッチの構造

- keychip-serial region NOP 6 / action-block 2（`0x457AF0` delete_directory_recursive・no-selfshutdown）/ billing no-OFF 1。
- network/region cluster 4（`FUN_006ff900` の ALL.Net region 供給で束撤去＝Phase B2）。
- infra 1（COM4 文字列）/ is-DVD 1（`DAT_01696ad8` 多重 global 脱結合が要るため撤去不可）。

read-fake の安い撤去は取り切った。次の削減は network/region 層の大仕事（Phase B2）。

## フロンティア（次の一手）

**【解決】ALL.Net NUPL セッション init ハンドシェイク**（旧ブロッカーの中核）: standalone は init 応答が拒否され `NUPL obj+0xd8:1→-1` で無限リトライ＝session 未確立だった。真因＝応答の `command` field が `"init_response"` でないと init パーサ `nupl_init_response_parse`(0x92bb10) が -1 を返すこと（＋local_uid/db_start_time/db_stop_time を top-level field で要求）。`src/host/allnet.c build_nupl_inner` init 枝を修正し **headless で確証**: `nupl.state d8:0 sm:2`（init 受理・session 前進）、`alabex.diag authok:1 lan:1`。詳細 `facts/devices.md`。診断 host hook `d_recv_parse`(gamehook 0x712710) 常駐。

**【解決・cdb 実証 2026-07-12】NUPL session SM state2 deadlock**（cardinfo が飛ばない真因）: cardinfo 送信ゲート `FUN_00717620` は sm==3 を要求するが SM は state2 停滞だった。cdb で `FUN_007137a0`(state2 handler)の advance-block(`FUN_00714230` 0x713826)が一度も hit せず、`FUN_00713550` が常時 true を返すことを確定。真因＝`FUN_00713550`→`FUN_0076de00`(時刻 window gate)。scheduled time obj+0x20185/0x20187 は state1 gate `FUN_00713eb0` が init 応答の db_start/db_stop_time の {hour,min} から格納。**fix: `allnet.c` の db_stop_time を 23:59 に**（終日 open）→ cdb で `FUN_0076de00`=-1 実測 → deadlock 解消。**session が前進し game が `attend_request` を送出**（init→attend）。詳細 `facts/devices.md`。

**【解決・cdb 実証 2026-07-12】ALL.Net session sm=2→3 確立**（core blocker 解消）: attend_response が deep parse(`FUN_00902040`) を通り state handler `FUN_007137a0` が `FUN_00714230()==0` で **SM を 3 へ前進**。要件（全て cdb 実証、詳細 `facts/devices.md`）: ①区切り="del" ②全フィールド非空値（pre-split が key=value 厳密2要素を要求・空値で C++例外）③複合配列は境界 stride 分多め token（rules=4000/ranking=240/map_id=40 等、overshoot 無害）④ms_close/ms_open/ms_maintenance_time/*_update を datetime 化（state handler が FUN_007230f0 再パース）⑤**book_keep_flg=base64 blob**（FUN_00722f20 base64 decode, len<4 で fail）。実装 `allnet.c build_session_config`。**sm=3 到達で game は params/seal/cap/advertiseinfo/ping を送出開始（d8:0 健全・0 fail）**。

**【到達 2026-07-12】カード選択 scene まで到達・「このカードは使用できません」の真因特定**。sm=3 session 確立で game は正規 boot 完走（attract/全国ランキング → touch → カード選択）。touch 注入(`nrsedge.touch.json` press/xm/ym‰)＋card 注入(`nrsedge.card.json` present/gen)で card-select 操作可。card 読取は成功（UID）だが **card_read_sm(0x671470) の UID whitelist で拒否 res:-97**（機構: bypass `0x16a55ba` / count `0x16a55ad` / UID配列 `0x16a55b0`。count!=0 かつ UID 不一致で halt 再照合 fail→`DAT_0169e368=1`→default case で -97。res は `card_transport_pump` が card_read_sm 戻り値を `DAT_016ae540` へ）。

**【解決 2026-07-13】ALL.Net 抑止パッチ全撤去 → genuine ブート完走（patches 15→8）**。device_status/region パッチ等を撤去し OS 境界エミュのみで boot 完走を達成。撤去で露出した2つの真ブロッカーを genuine 解決:
- **CHECKING CONNECTION の idx4(LOCAL GAME SERVER)無限待機**: 真ゲートは表示ループが status≠1 を待つこと（m1ec=manager+0x1ec=0 ゆえ本来通過可）。idx4 は LfsClient(Local game server)の接続不成立で status1 のまま。**LFS プロトコル(UDP探索:30001→TCP:30000, magic"LFSS")を RE し genuine 実装**（host/allnet.c）: h_sendto が探索 broadcast 0.0.0.0:30001→127.0.0.1:30001、h_connect が :30000→自前 responder 127.0.0.1:40130、`lfs_client` が accept 直後に 28B accept(flags bit0=1) push。connres=0→idx4=2 で突破。詳細 `facts/devices.md`。
- **boot 後 MMNW シーンの delivinst(配信インストール)未応答リトライ**: parser delivinst_response_parse(0x916150)の全必須 field を実装（instruction_interval=厳密4個/instruction_cloud=厳密48個の comma int-list 他）。受理で ALL.Net セッション完走(init→…→delivinst)→前面メニュー(TMNU, sig 5e43c280)到達。

**現ブロッカー = card 受理（元来の目的「このカードは使用できません」）**。card_read_sm(0x671470)の UID whitelist で res:-97。過去に bypass を3手法(logic global/gamehook/static patch)試すも **~13s で再強制**（CrackProof 整合性復元疑い）。∴ genuine 策 = **エミュレートカードの UID を whitelist 配列(`DAT_016a55b0`, count `DAT_016a55ad`)の期待値に一致させる**（再強制と戦わない）。whitelist は static writer 無し＝初期化データ/計算アドレス、要 runtime 観測。次: runtime で whitelist UID 群＋我々の読取 UID(`DAT_0169e314`)を diag 突合し card.c の提示 UID を整合。cardinfo(TEXT 45-field parser 0x90fed0)は本ゲート後段。

1. **entry-mode マネージャの sel 進行 gate**（`facts/gameflow.md`）: EntryMode シーン factory は `entrymode_scene_factory`(0x5ec6e0)。
   呼び出しは間接（マネージャの vtable slot 経由）で、sel を進める条件が attract→credit/card-auth の真の gate。
   session 確立が gate を開くか要確認（GUI で coin/touch→credit を実写）。cdb live トレース（0x5ec6e0 bp→戻り先 stack）が最短だが、headless は attract 手前で ~50% 停滞するため GUI/実機向き。
2. **カード情報応答**（`facts/devices.md`, 実装 `host/allnet.c`）: card-auth scene(0x5e6200) は読取 UID を `NetDataCardinfoRequest` として NUPL 経由で naominet.jp:80 へ POST。
   allnet.c が connect を 127.0.0.1:40080(ALLNET_PORT) へ振替え `NetDataCardinfoResponse`(5611B) を返す。前提: PowerOn(alAbEx auth) が stat=1+uri= を返さないと POST 先 URL が空（parser `FUN_006fe670`→`DAT_0210b530`）。プロフィールはサーバ側、カード(4032B)は ID に過ぎず forge 不要。
3. **Phase B2 = ALL.Net 層エミュ**: network/region cluster 4 の束撤去、card-info 応答、extend-image の実配信 install SM 完走を同層でまとめる。

## 未確定（要 RE）

overlapped シリアルの厳密な作法 / MMGP txn を成功させる最小経路（'E'/0x45 タスク 0x2206 応答 result=2）/ billing の TLS session を張る条件（`facts/ambilling.md` の仮説3）。

## ビルド・反復

- 人間: VSCode タスク「👤 ビルドして GUI を開く」（全ビルド→統合 GUI `loader.exe` 起動）。
- 自律: `loader.exe start --wait` / `status` / `stop`（`facts/workflow.md`「自律ゲームテスト」）。logic 変更は host が auto-swap。
- 永続 struct レイアウト変更時のみ restart。`abi.h` 変更は host+logic 両方の再ビルド＋restart。
- host 変更時は host.dll を loader cwd(nrs-util) と nrs cwd(bbs) の両方へ配置。

## 再開点 (2026-07-13 中断)
- **停止状態クリーン**: ゲーム stop 済 / Ghidra DB graceful 保存済（書き戻し焼込済）/ 全パッチ8個（ALL.Net 抑止パッチは全撤去済、残るはハード/クラッシュ対策のみ）。
- **genuine 化 完了層**: NUPL sm2→3 / NIC・LAN / keychip(40106) / amInstall(40102) / amGfetcher(40113)。device_status patch(0x72DCE0) 撤去済。
- **残ブロッカー**: CHECKING CONNECTION の device status 配列 idx2(UPLOAD)/idx3(GAME SERVER)/idx4(LOCAL) が 2(OK) に至らず（実測 3 or 1）。amStorage(40114) は query_storage_status を56回ループ（check=0/format=0 では ready 判定されず、amStorageWaitReady FUN_0097b440 の 18状態 SM）。
- **次の一手（RE 中）**: device status **書き込み側**を特定。getter 0x72dce0 は `*(*(int*)(manager+4) + 0x1d4 + idx*4)`（idx1=+0x1d8..idx4=+0x1e4）と確定。次は 0x72d000-0x72e000 帯の setter を xref で特定し、idx2/3/4 各デバイスタスクが status=2 を書く gating 条件（PCP/HTTP 応答 field）を確定 → amInstall/amGfetcher と同じ手法で整合応答を実装。
