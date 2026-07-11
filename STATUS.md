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

**残ブロッカー = credit/card-auth scene 到達＋cardinfo 応答**。session 確立で attract→credit 経路は unblock 済だが最終確証は GUI+実タッチが要る（headless は attract で ~50% 停滞・card-select 到達不可）。

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
