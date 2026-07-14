# STATUS — 現在地と次の一手

> 履歴は `git log` を正とする。本ファイルは現在地・到達点・次の一手のみを保つ（完了フェーズの逐次記録は残さない）。
> RE 事実は `facts/<subsys>.md`、関数/型/コメントの正は Ghidra DB。

## 現在の作業ツリー

genuine ブート完走まで到達（allnet.c の LFS エミュ含め commit 済）。現在の焦点は **card 受理**
（元来の目的「このカードは使用できません」）＝ card_read_sm の UID whitelist 突破。

## 到達点（実写確認済み）

boot は SYSTEM STARTUP を全行 OK で完走し（IC CARD/TOUCH/NETWORK/EXTEND IMAGE OK/ALL.NET AUTH/UPLOAD/GAME SERVER/LOCAL）、
COMPLETE → WARNING → BORDER BREAK Scramble タイトル → attract「画面をタッチしてください」(FREE PLAY) に到達する。
タッチ → GP 購入画面（260/520/1300 GP・SYSTEM OPERATOR FIONA）も確認済み。

- **touch（COM1）完動**: serial プロトコルを実エミュ（`src/logic/driver/touch.c`）。handshake 完了で "touch panel ok"、押下・座標・離しまで正常消費（`facts/devices.md`）。
- **card reader（COM2）完動**: SEGA 独自 IC Card R/W を byte-exact でエミュ（`src/logic/driver/card.c`）。init handshake 完走で "card slot ok"、SEARCH→select→read→commit→halt が完走（`facts/devices.md`）。
- **ALL.Net 層 genuine 化 完了**: NUPL play-session を sm2→3 まで確立し init→attend→params→seal→cap→advertiseinfo→ping→delivinst を完走。
  keychip(40106)/amInstall(40102)/amGfetcher(40113)/amGcatcher(40110)/amStorage(40114) の各 SM を実応答で one-shot 化。
  CHECKING CONNECTION は SERVER ロールで通過（SATELLITE は UDP :30001 探索応答が未実装。詳細 `facts/devices.md`）。
  実装は `src/host/allnet.c`/`keychip_proto.c`、詳細事実は `facts/devices.md`/`facts/mxgfetcher.md`。
- **genuine 化の方針**: host gamehook ＋ PCP/ALL.Net 応答のみで解き、ゲームメモリの静的パッチは追加しない。現在 `patches.applied=8`。

## 残 8 パッチの構造（`src/logic/patches.c` が正）

- **必須（維持）3**: billing `0xA065C0`(→8) / `0x457AF0` delete_directory_recursive nop（RET8_0・撤去禁止, `facts/bugs.md`）/ `0x4FDA50` is-DVD-boot→0（Error 913）。
- **amGfetcher download 分岐 3**: JL2JMP `0x97588A`/`0x97595F`/`0x975A1F`（jl→jmp）。genuine ALL.Net 化で冗長の可能性・撤去検証中。
- **infra 2**: self-shutdown `0x6C3F20`(je→jmp) / COM4 文字列 `0xAE11F0`(cfg->jvs_com へ)。

ALL.Net 抑止パッチ（device_status `0x72DCE0` / region `0x986A66`ほか）は genuine 化で撤去済（patches.c にコメントアウト残置）。

## フロンティア（次の一手）

**現ブロッカー = card 受理**。card_read_sm(0x671470)の UID whitelist で res:-97。過去に bypass を3手法(logic global/gamehook/static patch)試すも **~13s で再強制**（CrackProof 整合性復元疑い）。∴ genuine 策 = **エミュレートカードの UID を whitelist 配列(`DAT_016a55b0`, count `DAT_016a55ad`)の期待値に一致させる**（再強制と戦わない）。whitelist は static writer 無し＝初期化データ/計算アドレス、要 runtime 観測。次: runtime で whitelist UID 群＋我々の読取 UID(`DAT_0169e314`)を diag 突合し card.c の提示 UID を整合。cardinfo(TEXT 45-field parser 0x90fed0)は本ゲート後段。

1. **entry-mode マネージャの sel 進行 gate**（`facts/gameflow.md`）: EntryMode シーン factory は `entrymode_scene_factory`(0x5ec6e0)。
   呼び出しは間接（マネージャの vtable slot 経由）で、sel を進める条件が attract→credit/card-auth の真の gate。
   session 確立が gate を開くか要確認（GUI で coin/touch→credit を実写）。cdb live トレース（0x5ec6e0 bp→戻り先 stack）が最短だが、headless は attract 手前で ~50% 停滞するため GUI/実機向き。
2. **カード情報応答**（`facts/devices.md`, 実装 `host/allnet.c`）: card-auth scene(0x5e6200) は読取 UID を `NetDataCardinfoRequest` として NUPL 経由で naominet.jp:80 へ POST。
   allnet.c が connect を 127.0.0.1:40080(ALLNET_PORT) へ振替え `NetDataCardinfoResponse`(5611B) を返す。前提: PowerOn(alAbEx auth) が stat=1+uri= を返さないと POST 先 URL が空（parser `FUN_006fe670`→`DAT_0210b530`）。プロフィールはサーバ側、カード(4032B)は ID に過ぎず forge 不要。

## 未確定（要 RE）

overlapped シリアルの厳密な作法 / MMGP txn を成功させる最小経路（'E'/0x45 タスク 0x2206 応答 result=2）/ billing の TLS session を張る条件（`facts/ambilling.md` の仮説3）/ SATELLITE ロールの UDP :30001 探索応答エミュ。

## ビルド・反復

- 人間: VSCode タスク「👤 ビルドして GUI を開く」（全ビルド→統合 GUI `loader.exe` 起動）。
- 自律: `loader.exe start --wait` / `status` / `stop`（`facts/workflow.md`「自律ゲームテスト」）。logic 変更は host が auto-swap。
- 永続 struct レイアウト変更時のみ restart。`abi.h` 変更は host+logic 両方の再ビルド＋restart。
- host 変更時は host.dll を loader cwd(nrs-util) と nrs cwd(bbs) の両方へ配置。
