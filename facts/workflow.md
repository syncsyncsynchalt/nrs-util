# 作業方法論と運用知見（プロジェクトメモリ）

nrs-edge 開発で得た横断的な作業知見を集約する。
サブシステム固有の事実は `facts/<subsys>.md`、live bug/anti-pattern は `facts/bugs.md`、索引は `_index.md`。
（旧ユーザー単位メモリをここへ移管。以後の知見もこのファイルに追記する。）

## 自律ゲームテスト（起動と検証）

nrs.exe を自分で起動・注入し `nrsedge.log`(JSONL) を読んで挙動を検証する統合テストを自律実行できる。

**鉄則：自律テストの起動/終了/状態把握は必ず `loader.exe <verb>` CLI を使う。** GUI への PostMessage ハック・
`Start-Process`/`Stop-Process` の直叩き・ログの手読みは使わない（脆く、phase/errors/subsys を取りこぼす）。
VSCode タスクなら 🤖 系（`🤖 nrs: 起動→ready待ち` / `状態` / `終了`、`🤖 テスト: build(host+logic)→restart→ready`）。
ログ照会は `loader.exe logs --cat|--subsys|--grep|--tail` を端末で直接（人間は GUI のログタブ）。

**正しい起動方法（headless CLI, 2026-06-29 更新）**：`loader.exe` は dual-mode。引数なし=従来 GUI、
**引数あり=ヘッドレス CLI**（GUI を作らず stdout に JSON、機械可読な exit code を返す）。旧 PostMessage ハックは不要。
1 コマンド = 1 呼出で完結する：

```
loader.exe start --wait        # 起動+注入し host.ready まで block。exit 0=ready / 2=timeout / 3=注入失敗 / 4=早期exit
loader.exe status              # 集約状態を JSON 出力。exit 0=ready / 5=未ready / 6=未起動
loader.exe wait --event jvs.io --timeout=20   # 任意 ev 出現まで block。exit 0=found / 1=timeout
loader.exe logs --cat error --tail 20         # ログを host 側分類でフィルタ（cat/subsys/grep/tail）
loader.exe stop                # nrs.exe を taskkill
loader.exe restart --wait      # stop→start
```

- 対象 exe の既定は `C:\src\bbs\nrs.exe`（env `NRS_GAME_DIR` か `--game-dir DIR` で上書き）。
- `start` は host.dll/logic.dll をゲーム dir へ自動コピー → `nrsedge.log`/`nrsedge.status.json` を初期化 →
  SUSPENDED 起動 → 注入 → resume（GUI ▶起動と同一の `core_launch`）。既に nrs.exe が走っていれば二重起動を避け `already_running` を返す。
- **集約状態 `C:\src\bbs\nrsedge.status.json`** を 1 ショット読めば boot phase / errors / patches / 各 subsys ready が判る
  （ログ全行パース不要）。host が `host_log` の全イベントを観測し原子的に更新する（`src/host/status.c`）。
  `start --wait` / `status` はこのファイルを polling/読取して判定する。

**検証の勘所**：

- `status.json` の `phase`（attaching→hooks→logic→gamehooks→ready / exited / error）と `errors`/`patches` で起動到達点を即判定。
- `patches.applied` の **count 値**で「どの logic.dll が載ったか」を1行で判定（`status.json` の `patches`、または `logs --grep patches`）。
- 安定 attract の指標：phase=ready 到達後、`logs --subsys jvs`/`--subsys touch` が実時間で伸びる。errors 0 件。
  JVS の idle frame は `jvs_io_log` が dedup するので jvs.io が止まって見えても polling は回っている。
- 注入確認に 64bit PowerShell の `.Modules` は WOW64 で偽陰性。注入の証拠は `status.json`(phase 進行)とログ成長で取る。
- LogicState のフィールド追加は arena 上の状態レイアウトを変えるため hot-reload 不可。`restart` で再注入が要る。
- **phase は「boot 進行＋終端(exited)」だけを表す。** `phase=error` は host-init が確実に失敗する `hooks.fail`/`logic.load.fail`（＝host.ready が永遠に来ない）のみ。attract の良性ゲーム error（例 "Failed to check application data area"・`amBackupRecord error(-3)`）は `errors` カウンタを増やすが phase は動かさない＝`start --wait` を誤って失敗(exit 4)判定しない。これは実走で発覚したレース（良性 error が host.ready より先に届くと phase=error をラッチし start --wait が誤判定）の修正。`status.c` の breadcrumb で扱う。
- **status.json は明示停止(`stop`/`taskkill`)で削除、自滅は `ExitProcess` フックで phase=exited。** だから「こちらが止めた(file 無=`none`)」と「ゲームが落ちた(`exited`+last_error)」を区別できる。`status` の running 判定はプロセス存在(Toolhelp)が正、JSON の phase は補助。
- **PowerShell 5.1 の `Get-Content` は既定 ANSI で UTF-8 を cp932 誤読し文字化け＋`ConvertFrom-Json` 失敗する。** UTF-8 ファイル(tasks.json 等)を読む時は `-Encoding UTF8` 必須。loader CLI の JSON 出力は WriteFile 直書きなので問題ないが、ファイルを読み直す検証で踏む。

**Why**：旧来は GUI に `PostMessage(WM_COMMAND,ID_LAUNCH)` を撃ち、停止は `Stop-Process`、状態把握は 80k 行ログの
手読みだった（脆く AI から扱いにくい）。dual-mode CLI + `status.json` で「起動/終了/状態/待機/ログ照会」が
明確な exit code と JSON で完結する。`loader.exe`（引数なし）の GUI は人間用に従来どおり維持。

## 「できない・効かない」系は実体で再導出する

docs やコメントの「できない・クラッシュする・効かない」系の記述は、実体（Ghidra と実走ログ）で再導出してから信じる。
triage・日付つき訂正・推測で機構を当てない。

過去に静的 RE の推測でフィックスを2回外した（TESTモードのエッジ合成、hold-always）。
実走ログ（test/194c/cooked が全段 OK なのにメニュー不在）を取って初めて「入口は 0x160194c でなく scene id 要求」と判明した。
ブロッカー系は、推測でフィックスを当てる前に、まず実走ログで連鎖のどこが切れているかを切り分ける。必要なら変化時のみ出す診断計装を足して再実行する。

## パッチ監査：read-fake と action-block の区別

不要パッチを判定するときは、パッチの種類を実体で見極めてから撤去を決める。

- **read-fake**：状態の偽装（device presence/status を固定値にする等）。エミュが実状態を正規経路で供給すれば冗長化しうる。撤去候補。
- **action-block**：行為そのものの阻止（例 0x457AF0 = `delete_directory_recursive` を RET0 で無効化し、keychipSM_FSM case4 の appdata 不一致時の実ディレクトリ再帰削除を止める）。エミュが供給できる代替が無いので、エミュ完成度と無関係に冗長化しない。撤去は危険。

注記は信用せず Ghidra で実体関数まで確認する。本プロジェクトでは旧 Frida からの移植でコメントだけ古いまま運ばれており、注記ドリフトを複数摘発した：
0x457AF0「keychip crash helper」→実体 `delete_directory_recursive`、0x6FF980「getstatus gate」→実体 `hlsm_region_check`、0x701280「FreePlay」→実体 `pras_billing_ready_check`。
撤去可否が静的に確定できないとき（到達ガードが実行時 FS 状態に依存する等）は、誤撤去の代償が不可逆なら保持する（リスク非対称）。詳細は `facts/bugs.md` の [RISK] 0x457AF0。

### 撤去テストの合格基準は「SYSTEM STARTUP 全行＋ERROR 不在」（「attract 到達」では不十分）[L, 2026-06-30]

パッチ撤去の検証で **「attract に到達するか」だけを見るのは誤り**。実例: region/storage/billing パッチを撤去しても attract には到達したが、
**SYSTEM STARTUP の途中に "ERROR." が表示**されていた（CHECKING NETWORK OK 直後）。`amlib_master_errCode`(0x16f5af0)は
**最初に立った errCode を latch**するので、撤去した各パッチが抑止していた error が**カスケードで次々 surface**する（region 4→board-index 0xa→billing 0x15→…）。
最初の latch error が後続を mask するため、attract だけ見ると複数の latent error を見逃す。
- **正しい手順**: プロセス内蔵 GL キャプチャ(`capture.req`→`capture.png`)で **SYSTEM STARTUP を早期〜完了まで複数スクショ**し、
  全 `CHECKING …` 行が OK（EXTEND IMAGE … NG は標準筐体で正常・非ブロッキング）かつ **"ERROR." 行が無い**ことを確認する。計装なら `boot_diag`(errCode 観測)。
- region/storage/billing は keychip/board/課金の**標準筐体ハード/サービス補償**で互いに連鎖＝個別撤去不可。presence(card/touch)のみ実 device emu で真に冗長。

### エミュ供給のタイミング（CrackProof clobber と決定的 hook 点）[L, 2026-06-30]

「NOP でなくデータ供給」でパッチを置換する際、**供給タイミング**が成否を分ける（`静的パッチの clobber` の発展）。
- bind 時(CREATE_SUSPENDED, entry 前)の .data/.bss 書込みは **CrackProof アンパックが後で再初期化して消す**（PcbRegion 0x16014C4 は writer 無しなのに 1→0 に戻った）。
- `on_jvs_tick`(per-frame)は早期 init チェックに**間に合わない**（amlib_master_init は最初の on_jvs_tick より前に走る＝errCode latch 済）。
- `on_create_file`(ファイル open 時)は amlib 早期 init に重なるが**ファイル open タイミング依存でレース**（チェックの前後が run ごとに振れる）。
- ⇒ 早期 init チェック(amlib_master_init の region 等)の直前にデータ供給するには **対象 init 関数を gamehook で detour**する必要がある（host 変更＋restart）。
  名前ベース device は `mxdev_*`/`*_force_ready`、関数フックは `host/gamehook.c` の detour 機構を使う。
- 多目的 global に注意: `DAT_01696ad8` は is-DVD 判定と**筐体ロール(1=SERVER)**を兼用＝0 にすると SERVER→SATELLITE 表示が壊れる。安易に書かず実体を確認。

## 静的パッチの clobber

`patches_apply` は CREATE_SUSPENDED 注入のため entry より前に走る。
ゲームが init で書き直すグローバルは、静的パッチでなく init 関数の hook で開放する。
例：amDebug の logLevel/mask の静的開放は `amDebugInit`(0x55C500) に上書きされて脱落するため、`host/dbglog.c` が amDebugInit を hook して init 後に開放する。

## パッチ削減の定石（OS 境界エミュ化）

鉄則「ゲームメモリパッチは原則ゼロ＝OS 境界で仮想化」の実践。
パッチが偽装する値は、対応するデバイス/ファイルのエミュが正データを供給すればゲーム自身のチェックが自然通過して消える。3 つの型がある：

1. **既存デバイスエミュが既に供給** → そのまま冗長。例：platform "AAL" は columba DMI(`mxdevices.c build_dmi`)が OEM 文字列 index2="AAL" を供給済みで、`amOemstringGetOemstring` 経由で素の `amPlatformGetPlatformId` が "AAL" を返す。0x981FF0 撤去。
2. **既存エミュへ ctx を force-provision** → デバイスが SetupDi(PnP GUID)で開かれ standalone で列挙失敗する場合、ctx を直接再現して既存 IOCTL エミュへ流す。例：EEPROM(`eeprom_force_ready`)・dipsw(`dipsw_force_ready`、ctx base 0xccf488 に handle=H_MXSMBUS)。dipsw read の `DeviceIoControl(0x9c402004,cmd=5)` が mxsmbus エミュへ流れ、`mxdev_ioctl` が index0=0x20 を返して board index 2 を算出。0x45A0F5/F9 撤去。
3. **OS リソースの仮想供給** → CreateFile/ReadFile フックで仮想ファイルを返す。例：OsVersion が読む `C:\System\SystemVersion.txt` を `api.c` の on_create_file(sentinel 0xC0114002)/on_read_file(8 バイト ASCII)で供給。非ゼロ parse で `amPlatformGetOsVersion` が戻り 0 を返し、gate `FUN_0045a6f0` を通過。0x981D60 撤去。

撤去判断の前に「そのデバイスが standalone で実際にどう開かれるか（CreateFile by name か SetupDi PnP 列挙か）」を実体で確認する。名前ベースの host フック(`mxdev_create`)に乗るか否かが決まる。
検証は差分ライブテスト：パッチ撤去→起動→nrsedge.log で対応 error の不在と安定 attract を確認する。

## 日本語の清書

日本語の文書・コメントを書くときは `.agents/skills/stop-ai-slop-jp/SKILL.md` と `.agents/skills/japanese-tech-writing/SKILL.md` を読んで推敲する。
一文一行、用語定義は全角コロン、ダッシュ類と中黒並列を避ける、過度な断定を避け不確実性は保つ、AI 臭の空句を使わない。

## 脱 Python 移植

tools/ の Python 依存を native 化中。control_panel は C 化完了（`loader.exe` = 統合 GUI に吸収。起動/終了/再起動・FreePlay/TEST/Windowed・入力設定/テスト・ログ tail を担う）。
残りツールの移植も同方針。Python が残るのは `tools/ghidra_mcp/`（bridge / build_headless）程度。
