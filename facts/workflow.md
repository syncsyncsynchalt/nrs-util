# 作業方法論と運用知見（プロジェクトメモリ）

横断的な作業知見。サブシステム固有事実は `facts/<subsys>.md`、live bug/anti-pattern は `facts/bugs.md`、索引 `_index.md`。

## 自律ゲームテスト（起動と検証）

nrs.exe を自分で起動・注入し `nrsedge.log`(JSONL) を読んで挙動を検証する統合テストを自律実行できる。

**鉄則：自律テストの起動/終了/状態把握は必ず `loader.exe <verb>` CLI を使う**（`Start-Process`/`Stop-Process` 直叩き・ログ手読みは phase/errors/subsys を取りこぼす）。
`loader.exe` は dual-mode（引数なし=GUI / 引数=ヘッドレス CLI＝stdout に JSON＋機械可読 exit code）。1 コマンド=1 呼出で完結する（詳細な反復ループは `../CLAUDE.md`「ビルド・反復」）：

```
loader.exe start --wait        # 起動+注入し host.ready まで block。exit 0=ready / 2=timeout / 3=注入失敗 / 4=早期exit
loader.exe status              # 集約状態を JSON 出力。exit 0=ready / 5=未ready / 6=未起動
loader.exe wait --event jvs.io --timeout=20   # 任意 ev 出現まで block。exit 0=found / 1=timeout
loader.exe logs --cat error --tail 20         # ログを host 側分類でフィルタ（cat/subsys/grep/tail）
loader.exe stop                # nrs.exe を taskkill
loader.exe restart --wait      # stop→start
```

- **観測窓(ログ GUI)は help/stop 以外の全動詞で必ず出す**（不在なら spawn・既存は再利用/前面化）。ヘッドレスモードは無い。polling(status/wait/logs)中に窓が閉じても次の動詞で復活。
- **単一インスタンス／ライフサイクル保証**（名前付き mutex + Job）: GUI は 1 つだけ（`nrs_edge_gui_singleton`）／`nrs.exe` も 1 つだけ（launch を `nrs_edge_launch_lock` で直列化・start 連射は `already_running`）／**GUI を閉じる/落ちると nrs も終了**（GUI 保有の `KILL_ON_JOB_CLOSE` Job に nrs を登録。WM_DESTROY で即 kill、Job が backstop）。CLI 動詞プロセスは並行実行可（status polling を妨げない）。
- 対象 exe の既定は `C:\src\bbs\nrs.exe`（env `NRS_GAME_DIR` か `--game-dir DIR` で上書き）。
- `start` は host.dll/logic.dll をゲーム dir へ自動コピー → **起動ごとの専用ログ** `C:\src\bbs\logs\nrsedge-<時刻>.log` を作り
  host へ env `NRS_LOG_FILE` で渡す＋直近パスを `nrsedge.logpath` に記録 → `nrsedge.status.json` を初期化 →
  SUSPENDED 起動 → 注入 → resume（GUI ▶起動と同一の `core_launch`）。既に nrs.exe が走っていれば二重起動を避け `already_running` を返す。
  `logs`/`wait` は `nrsedge.logpath` 経由で最新起動のログを対象にする（別プロセスでも一貫）。GUI ログ窓は ▶起動ごとに自動クリア＝前回起動分を混ぜない。
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
- **phase は「boot 進行＋終端(exited)」だけを表す。** `phase=error` は host-init が確実に失敗する `hooks.fail`/`logic.load.fail`（＝host.ready が永遠に来ない）のみ。attract の良性ゲーム error（例 "Failed to check application data area"・`amBackupRecord error(-3)`）は `errors` カウンタを増やすが phase は動かさない＝`start --wait` を誤って失敗(exit 4)判定しない。`status.c` の breadcrumb で扱う。
- **status.json は明示停止(`stop`/`taskkill`)で削除、自滅は `ExitProcess` フックで phase=exited。** だから「こちらが止めた(file 無=`none`)」と「ゲームが落ちた(`exited`+last_error)」を区別できる。`status` の running 判定はプロセス存在(Toolhelp)が正、JSON の phase は補助。
- **PowerShell 5.1 の `Get-Content` は既定 ANSI で UTF-8 を cp932 誤読し文字化け＋`ConvertFrom-Json` 失敗する。** UTF-8 ファイル(tasks.json 等)を読む時は `-Encoding UTF8` 必須。loader CLI の JSON 出力は WriteFile 直書きなので問題ないが、ファイルを読み直す検証で踏む。

## 静的解析と動的デバッグは両輪（片方で止めない）

Ghidra 静的解析だけで完結させず動的デバッグを標準併用する。静的像と実行時像は CrackProof の自己書換え・unpack 後再初期化・実行時 FS/デバイス状態依存でズレる（例：`PcbRegion` 0x16014C4 は writer 無しなのに unpack で 1→0 に戻る）ため、片方の像だけで挙動・撤去可否・修正を確定しない。一次観測=logic の JSONL ログ＋`nrsedge.status.json`、静的に取れない分岐/値/クラッシュ点は cdb で実体を取る（**CLAUDE.md の「稀に cdb」は下限であって上限ではない**）。実走で見えた事実は Ghidra に書き戻して複利化する。

## 「できない・効かない」系は実体で再導出する

docs/コメントの「できない・クラッシュ・効かない」系は Ghidra＋実走ログで再導出してから信じる。推測で機構を当てない。
実例: 静的推測でフィックスを2回外した（TEST モードのエッジ合成／hold-always）。実走ログ（test/194c/cooked 全段 OK なのにメニュー不在）で初めて「入口は 0x160194c でなく scene id 要求」と判明。
ブロッカーは推測フィックス前に実走ログで連鎖の切断点を切り分ける。必要なら変化時のみ出す診断計装を足す。

## パッチ監査：read-fake と action-block の区別

不要パッチを判定するときは、パッチの種類を実体で見極めてから撤去を決める。

- **read-fake**：状態の偽装（device presence/status を固定値にする等）。エミュが実状態を正規経路で供給すれば冗長化しうる。撤去候補。
- **action-block**：行為そのものの阻止（例 0x457AF0 = `delete_directory_recursive` を RET0 で無効化し、keychipSM_FSM case4 の appdata 不一致時の実ディレクトリ再帰削除を止める）。エミュが供給できる代替が無いので、エミュ完成度と無関係に冗長化しない。撤去は危険。

注記は信用せず Ghidra で実体関数まで確認する。本プロジェクトでは旧 Frida からの移植でコメントだけ古いまま運ばれており、注記ドリフトを複数摘発した：
0x457AF0「keychip crash helper」→実体 `delete_directory_recursive`、0x6FF980「getstatus gate」→実体 `hlsm_region_check`、0x701280「FreePlay」→実体 `pras_billing_ready_check`。
撤去可否が静的に確定できないとき（到達ガードが実行時 FS 状態に依存する等）は、誤撤去の代償が不可逆なら保持する（リスク非対称）。詳細は `facts/bugs.md` の [RISK] 0x457AF0。

### 撤去テストの合格基準は「SYSTEM STARTUP 全行＋ERROR 不在」（「attract 到達」では不十分）[L]

パッチ撤去の検証で **「attract に到達するか」だけを見るのは誤り**。実例: region/storage/billing パッチを撤去しても attract には到達したが、
**SYSTEM STARTUP の途中に "ERROR." が表示**されていた（CHECKING NETWORK OK 直後）。`amlib_master_errCode`(0x16f5af0)は
**最初に立った errCode を latch**するので、撤去した各パッチが抑止していた error が**カスケードで次々 surface**する（region 4→board-index 0xa→billing 0x15→…）。
最初の latch error が後続を mask するため、attract だけ見ると複数の latent error を見逃す。
- **正しい手順**: プロセス内蔵 GL キャプチャ(`capture.req`→`capture.png`)で **SYSTEM STARTUP を早期〜完了まで複数スクショ**し、
  全 `CHECKING …` 行が OK（EXTEND IMAGE … NG は標準筐体で正常・非ブロッキング）かつ **"ERROR." 行が無い**ことを確認する。計装なら `boot_diag`(errCode 観測)。
- region/storage/billing は keychip/board/課金の**標準筐体ハード/サービス補償**で互いに連鎖＝個別撤去不可。presence(card/touch)のみ実 device emu で真に冗長。

### エミュ供給のタイミング（CrackProof clobber と決定的 hook 点）[L]

「NOP でなくデータ供給」でパッチを置換する際、**供給タイミング**が成否を分ける（`静的パッチの clobber` の発展）。
- bind 時(CREATE_SUSPENDED, entry 前)の .data/.bss 書込みは **CrackProof アンパックが後で再初期化して消す**（PcbRegion 0x16014C4 は writer 無しなのに 1→0 に戻った）。
- `on_jvs_tick`(per-frame)は早期 init チェックに**間に合わない**（amlib_master_init は最初の on_jvs_tick より前に走る＝errCode latch 済）。
- `on_create_file`(ファイル open 時)は amlib 早期 init に重なるが**ファイル open タイミング依存でレース**（チェックの前後が run ごとに振れる）。
- ⇒ 早期 init チェック(amlib_master_init の region 等)の直前にデータ供給するには **対象 init 関数を gamehook で detour**する必要がある（host 変更＋restart）。
  名前ベース device は `mxdev_*`/`*_force_ready`、関数フックは `host/gamehook.c` の detour 機構を使う。
- 多目的 global に注意: `DAT_01696ad8` は is-DVD 判定と**筐体ロール(1=SERVER)**を兼用＝0 にすると SERVER→SATELLITE 表示が壊れる。安易に書かず実体を確認。

## GUI 挙動の検証（Windows 固有の罠・PS 5.1）

loader GUI（ログ窓など）の挙動を外部スクリプトで観測・検証するときの定石。実例＝「ログ窓 spawn 時に前回ランのログが流れる」バグの検証（`cli_ensure_gui` が `NRS_TAIL_SKIP` に旧ログパスを渡し、tail_thread が初見ファイル==G_LOG なら末尾追従・別なら先頭読み。commit 111f7ec）。

- **GUI ウィンドウ観測は前面（対話ウィンドウステーション）から行う。** PowerShell `Start-Job` の子は**非対話 window station**で走り、対話デスクトップのウィンドウを `EnumWindows`/`FindWindowW` で列挙できない（全区間 `noGUI` になる）。バックグラウンド並行が要るなら「`Start-Process` で対象を非同期起動＋前面ループでサンプリング」にする。
- **ネイティブコールバック内の出力はホスト出力に流れない。** `EnumChildWindows` の scriptblock delegate から `Write-Output` しても消える。`$script:` スコープの配列に溜め、列挙後にまとめて出す。
- **owner-draw ログ窓は WM_GETTEXT で読めない。** 同僚の仮想ログビュー(`nrsLogView`)導入後は行本文が取れないので、行数は `g_logstatus`（`nrsLogView` の直後の Static）の「総数 N」から読む。
- **PS 5.1 の `-File` はスクリプトを ANSI 解釈**（BOM 無し UTF-8 だと日本語コメントが誤デコードされ**次行を飲む**＝`New-Object`/`foreach` が null 化する謎バグ）。**テストスクリプトは ASCII のみで書く**（実行時にウィンドウから読む日本語データは可）。
- **一瞬流れて消える系バグの検証は「陽性対照＋実経路」を対にする。** ①検出器が本当に洪水を見えること（逆条件で前回ログ全量=総数N が読める）と、②実 `loader.exe start` の本物の `cli_ensure_gui` 経路でフレッシュ GUI が旧ログを流し込まないこと、の両方を示す。合成 env を手で設定しただけ・最終状態だけの確認は片手落ち。`core_launch` は game 起動前に無条件で新ログ作成＋ポインタ切替するので、遷移前の「ptr=旧ログ」窓を前面高速サンプリング（Add-Type 事前ウォーム）で捉える。
- **「Claude 実行時にログ窓が出ない」の主因＝背景 spawn 窓の非アクティブ化**（commit で fix 済）。`cli_ensure_gui` が GUI 不在時に自分自身を無引数 spawn するが、生成主(loader CLI)が非フォアグラウンドなので Windows の foreground 制限で新窓がアクティブ化されず**ユーザーの窓の裏に開く**（人間の VSCode ▶起動は前面なので露見しない＝「あなたが実行するとき」限定症状）。fix＝spawn 分岐で `WaitForInputIdle`→`FindWindow` ポーリング→`gui_raise`（`SWP_NOACTIVATE` 付き TOPMOST↔NOTOPMOST トグル＝**フォーカスを奪わず Z オーダーだけ浮上**）。窓生成を待つ副次効果で cmd_start の 1604→1491 二重 spawn レースも解消。polling 動詞(status/wait/logs)は既存窓に raise=0＝**引っ張らない**（手前の作業窓を奪い返さない）を維持。
- **単一化機構(mutex+FindWindow)は無実。** 既存 GUI ありで `status` を叩いても重複 spawn は 0（loader 自身の `FindWindow` は正常）。※計測用 PS/.NET スレッドからの `FindWindowW`=0 は CLR スレッドのデスクトップ束縛アーティファクトで、`EnumWindows` は同窓を可視で列挙できる（loader 本体の判定とは無関係）。窓は WinSta0\Default・session 1（実対話デスクトップ）に実在。
- **窓の「浮上したか」は `EnumWindows` の Z オーダー(topmost first)で測る。** 手前に Notepad を `SetForegroundWindow` で置き、`status`/`start` 後に対象窓の rank を見る（rank=0=最前面）。フォーカス非奪取は `GetForegroundWindow` が対象窓でないことで確認。
- **loader.exe は GUI サブシステム(PE subsystem=2)。** シェルは終了を待たず、`start --wait` でも PS の `$LASTEXITCODE`/stdout が**空**になり得る（Claude が JSON/exit を取り損ねる）＝観測性の残課題。判定は `nrsedge.status.json`/ログ成長で取る（プロセス非同期に依存しない）。job 影響は主因でない: PowerShell tool の job=KILL_ON_JOB_CLOSE+SILENT_BREAKAWAY、Bash tool の job=LimitFlags 0 → どちらも spawn GUI は生存。

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
