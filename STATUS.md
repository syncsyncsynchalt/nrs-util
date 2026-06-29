# STATUS — 現在地と次の一手

## フェーズ: ★パッチ削減（OS 境界エミュ化）+ 自律テスト起動法の確立 — 2026-06-29

**ゲームメモリパッチ削減**: `patches.applied count 29→25`（4 byte-patch 撤去）。鉄則「パッチ原則ゼロ＝OS 境界で仮想化」へ前進。
全てライブ確認済み（host.ready→安定 attract、errCode 0 件）:
- **platform "AAL"** (0x981FF0): columba DMI(`mxdevices.c build_dmi`)が OEM 文字列 index2="AAL" を供給済み＝冗長。
- **dipsw board index** (0x45A0F5/F9): `dipsw_force_ready`(`api.c`) が dipsw ctx を H_MXSMBUS で provision し、read の mxsmbus IOCTL(`mxdev_ioctl` cmd5, index0=0x20)へ流す。素の `amDipswRead` が board index 2 を算出。
- **OsVersion** (0x981D60): 仮想ファイル `C:\System\SystemVersion.txt`(`api.c` on_create_file/on_read_file)で 8 バイトを供給。
- 定石・詳細: `facts/workflow.md`「パッチ削減の定石」/ `facts/amplatform.md` / `facts/devices.md`。

**自律テスト起動法を CLI 化（2026-06-29）**: `loader.exe` を **dual-mode** 化。引数なし=従来 GUI、引数あり=ヘッドレス CLI。
`start --wait` / `stop` / `restart` / `status` / `wait --event` / `logs --cat|--subsys|--grep|--tail` を **JSON on stdout + 機械可読 exit code** で提供（旧 PostMessage ハック廃止）。
host が `host_log` 全イベントを観測し **`nrsedge.status.json`**（phase / errors / patches / subsys ready）を原子更新（`src/host/status.c`。abi 不変・logic 無改変）。
1 ショットで起動到達点が判る。`build host loader` 通過・read-only verbs ライブ確認済。手順は `facts/workflow.md`「自律ゲームテスト」。

**残りパッチ（高コスト・別タスク）**: network(amNet SM 解決 or NIC エミュ) / dongle・card・touch(新規デバイス protocol) /
billing(ローカル ALL.Net) / region(amJvsp keychip txn) / no_selfshutdown(action-block)。network は bugs.md [OPEN] の独立 latch が絡む。

**横断知見をプロジェクトメモリへ集約**: 旧ユーザー単位メモリ（起動法/RE方法論/パッチ削減/清書/移植）を `facts/workflow.md` へ移管。

---

## フェーズ: ★★ATTRACT 安定到達（クリーン起動・実機確認）+ GUI コントロールパネル完備 — 2026-06-28

**運用知見**: nrs.exe を**手動起動しない**（必ず統合 GUI「▶起動」= in-process 注入経由）。
手動起動は二重起動 / keychip ポート(40100..40113)競合でゲームが数秒で終了する。クリーン起動なら attract 安定。
**統合 GUI**: `src/host/loader.c`（native Win32・Python 不要。`loader` ターゲットを cmake build → `build/Debug/loader.exe`。
旧 control_panel.exe + 旧 loader.exe(CLI) + 旧 run.ps1 の inject/tail を一本化）= 起動(in-process 注入)/終了/再起動・FreePlay/TEST/Windowed・
入力設定/テスト（GUI 直接ポーリングでゲーム不要）・ログ（ts/色分け/フィルタ/検索/I-O抑制/JSONL書出）。設定は nrsedge.cfg → host。

**= 過去 Frida 実装の boot-critical 全サブシステムを native 化し、実機で attract まで到達。end-to-end 検証成功。**
次の目標: attract → ゲーム開始（入力検証 + コイン + **タッチパネル**）。

**ライブ検証 OK**: 統合 GUI の ▶起動（= in-process 注入。`loader.exe` は引数を無視するので注入は必ずボタン経由。
自律実行は `facts/workflow.md` 参照）で `nrsedge.log` に
`host.attach→patches.applied→logic.bind→logic.ok→gamehooks.ok→keychip.server.up→windowed.hooks→host.ready`
が全て出力、nrs.exe 実行継続（ユーザー確認「動作しています」）。patches.applied の count はパッチ撤去で変動（現在 25。2026-06-29 時点）。
発見・修正したバグ: **reload ロック保持中の hooked API self-deadlock**（`facts/bugs.md` 参照。`do_load` で修正）。
デバッグ手法: breadcrumb で `hooks.ok`→停止を特定 → cdb のモジュールロードで logic_live ロード済確認 → コード解析で deadlock 断定。

**移植台帳: `facts/port_status.md`（旧 boot 全モジュール → native の欠落ゼロ追跡）。**
追加移植: keychip PCP サーバ(`host/keychip_server.c`) / mxdrivers(`logic/driver/mxdevices.c`: columba DMI=RINGEDGE2 +
mxsram/mxsuperio/mxsmbus eeprom) / amplatform(AAL) / freeplay / keychip present hold / windowed。**全ビルド通過。**
残り(非 boot-gating): rtc / getstatus 動的 / mxgfetcher recv / client.js pcpaOpenClient(server 稼働で不要かも) / region 条件 hook。

旧 Frida 実装は破棄済み。native C（host + reloadable logic）へ完全移行。**全ターゲットがビルド通過**。

### 完了
- **P0 RE 帯**: `facts/`(旧 FACTS 保全) / `data/known_names.json`(serial/transport 追記) / `ref.md` /
  COM map・kdserial・JVS=COM4・columba=DMI 反映。drift 訂正済み。
- **破壊的移行**: 旧 Frida 製品・旧ツール・docs・captures 削除。RE エンジン/知見は保全。
- **骨格 + ビルド検証**:
  - `cmake -B build -G "Visual Studio 17 2022" -A Win32` 構成 OK（MSVC x86 検出）。
  - **`logic.dll` / `host.dll` / `loader.exe` 全てビルド成功**。
  - **MinHook を `third_party/minhook` に vendor**（host が link）。
- **JVS フレームエンジン** `src/logic/driver/mxjvs.c`（micetools `jvs_base.c`+`jvs_837_14572.c` を lift）:
  RESET/ASSIGN_ADDR/READ_ID/GET_*_VERSION/GET_FEATURES/READ_SW/READ_COIN/READ_ANALOG/GPIO/COIN_DECREASE、
  マスク/エスケープ/チェックサム/複数コマンド対応。READ_ID/GET_FEATURES/READ_SW(入力反映)/
  複数コマンドを実装。
- **COM4 シリアル傍受**を `src/logic/api.c` に配線（CreateFileA/W→sentinel、Write→frame→Read で応答）。
  host hook は CreateFileA も対応（nrs は A 版で COM4 を開く）。
- **P3 入力層**: `mxjvs_set_input`（論理入力→JVS 13bit sw / analog ch1=X ch0=Y / TEST / coin エッジ。
  bit 配置 facts/devices.md 準拠）+ `input.c`（GetAsyncKeyState ポーラ、既定バインド）。api.c が
  Write 毎に poll→set_input。sw/analog/coin マッピング実装済み。
- **旧 impl 静的パッチ全移植** `src/logic/patches.c`: ambilling/amdongle/amjvs(forgery)/devices(board index
  0xa/0xb・touch/card presence)/mxnetwork/mxsegaboot/mxstorage/region/mxgfetcher の**全静的バイトパッチ +
  node/region データ書込み**を `patches_apply()` が bind 時に nrs.exe へ適用。**全ビルド通過**。
  ＝旧 impl の「attract 到達」静的基盤を native で再現。詳細・残り動的分は `facts/port_status.md`。
- **game-function hook 機構** `src/host/gamehook.c`（reload-safe: detour=安定 host／logic=g_api 経由）。
  第一利用として **amjvs/input.js を移植**: `on_jvs_tick`(jvs_update_main PRE→node BSS 直書き) +
  `on_sys_override`(dipsw read 後/sysinput 前→DAT_0160194c TEST/SERVICE 上書き)。全ビルド通過。
- **amplatform/identity**(patches.c: "AAL"/"WindowsXP") + **freeplay**(on_jvs_tick 内 per-frame) +
  **keychip present hold**(on_keychip_hold game-fn hook 0x6F0A80) 移植。
- **keychip PCP サーバ** `src/host/keychip_server.c`（旧 pcpa_server.py 移植・winsock 7 ポート・
  認証バイパス code=54・mxmaster/amNet/billing 応答。host 常駐 reload-safe）。**全ビルド通過**。

### 次の一手（P2 ライブ統合 — 実機が要るためここから手動/対話）
1. **`loader.exe start --wait` で実起動検証**: `host.dll` 注入 → JSONL ログで `jvs.open(COM4)` と
   `amJvspInit` が **state 偽装無しで正規 init** するか確認（旧クラッシュ誤診の最終クローズ）。
2. **overlapped シリアル対応** ← 最重要未解決。nrs の JVS poll スレッド(`jvs_poll_thread` 0x9896C0)は
   **overlapped ReadFile/WriteFile + event 待ち**。現状 api.c は同期完了で返すため event が signal されず
   **poll が止まる恐れ**。OVERLAPPED 経路（event signal / 即時完了の作法）を実機で詰める。
3. **フレーム組立**: 現状「1 write=1 frame」を仮定。nrs が分割 write する場合は host 側でバッファリング。

### ロードマップ
P2(JVS ライブ) → P3 入力(KB/XInput→`mxjvs` の sw/analog) → P4 driver(columba/dipsw/touch/card) →
P5 system(keychip in-proc/network) → P6 crackproof + 実起動(touch) → P7(任意) 配布。

### 未確定（facts/ 参照）
overlapped シリアルの作法 / COM2 device protocol / kdserial 設定元(`DAT_01696ad4`) /
R-GRIP rate 入力源 / touch screen protocol / CrackProof 干渉範囲 / micetools が BB を実起動できるか。

### ビルド/反復メモ
- 反復（人間）: VSCode タスク「👤 ビルドして GUI を開く」（build→GUI 起動）。反復（自律）: `loader.exe start --wait`/`status`/`stop`。logic 変更は host が auto-swap（再起動不要）。
- MinHook は vendor 済（`third_party/minhook`、`.git` 除去）。`build/` 等は `.gitignore` 済。
