# boot/ nrs.exe スタンドアロン起動シム（成果物）

`nrs.exe`(NRS, RingEdge) を物理ハードなしで起動させる実体。RingEdge の各サブシステムを
emulate / patch する frida モジュール群 + keychip(PCP) サーバ。**解析ツールは `tools/`、これは成果物**。

## 構成（RingEdge 実機準拠）

dir = RingEdge 実行ファイル(`mx*.exe`)/ ライブラリ(`am*`)。単純固定バイト patch も
**所属サブシステムの dir** に `patch()` で置く（中央ファイルは持たない。一覧監査 `tools/static/patch_audit.py`）。

| dir | RingEdge コンポーネント | 役割 |
|---|---|---|
| `lib/` | — | 共有ヘルパ + `patch()/hook()/watch()`。**先頭ロード必須** |
| `amdongle/` | amDongle 1.12 | ドングル busy 固定 + SM 監視 |
| `mxnetwork/` | mxnetwork.exe / amNet | DHCP/NIC SM、LAN type(state4)、ALL.Net 接続(state6) |
| `amjvs/` | amJvs/amJvsp | JVS 初期化/状態（`state.js`） |
| `amplatform/` | amPlatform | board/OS identity、HW 検出(Error 0901) |
| `mxgfetcher/` | mxgfetcher.exe / amGfetcher | get_status recv 完了、boot SM 前進 |
| `ambilling/` | ALL.Net Plus Billing (alpbEx) | billing offline idle（実装 `ambilling/status.js` 0xA065C0） |
| `amrtc/` | amRtc | ローカル時刻 |
| `mxkeychip/` | mxkeychip.exe / keychip / PCP | client 回復、setup、region、`server/`=PCPA サーバ（mxmaster port 40100 含む） |
| `mxdrivers/` | mx ドライバ / amBackup 層 | mxsram/mxsuperio/mxhwreset/jvs pipe デバイス偽装 ＋ amBackup 層スタック |
| `mxsegaboot/` | mxsegaboot.exe / SYSTEM STARTUP | extend image(state5)/p-ras(state7)（実装 `mxsegaboot/startup.js`） |
| `mxstorage/` | mxstorage.exe | storage presence（実装 `mxstorage/presence.js` 0x4FDA50） |
| `devices/` | 周辺デバイス presence 連鎖 | IC Card R/W・Touch Panel・USB I/O（実装 `devices/presence.js`） |
| `app/` | ゲーム窓/プロセス | windowed、exit、self-shutdown 無力化 |

## 構成の単一ソース = `MANIFEST.json`

`launch.py` は `MANIFEST.json` の `load_order` 順にモジュールを連結ロードする（ファイル名順ではない）。
各エントリが `module / subsys / persistence / network_role` を宣言する（番地 `// va:` は各モジュールヘッダが持つ）。

- **persistence**: `persistent`(patchCode/data-write、detach 後も有効) / `runtime`(Interceptor・timer、
  detach で revert) / `monitor`(log のみ) / `served`(keychip サーバが応答) / `na`。
  **runtime の集合 = 完全スタンドアロン化の残課題**。
- **network_role**: `local`(in-game patch のまま) / `serve`(将来ネットワーク化時に実サーバ応答へ移す層)。

規約（命名・ヘッダ）は [`CONVENTIONS.md`](CONVENTIONS.md)。

## 起動

```powershell
$py="$env:LOCALAPPDATA\Programs\Python\Python313\python.exe"
& $py boot\launch.py --spawn                       # 既定: GUI ログ窓（プレイ中は開いたまま）
& $py boot\launch.py --spawn --no-gui --duration 90  # console（ヘッドレス/定時キャプチャ）
```
`launch.py` が `boot\mxkeychip\server\pcpa_server.py` を自動起動し、**nrs.exe を `frida.spawn` で
サスペンド起動 → MANIFEST 順に全モジュールをロード → `frida.resume`** → capture。
監視は窓を閉じる（または `--duration`/Ctrl+C）まで継続し、**終了時に nrs.exe と pcpa_server を
自動終了**する（残して観察を続けるなら `--keep`）。

**ログ表示（既定 GUI）**: frida ブートログ＋pcpa サーバログを 1 つの窓に時刻付きで集約（`boot/log_gui.py`、
Tkinter・依存なし）。ソース別カラー／部分一致フィルタ／I-O ノイズ(NtCreateFile)非表示／エラーのみ／
検索／一時停止／表示分の JSONL 書出。全ログは `captures/frida-*.txt`（人間用）と
`captures/frida-*.jsonl`（AI 解析用・`{ts,src,lvl,msg}` 構造化）に保存。Tk 不在環境や `--no-gui` では console。

**サスペンド起動**: `frida.spawn` でサスペンド起動することで、nrs.exe 最初期の init
（amlib/amSram/amEeprom/amBackup のデバイス init）より前に全フックを効かせる。これにより
emulate デバイスが開けるようになり、amSramInit が mxsram emulation を正しく掴む（amBackup の
SRAM 系が `data/nvram/sram.bin` に永続）。後追い attach では最初期 init がフック設置前に走り切り、
emulate デバイスを開けず失敗する（amBackup が -3 を返す）。

## 整合チェック
```powershell
& $py tools\hygiene\check_doc_sync.py   # MANIFEST↔モジュール↔FACTS の整合（pre-commit でも自動実行）
```
