# amdebug FACTS（co-located）

nrs.exe 内蔵の amiDebug ロギング機構の事実。横断定数は `../ARCH.md`、索引は repo ルート `FACTS.md`。
confidence: [F]=Frida確認 [S]=静的解析 [I]=推論

由来: 文字列 `"amiDebug Ver.1.00 Build:Oct 21 2011"` (static 0xAE16D0) と config キー
`DebugLogLevel`/`DebugLogMask`/`DebugLogFile`/`SetDebugFlag`/`ClrDebugFlag` (0xBCEA10..)。

---

## ログ系統 [S]（A/B=amiDebug, C=生stdio, D=SEH crash。全て src/host/dbglog.c が窓へ転送）

retail ビルドでも系統A は**既定で部分的に生成される**（後述: amDebugInit が logLevel=4/mask=0xff を設定）が、
出力先が stderr（窓では不可視）かつログファイル未 open のため**実質見えない**。系統B は整形後に破棄。
`boot/amdebug/diag.js`（Frida）/ `src/host/dbglog.c`（native）が両系統を可視化する。

### A. レベル付きログ（カテゴリ/重大度ゲート付き）

```
呼出元多数 → amDebugOutLv(0x55C9C0) → amDebugLog_format(0x55C930) → amDebugLog_sink(0x55C800)
```

- 入口 `amDebugOutLv` (0x55C9C0): `EAX`=level/category。下のゲートを判定し、通れば format へ。
- `amDebugLog_format` (0x55C930): `_vsnprintf` で整形し再ゲート → シンク呼出。
- **シンク** `amDebugLog_sink` (0x55C800, `__fastcall`): `ECX`=level, `EDX`=整形済みメッセージ。
  `level&8` 立ちで `@%d[%Y-%m-%d %H:%M:%S.0] ` を前置し、**stderr**（`__iob_func()+0x40`）と
  ログファイル `amDebug_logFile` の両方へ `fprintf`/`fputs`。

**ゲート式**: `(-1 < logLevel) && ((level & ~8) <= logLevel) && (logMask & (1 << ((level & ~8) & 0x1f)))`
- `level & 8` = タイムスタンプ前置フラグ（判定値からは除外）
- 重大度 = `level & 7`
- **既定値の実体 [S]**: `amDebugInit`(0x55C500) が起動時に `memset(&0x1696F30,0,0x2fc)`（logLevel/mask/file
  全域）後 `logLevel=4` / `logMask=0xff` を設定。よって既定で重大度 **0..4・カテゴリ 0..7 は通過**
  （-1=全抑止は誤り。BSS 初期値=0 で、-1 にはならない）。`logLevel=0x7fffffff`＋`logMask=0xffffffff` で全通過。
- **clobber 注意 [S]**: native は CREATE_SUSPENDED 注入のため patches_apply（entry 前）の静的開放は
  resume 後の amDebugInit に上書きされ lv5..7 が脱落する。`src/host/dbglog.c` が amDebugInit(0x55C500)
  を hook し**本体実行後**に再開放（Frida diag.js は実行中 attach=init 後ゆえ問題化しなかった）。

### B. 無条件ログ（printf 風・level 無し。retail で破棄）[S]

```
呼出元 30+ → amDebugOut(0x55C7E0) → amDebugOut_format(0x55C790)
```

`amDebugOut_format` (0x55C790) の逆アセンブル（実体）:
```
SUB ESP,0x404            ; buf = [esp] (0x400) + cookie[+0x400]
MOV EAX,[ESP+0x408]      ; format（第1引数）
PUSH ECX/EAX/0x400/buf   ; 4 push = 0x10
CALL _vsnprintf (0xA827AF)
0x55C7BC: MOV ECX,[ESP+0x410] ; ★戻り直後。esp=entry-0x414, buf=entry-0x404=esp+0x10
ADD ESP,0x10
XOR EAX,EAX ; RET          ; ← 整形結果を書き出さず破棄
```
書き出し命令が無く、`STARTUP=` / `GAME TITLE = <ゲーム名>` 等の起動ヘッダ（`amDebugLog_control`
0x55CFD0 が出力）を含む全メッセージが捨てられる。**復元法**: `0x55C7BC` に Interceptor.attach し
`esp+0x10` の整形済みバッファを読む（関数境界外 attach だが Frida は任意番地可、固定バイナリで安定）。

---

## Frida Hook（`boot/amdebug/diag.js`） [F]

| 種別 | static_VA | 内容 |
|---|---|---|
| data write | 0x1696F38 | amDebug_logLevel = 0x7fffffff（フィルタ開放。A 系統を全通過） |
| data write | 0x1696F3C | amDebug_logMask = 0xffffffff（全カテゴリ bit ON） |
| attach | 0x55C800 | amDebugLog_sink onEnter: ECX=level&7, EDX=msg を `AMDBG [lv*]` で送出 |
| attach | 0x55C7BC | amDebugOut_format 内 _vsnprintf 直後: [esp+0x10] を `AMDBG [raw]` で送出 |

**[F] 捕捉実例**:
- `[lv0] Failed to check application data area.` / `[lv3] amHmInit() failed.` /
  `[lv3] amlib: Region error. (01, 01, 00, 05)`（= 0903 region の元メッセージ）
- `[lv7] [Resolver] init OK` / `[lv7] DNS: resolving (0,1,0)` /
  `[lv7] ### alDnsGetIpAddr() Error!!!![tenporouter.loc]:-92` /
  `[lv7] DNS: getting IP address success naominet.jp(202.144.249.117)`（ALL.Net DNS 連鎖が丸見え）
- `[raw] amBackupRecordReadDup: error(-21)` / `[raw] amBackupRecordWriteDup: error(-3)`
  （retail で破棄される無条件ログ。esp+0x10 復元が動作）

esp+0x10 の境界外 attach は安定動作。注: 起動ヘッダ（STARTUP=/GAME TITLE=）はフック確立より前に発火する
ため捕捉対象外（amBackup 等それ以降の無条件ログは確実に捕捉）。

### C. amiDebug 非経由の生 stdio 開発ログ [S]

amiDebug を通さず**直接 `fprintf(stderr,...)` / `printf`** する開発ログが各所に残存。全て CRT の
単一出口 `__write`(0xA823A3, `int __cdecl(fd,buf,cnt)`, fd1=stdout/2=stderr) を通る。GUI app ＝
コンソール無しのため stderr/stdout は不可視。`src/host/dbglog.c` が `__write` を hook し fd1/2 を窓へ。

確認した発生源（一例）[S]:
- `FUN_0048DDD0`(render): `"ERROR: Render Target is already pushed.\n"` / `"...is not pushed.\n"` → stderr
- `FUN_006C3C60`(app entry): `"amSehLoggerSetExceptionFilter() failed.\n"` → stderr
- `FUN_006C3F70`: __iob_func を 80+ 回呼ぶデバッグダンプ。amDebugConfigApply の AppArgs/SetDebugFlag 経由で駆動

注: `amDebug_flag_lo/hi`(SetDebugFlag, 0x1696F28/2C) の読み手（FUN_0089C780 `&0x4000`、FUN_0076DBD0
`&0x800` 等）は**ログでなく開発機能の挙動ゲート**（描画/入力状態の強制）。ログ目的では触らない。
系統A sink は dbglog.c が原関数を呼ばないので stderr 二重化せず、系統C には amiDebug は重複しない。

---

## 他のログ機構の調査結果（窓へは未接続。要否を判断するための棚卸し）[S]

| 機構 | 経路 | 内容 | 窓接続の要否 |
|---|---|---|---|
| **Windows イベントログ** | amDebugLog_sink→`amDebug_eventLogBridge`(0x45AD50, gate `DAT_016014A6`)→`amEventLogReport`(0x985B00, RegisterEventSourceA/ReportEventA) | amDebug と**同一メッセージ**を Event Viewer へ重送 | **不要**（系統A と内容重複。唯一の呼び元が sink 経路）|
| **SEH クラッシュ・バックトレース（系統D）** | 例外時 `amSehLog_walkStack`(0x4566F0, StackWalk64)→`amSehLog_emitFrame`(0x456900, SymFromAddr/SymGetLineFromAddr64)→組立バッファ ctx(&DAT_01600B90)+0xAC（長さ +0xA4）→`Y:/err.log` | フレーム毎 `%02d %08x ... <0x%08x>+off (file:line)` のスタックトレース | **✅ 接続済**。dbglog.c が emitFrame(0x456900) を POST hook し ctx+0xAC の完成行を `{"ev":"crash"}` で窓へ。`Y:/err.log`(errlog_path_init 0x89D610) は Y: 不在で書込失敗するが**メモリ読取ゆえ非依存**。crash 専用＝通常時は無音 |
| **err.log / Y:/err.log** | fopen+fprintf（fd≥3） | エラー/クラッシュ詳細ファイル | 上の SEH と同一ファイル。fd≥3 ゆえ系統C(fd1/2)では拾わない |
| **last_pras.log / last_shime.log** | fopen+fprintf | pras(課金)/shime サブシステムの最終状態スナップショット | 別内容・ファイル。要なら fopen フック＋fd 追跡 or パス再配置で捕捉可 |

結論: amDebug を経由する系統（A/B/C + Event ログ）は捕捉済み or 重複。**新規・別内容の SEH クラッシュ
バックトレースを系統D として接続済**（emitFrame 0x456900 POST hook で組立バッファを読取＝Y: 不在でも動作）。
残りの file ログ（last_pras/last_shime）は別内容だが crash 程の価値は薄く未接続（要望あれば fopen フックで対応可）。

persistence=monitor（attach は detach で消える）。data write は detach 後も残るが無害。
切替: モジュール先頭 `ENABLE_ALL`（false で A 系統のフィルタ開放を抑止、B 系統は常時有効）。

---

## 関数 [S]

| static_VA | Name | Notes |
|---|---|---|
| 0x55C7E0 | amDebugOut | 無条件 printf 風ログ入口（format+varargs）。出力は破棄 |
| 0x55C790 | amDebugOut_format | `_vsnprintf`→スクラッチ整形のみ（書き出し命令無し）。0x55C7BC=整形直後 |
| 0x55C9C0 | amDebugOutLv | レベル付きログ入口。EAX=level/cat、ゲート判定→0x55C930 |
| 0x55C930 | amDebugLog_format | `_vsnprintf`＋再ゲート→シンク呼出 |
| 0x55C800 | amDebugLog_sink | シンク。`@lv[ts] msg` を stderr＋ログファイルへ。__fastcall(ECX=level,EDX=msg) |
| 0x55CA00 | amDebugLog_openFile | `nrs.log`/`nrs-%Y%m%d-%H%M%S.log` を open しヘッダ書込 |
| 0x55CFD0 | amDebugLog_control | AppCtrlFlag bit8 でログ/スクリーンキャプチャ開閉。起動ヘッダ出力 |
| 0x55C500 | amDebugInit | memset(&0x1696F30,0,0x2fc)→logLevel=4/mask=0xff 設定。startup 初期化。dbglog.c の gate 再開放 hook 先 |
| 0x55CEE0 | amDebugLog_autoOpen | sink 内 lazy open: logFileName!=0 && !logFileOpen 時 fopen(name,"w")→logFile |
| 0x6C5500 | amDebugConfigApply | config から DebugLogLevel/Mask/File・Set/ClrDebugFlag・AppCtrlFlag 等を適用 |

## グローバル [S]

| static_VA | Type | Name | Notes |
|---|---|---|---|
| 0x1696F38 | S32 | amDebug_logLevel | DebugLogLevel。amDebugInit 既定=4。`(lv&~8)<=この値`で通過（-1 にはならない）|
| 0x1696F3C | U32 | amDebug_logMask | DebugLogMask。`1<<((lv&~8)&0x1f)` bit で通過 |
| 0x1696F28 | U32 | amDebug_flag_lo | SetDebugFlag/ClrDebugFlag 下位32bit |
| 0x1696F2C | U32 | amDebug_flag_hi | 同上位32bit |
| 0x1696FC4 | FILE* | amDebug_logFile | ログファイルハンドル（未 open=0） |
| 0x1696F40 | U8 | amDebug_logFileOpen | ログファイル open 済みフラグ |
| 0x1696F41 | char[128] | amDebug_logFileName | 出力先ログファイル名バッファ |

注: `0xA76C4B` = `__iob_func` 相当。`+0x40` = stderr（シンクの stdio 出力先）。
