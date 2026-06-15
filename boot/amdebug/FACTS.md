# amdebug — FACTS（co-located）

nrs.exe 内蔵の amiDebug ロギング機構の事実。横断定数は `../ARCH.md`、索引は repo ルート `FACTS.md`。
confidence: [F]=Frida確認 [S]=静的解析 [I]=推論

由来: 文字列 `"amiDebug Ver.1.00 Build:Oct 21 2011"` (static 0xAE16D0) と config キー
`DebugLogLevel`/`DebugLogMask`/`DebugLogFile`/`SetDebugFlag`/`ClrDebugFlag` (0xBCEA10..)。

---

## ログ2系統 [S]

retail ビルドでは**どちらも既定で出力されない**。`boot/amdebug/logcapture.js` が両系統を Frida で可視化する。

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
- 既定 `logLevel = -1` で全抑止。`logLevel=0x7fffffff` かつ `logMask=0xffffffff` で全通過。

### B. 無条件ログ（printf 風・level 無し） — retail で破棄 [S]

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

## Frida Hook（`boot/amdebug/logcapture.js`） [F] 実機確認 2026-06-13（frida-20260613-211406.txt）

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
| 0x6C5500 | amDebugConfigApply | config から DebugLogLevel/Mask/File・Set/ClrDebugFlag・AppCtrlFlag 等を適用 |

## グローバル [S]

| static_VA | Type | Name | Notes |
|---|---|---|---|
| 0x1696F38 | S32 | amDebug_logLevel | DebugLogLevel。-1=全抑止、`(lv&~8)<=この値`で通過 |
| 0x1696F3C | U32 | amDebug_logMask | DebugLogMask。`1<<((lv&~8)&0x1f)` bit で通過 |
| 0x1696F28 | U32 | amDebug_flag_lo | SetDebugFlag/ClrDebugFlag 下位32bit |
| 0x1696F2C | U32 | amDebug_flag_hi | 同上位32bit |
| 0x1696FC4 | FILE* | amDebug_logFile | ログファイルハンドル（未 open=0） |
| 0x1696F40 | U8 | amDebug_logFileOpen | ログファイル open 済みフラグ |
| 0x1696F41 | char[128] | amDebug_logFileName | 出力先ログファイル名バッファ |

注: `0xA76C4B` = `__iob_func` 相当。`+0x40` = stderr（シンクの stdio 出力先）。
