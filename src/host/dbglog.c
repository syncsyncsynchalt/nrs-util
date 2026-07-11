/* dbglog.c — nrs.exe 内蔵の開発デバッグログ4系統を捕捉して host ログ(JSONL)へ転送。詳細は facts/amdebug.md。
 *
 * 系統A（amiDebug レベル付き, ゲート有）: amDebugOutLv→amDebugLog_format→amDebugLog_sink(0x55C800)。
 *   amDebugInit が既定 logLevel=4/mask=0xff（lv5..7 脱落）→ d_dbg_init が init 後に全開。
 *   シンク入口を hook し整形済みメッセージ(EDX)を転送。__fastcall(ECX=level, EDX=msg)。原 sink は呼ばない
 *   （stderr 出力を抑止＝系統C の __write hook と二重化しない）。
 * 系統B（amiDebug 無条件 printf 風）: amDebugOut(0x55C7E0)→amDebugOut_format で _vsnprintf 後に破棄。
 *   保存先が無いので自前で vsnprintf し直して転送。__cdecl(fmt, ...)。
 * 系統C（amiDebug 非経由の生 stdio）: CRT _write(__write 0xA823A3) を hook し fd1/2 を転送。
 *   GL/render 等が直接 fprintf(stderr,...) する開発エラーや FUN_006C3F70 ダンプを捕捉。
 * 系統D（SEH クラッシュ・バックトレース）: amSehLog_emitFrame(0x456900) を POST hook し、
 *   StackWalk64 が組み立てたフレーム行（ctx+0xAC）を窓へ。本来先 Y:/err.log 不在でも復元。
 *
 * host 側に置く理由: ログは host の所有。logic に依存しないので reload-safe（logic.dll swap で無効化しない）。
 * MH_Initialize は hooks_install で実施済み。 */
#include "host.h"
#include "MinHook.h"
#include <stdio.h>
#include <stdarg.h>

#define IMAGE_BASE 0x400000u

/* 系統A: シンク __fastcall(ECX=level, EDX=msg)。戻り EAX(1/0)。 */
static int (__fastcall *o_dbg_sink)(unsigned level, const char *msg);
/* 系統B: amDebugOut __cdecl(fmt, ...)。整形結果を破棄するため orig は呼ばない（観測のみ）。 */

/* 系統A ゲート開放: amDebugInit(0x55C500) は memset(&logregion,0,0x2fc) 後に logLevel=4/mask=0xff を設定。
 * 注入は CREATE_SUSPENDED ＝ patches_apply は entry 前に走るため、静的開放(0x1696F38/3C)は resume 後の
 * amDebugInit に上書きされる（既定 4/0xff = 重大度0..4 のみ通過、lv5..7 脱落）。→ init 完了直後に再度全開。
 * data セクションの可変グローバルゆえ VirtualProtect 不要。 */
static void (*o_dbg_init)(void);
static void __cdecl d_dbg_init(void) {
    o_dbg_init();   /* 本体: memset → logLevel=4 / logMask=0xff を先に確定させる */
    uintptr_t base = (uintptr_t)GetModuleHandleW(NULL);
    *(volatile int *)     (base + (0x1696F38 - IMAGE_BASE)) = 0x7FFFFFFF;  /* amDebug_logLevel 全レベル */
    *(volatile unsigned *)(base + (0x1696F3C - IMAGE_BASE)) = 0xFFFFFFFF;  /* amDebug_logMask 全カテゴリ */
}

/* JSON 文字列エスケープ（ゲームメッセージは任意バイト＝logview の json.loads を壊さない）。 */
static void json_escape(const char *s, char *out, size_t cap) {
    size_t o = 0;
    for (; s && *s && o + 7 < cap; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '"':  out[o++] = '\\'; out[o++] = '"';  break;
            case '\\': out[o++] = '\\'; out[o++] = '\\'; break;
            case '\n': out[o++] = '\\'; out[o++] = 'n';  break;
            case '\r': out[o++] = '\\'; out[o++] = 'r';  break;
            case '\t': out[o++] = '\\'; out[o++] = 't';  break;
            default:
                if (c < 0x20) o += (size_t)_snprintf(out + o, cap - o, "\\u%04x", c);
                else          out[o++] = (char)c;
        }
    }
    out[o] = 0;
}

/* lv&7 を表示カテゴリ(lvl)へ: 小さいほど重大（facts: lv0/lv3=失敗, lv7=verbose）。 */
static const char *lvl_of(unsigned sev, const char *msg) {
    if (sev <= 1) return "error";
    if (sev <= 3) return "warn";
    return "info";   /* msg 中の error/fail 等は logview 側の正規表現が拾う */
}

static void emit_game(unsigned level, int raw, const char *msg) {
    if (!msg) return;
    char buf[1100], esc[2200], line[2400];
    /* 末尾改行を除去（ゲームの format は末尾 \n を含むことが多い）。 */
    size_t n = 0;
    while (msg[n] && n < sizeof buf - 1) n++;
    while (n && (msg[n - 1] == '\n' || msg[n - 1] == '\r')) n--;
    memcpy(buf, msg, n); buf[n] = 0;
    if (!buf[0]) return;

    json_escape(buf, esc, sizeof esc);
    unsigned sev = level & 7;
    _snprintf(line, sizeof line,
              "{\"ev\":\"game\",\"sys\":\"%s\",\"lv\":%u,\"msg\":\"%s\"}",
              raw ? "raw" : "lvl", sev, esc);
    line[sizeof line - 1] = 0;
    host_log(raw ? "info" : lvl_of(sev, buf), line);
}

static int __fastcall d_dbg_sink(unsigned level, const char *msg) {
    emit_game(level, 0, msg);
    /* 原 sink は呼ばない: 原関数は msg を stderr(__iob+0x40) へ fputs するため、下の __write(fd2)
       hook と二重取得になる。整形済み msg は emit_game で転送済みなので原出力は不要。
       （amiDebug 自前ログファイルは standalone で未使用ゆえ損失なし）。 */
    (void)o_dbg_sink;
    return 1;
}

/* 開発用 stdio ログ捕捉: CRT _write(__write 0xA823A3, __cdecl(fd,buf,cnt)) を hook し
 * fd 1(stdout)/2(stderr) を窓へ転送。amiDebug を経由しない直接 fprintf(stderr,...) —
 * GL/render の "ERROR: Render Target is not pushed."、"amSehLoggerSetExceptionFilter() failed." や
 * デバッグダンプ FUN_006C3F70 等 — はここを通る。これが「残っている開発用デバッグ出力の仕組み」。
 * 再帰なし: host_log は host.dll 側の別 CRT ＝ nrs.exe の __write を経由しない。 */
static int (__cdecl *o_write)(int fd, const void *buf, unsigned cnt);
static int __cdecl d_write(int fd, const void *buf, unsigned cnt) {
    if ((fd == 1 || fd == 2) && buf && cnt) {
        char raw[1100], esc[2200], line[2500];
        unsigned n = cnt < sizeof raw - 1 ? cnt : (unsigned)(sizeof raw - 1);
        memcpy(raw, buf, n);
        while (n && (raw[n - 1] == '\n' || raw[n - 1] == '\r')) n--;
        raw[n] = 0;
        if (raw[0]) {
            json_escape(raw, esc, sizeof esc);
            _snprintf(line, sizeof line, "{\"ev\":\"stdio\",\"fd\":%d,\"msg\":\"%s\"}", fd, esc);
            line[sizeof line - 1] = 0;
            host_log("info", line);   /* msg 中の ERROR/fail は logview 側で error 着色される */
        }
    }
    return o_write(fd, buf, cnt);
}

static void __cdecl d_dbg_out(const char *fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    _vsnprintf(buf, sizeof buf, fmt ? fmt : "", ap);   /* amDebugOut_format と同じ 0x400 整形 */
    va_end(ap);
    buf[sizeof buf - 1] = 0;
    emit_game(0, 1, buf);
    /* orig amDebugOut は結果を破棄するだけ（副作用なし）＝呼び戻さない。 */
}

/* 系統D（SEH クラッシュ・バックトレース）: 例外時 amSehLog_walkStack(0x4566F0) が各フレームを
 * StackWalk64 で辿り、amSehLog_emitFrame(0x456900, __cdecl(frame*)) が ctx(&DAT_01600B90)+0xAC に
 * シンボル付き行を組み立てる（長さ ctx+0xA4）。本来は Y:/err.log へ書くが standalone は Y: 不在で
 * 書込失敗＝消える。emitFrame を POST で hook し**メモリ上の完成行**を窓へ転送（ファイル非依存）。
 * 唯一の呼び元は walkStack ＝ crash 経路のみ（通常時は発火しない）。1 呼出 = 1 フレーム行。 */
#define SEH_CTX_VA   0x1600B90u   /* amSehLog ctx = &DAT_01600B90（FUN_004572E0 が常に返す固定番地）*/
#define SEH_LEN_OFF  0xA4         /* ctx+0xA4 = 現フレーム行の長さ */
#define SEH_TXT_OFF  0xAC         /* ctx+0xAC = 現フレーム行のテキスト */
static void (__cdecl *o_seh_frame)(void *frame);
static void __cdecl d_seh_frame(void *frame) {
    o_seh_frame(frame);   /* 原: シンボル解決して ctx+0xAC の行を完成させる */
    uintptr_t ctx = (uintptr_t)GetModuleHandleW(NULL) + (SEH_CTX_VA - IMAGE_BASE);
    int len = *(volatile int *)(ctx + SEH_LEN_OFF);
    if (len > 0 && len < 0x400) {
        char raw[0x404], esc[0x810], line[0x880];
        memcpy(raw, (const char *)(ctx + SEH_TXT_OFF), (unsigned)len);
        raw[len] = 0;
        while (len && (raw[len - 1] == ' ' || raw[len - 1] == '\n' || raw[len - 1] == '\r'))
            raw[--len] = 0;
        if (raw[0]) {
            json_escape(raw, esc, sizeof esc);
            _snprintf(line, sizeof line, "{\"ev\":\"crash\",\"msg\":\"%s\"}", esc);
            line[sizeof line - 1] = 0;
            host_log("error", line);   /* crash＝error 着色で目立たせる */
        }
    }
}

static int hk(unsigned va, void *det, void **orig) {
    void *a = (void *)((uintptr_t)GetModuleHandleW(NULL) + (va - IMAGE_BASE));
    return (MH_CreateHook(a, det, orig) == MH_OK && MH_EnableHook(a) == MH_OK) ? 0 : -1;
}

void dbglog_install(void) {
    int e = 0;
    e |= hk(0x55C500, (void *)d_dbg_init, (void **)&o_dbg_init);   /* 系統A gate を init 後に開放（clobber 対策）*/
    e |= hk(0x55C800, (void *)d_dbg_sink, (void **)&o_dbg_sink);   /* 系統A シンク */
    e |= hk(0x55C7E0, (void *)d_dbg_out,  0);                     /* 系統B 無条件ログ入口 */
    e |= hk(0xA823A3, (void *)d_write,    (void **)&o_write);     /* 系統C CRT _write: 開発 stdio(fd1/2)を窓へ */
    e |= hk(0x456900, (void *)d_seh_frame, (void **)&o_seh_frame);/* 系統D SEH crash backtrace（フレーム毎）*/
    host_log(e ? "warn" : "info",
             e ? "{\"ev\":\"dbglog.partial\"}" : "{\"ev\":\"dbglog.hooks\"}");
}
