/* capture.c — nrs.exe の GL フレームをプロセス内部から確実にキャプチャ（唯一の正式手段）。
 * 外部の窓検索/CopyFromScreen は窓遮蔽・GL backbuffer 非取得・Get-Process 間欠失敗で不安定だった。
 * host は GL コンテキスト内にいるので SwapBuffers フック時に glReadPixels で実フレームを直接読める。
 *
 * トリガ: cwd(=nrs.exe dir, C:\src\bbs) に `capture.req` が出現したら次フレームを `capture.png` へ保存し
 *         req を削除（ワンショット）。原子的に書くため .tmp→rename。保存時は host ログに capture.saved を出す。
 * 形式: PNG（GDI+）。glReadPixels は GL_BGRA で読み GDI+ 32bppARGB と一致、縦は負 stride で反転。 */
#include "host.h"
#include "MinHook.h"
#include <stdlib.h>

/* ---- OpenGL (opengl32.lib, __stdcall) ---- */
__declspec(dllimport) void WINAPI glReadPixels(int x, int y, int w, int h, unsigned fmt, unsigned type, void *data);
__declspec(dllimport) void WINAPI glReadBuffer(unsigned mode);
__declspec(dllimport) const char * WINAPI glGetString(unsigned name);
#define GL_VENDOR   0x1F00u
#define GL_RENDERER 0x1F01u
#define GL_VERSION  0x1F02u
#define GL_BACK          0x0405u
#define GL_BGRA          0x80E1u
#define GL_UNSIGNED_BYTE 0x1401u

/* ---- GDI+ flat API (gdiplus.lib, __stdcall) ---- */
typedef struct { UINT32 GdiplusVersion; void *DebugEventCallback; BOOL SuppressBackgroundThread; BOOL SuppressExternalCodecs; } GdiplusStartupInput;
int WINAPI GdiplusStartup(ULONG_PTR *token, const GdiplusStartupInput *in, void *out);
int WINAPI GdipCreateBitmapFromScan0(int w, int h, int stride, int format, BYTE *scan0, void **bitmap);
int WINAPI GdipSaveImageToFile(void *image, const WCHAR *filename, const GUID *clsidEncoder, const void *encoderParams);
int WINAPI GdipDisposeImage(void *image);
#define PixelFormat32bppARGB 0x0026200A
#define PixelFormat32bppRGB  0x00220009   /* 4th byte = unused(X)。GL framebuffer の alpha=0 でも RGB を表示 */
static const GUID PNG_ENCODER = { 0x557cf406, 0x1a04, 0x11d3, { 0x9a, 0x73, 0x00, 0x00, 0xf8, 0x1e, 0xf3, 0x2e } };

static ULONG_PTR g_gdip_token;
static int       g_gdip_ok;

static void save_png(BYTE *bgra, int w, int h, const WCHAR *path) {
    if (!g_gdip_ok) {
        GdiplusStartupInput in = { 1, NULL, FALSE, FALSE };
        if (GdiplusStartup(&g_gdip_token, &in, NULL) != 0) return;
        g_gdip_ok = 1;
    }
    void *bmp = NULL;
    int stride = w * 4;
    /* glReadPixels は下→上に格納。負 stride + 最終行ポインタで top-down 画像にする。 */
    if (GdipCreateBitmapFromScan0(w, h, -stride, PixelFormat32bppARGB,
                                  bgra + (size_t)(h - 1) * stride, &bmp) != 0 || !bmp) return;
    GdipSaveImageToFile(bmp, path, &PNG_ENCODER, NULL);
    GdipDisposeImage(bmp);
}

/* back buffer を glReadPixels → PNG。hdc から window client サイズを得る。 */
static void do_capture(HDC hdc) {
    HWND hw = WindowFromDC(hdc);
    RECT rc;
    if (!hw || !GetClientRect(hw, &rc)) return;
    int w = rc.right, h = rc.bottom;
    if (w <= 0 || h <= 0 || w > 8192 || h > 8192) return;
    BYTE *buf = (BYTE *)malloc((size_t)w * h * 4);
    if (!buf) return;
    glReadBuffer(GL_BACK);
    glReadPixels(0, 0, w, h, GL_BGRA, GL_UNSIGNED_BYTE, buf);
    /* GL framebuffer の alpha は 0 のことが多く ARGB だと全透明=白表示になる。alpha を不透明化。 */
    { size_t px = (size_t)w * h; for (size_t i = 0; i < px; i++) buf[i * 4 + 3] = 0xFF; }
    save_png(buf, w, h, L"capture.png.tmp");
    free(buf);
    MoveFileExA("capture.png.tmp", "capture.png", MOVEFILE_REPLACE_EXISTING);  /* 原子的差し替え */
}

/* 要求ファイル検知。あれば 1 フレーム保存して req 削除。
 * 毎 swap だと present ホットパス（render_thread_main 0x801E80）に FS syscall を入れるので 30 swap 毎に間引く
 * （capture は ~0.5s 遅延でも十分。これで present 計装の交絡＝毎フレーム GetFileAttributes を除去）。 */
static void capture_check(HDC hdc) {
    static volatile LONG ctr;
    if ((InterlockedIncrement(&ctr) % 30) != 0) return;
    if (GetFileAttributesA("capture.req") == INVALID_FILE_ATTRIBUTES) return;
    DeleteFileA("capture.req");           /* 先に削除＝二重 swap でも 1 回 */
    do_capture(hdc);
    host_log("info", "{\"ev\":\"capture.saved\",\"file\":\"capture.png\"}");
}

/* ---- present 計装（チラつき/オブジェクト未描画 調査） ----
 * 「特定オブジェクトだけ点滅・消える」＝present ペーシング崩れ or レンダースレッド受け渡し race の疑い。
 * 毎 swap は QPC＋算術のみ（撹乱最小）、host_log は PD_WINDOW swap 毎に 1 行へ集約。
 * present 経路の実体（Ghidra）: render_thread_main(0x801E80) が描画→SwapBuffers→SetEvent→自己 Suspend、
 * frame_present_main(0x89CB80) が wglSwapIntervalEXT で vsync 設定＋render_done_event 待ち。 */
#define IMAGE_BASE 0x400000u
#define VA_SWAP_INTERVAL_CUR 0x016d8284u  /* int  最後に設定した swap interval */
#define VA_SWAP_INTERVAL_MIN 0x016d8288u  /* int  clamp 下限 */
#define VA_RENDER_THREADED   0x022548c8u  /* char !=0 で threaded present */
#define VA_WGL_SWAPINT_PTR   0x016f5388u  /* void* wglSwapIntervalEXT（0=未解決） */
#define PD_MAXTH 4
#define PD_WINDOW 300u                    /* ~5s @60fps 毎に集計を吐く */

static LARGE_INTEGER g_qpf;
static CRITICAL_SECTION g_pd_cs;
static int g_pd_init;
static unsigned g_pd_swaps;
static LONGLONG g_pd_last_spike;   /* スパイク即時ログのレート制限基準（QPC） */
static struct { DWORD tid; LONGLONG last; unsigned cnt; LONGLONG sum, mx, mn; unsigned nlong, nshort; } g_pd[PD_MAXTH];

static int game_i32(unsigned va) { return *(volatile int *)((uintptr_t)GetModuleHandleW(NULL) + (va - IMAGE_BASE)); }
static unsigned char game_u8(unsigned va) { return *(volatile unsigned char *)((uintptr_t)GetModuleHandleW(NULL) + (va - IMAGE_BASE)); }
static void *game_ptr(unsigned va) { return *(void *volatile *)((uintptr_t)GetModuleHandleW(NULL) + (va - IMAGE_BASE)); }

static void present_probe(void) {
    if (!g_pd_init) { InitializeCriticalSection(&g_pd_cs); QueryPerformanceFrequency(&g_qpf); g_pd_init = 1; }
    LARGE_INTEGER now; QueryPerformanceCounter(&now);
    DWORD tid = GetCurrentThreadId();

    /* emit 時のスナップショット */
    struct { DWORD tid; unsigned cnt; LONGLONG avg, mn, mx; unsigned nlong, nshort; } snap[PD_MAXTH];
    int nsnap = 0, emit = 0;
    int spike = 0; LONGLONG spike_us = 0;   /* 即時スパイク（ヒッチ）ログ用 */

    EnterCriticalSection(&g_pd_cs);
    int i, slot = -1, freeslot = -1;
    for (i = 0; i < PD_MAXTH; i++) {
        if (g_pd[i].tid == tid) { slot = i; break; }
        if (g_pd[i].tid == 0 && freeslot < 0) freeslot = i;
    }
    if (slot < 0 && freeslot >= 0) {
        slot = freeslot;
        g_pd[slot].tid = tid; g_pd[slot].last = now.QuadPart;
        g_pd[slot].cnt = 0; g_pd[slot].sum = 0; g_pd[slot].mx = 0; g_pd[slot].mn = 0x7fffffffffffffffLL;
        g_pd[slot].nlong = 0; g_pd[slot].nshort = 0;
    } else if (slot >= 0) {
        LONGLONG dt = now.QuadPart - g_pd[slot].last;
        g_pd[slot].last = now.QuadPart;
        if (dt > 0 && g_qpf.QuadPart > 0) {
            LONGLONG us = dt * 1000000LL / g_qpf.QuadPart;
            g_pd[slot].cnt++; g_pd[slot].sum += us;
            if (us > g_pd[slot].mx) g_pd[slot].mx = us;
            if (us < g_pd[slot].mn) g_pd[slot].mn = us;
            if (us > 25000) g_pd[slot].nlong++;   /* >25ms = stall/フレーム飛ばし */
            if (us < 8000)  g_pd[slot].nshort++;  /* <8ms  = 二重 present */
            /* ヒッチ瞬間を即時記録（>33ms=60Hz で1フレーム以上落ち）。最低 100ms 間隔でレート制限。 */
            if (us > 33000 && (now.QuadPart - g_pd_last_spike) * 1000LL / g_qpf.QuadPart > 100) {
                g_pd_last_spike = now.QuadPart; spike = 1; spike_us = us;
            }
        }
    }
    if (++g_pd_swaps >= PD_WINDOW) {
        g_pd_swaps = 0; emit = 1;
        for (i = 0; i < PD_MAXTH; i++) {
            if (g_pd[i].tid == 0 || g_pd[i].cnt == 0) continue;
            snap[nsnap].tid = g_pd[i].tid; snap[nsnap].cnt = g_pd[i].cnt;
            snap[nsnap].avg = g_pd[i].sum / g_pd[i].cnt; snap[nsnap].mn = g_pd[i].mn; snap[nsnap].mx = g_pd[i].mx;
            snap[nsnap].nlong = g_pd[i].nlong; snap[nsnap].nshort = g_pd[i].nshort; nsnap++;
            g_pd[i].cnt = 0; g_pd[i].sum = 0; g_pd[i].mx = 0; g_pd[i].mn = 0x7fffffffffffffffLL;
            g_pd[i].nlong = 0; g_pd[i].nshort = 0;   /* last は保持＝dt 連続性 */
        }
    }
    LeaveCriticalSection(&g_pd_cs);

    if (spike) {
        char line[160];
        wsprintfA(line, "{\"ev\":\"present.spike\",\"tid\":%lu,\"dt_us\":%ld,\"threaded\":%d}",
                  tid, (long)spike_us, (int)game_u8(VA_RENDER_THREADED));
        host_log("warn", line);
    }
    if (emit) {
        int sint = game_i32(VA_SWAP_INTERVAL_CUR), smin = game_i32(VA_SWAP_INTERVAL_MIN);
        int threaded = game_u8(VA_RENDER_THREADED), vsync_ok = game_ptr(VA_WGL_SWAPINT_PTR) != 0;
        for (i = 0; i < nsnap; i++) {
            char line[320];
            wsprintfA(line,
                "{\"ev\":\"present.stats\",\"tid\":%lu,\"frames\":%u,\"avg_us\":%ld,\"min_us\":%ld,\"max_us\":%ld,"
                "\"stalls\":%u,\"doubles\":%u,\"swap_int\":%d,\"swap_min\":%d,\"threaded\":%d,\"vsync_ok\":%d}",
                snap[i].tid, snap[i].cnt, (long)snap[i].avg, (long)snap[i].mn, (long)snap[i].mx,
                snap[i].nlong, snap[i].nshort, sint, smin, threaded, vsync_ok);
            host_log("info", line);
        }
    }
}

/* 診断レバー: NRSEDGE_SWAP_INTERVAL=N が設定されていれば、ゲームが解決済みの wglSwapIntervalEXT を
 * 毎 swap 直前に (N) で上書き呼びする（ゲームの global は触らない）。N=0 で vsync OFF。
 * TP(windowed) がビート無し＝present 設定差の疑い。vsync OFF で 33ms ビートが消えるかの対照実験用。 */
static void apply_forced_swapinterval(void) {
    static int forced = -2;   /* -2=未判定, -1=無効, それ以外=強制値 */
    static void (WINAPI *fn)(int);
    if (forced == -2) {
        const char *e = getenv("NRSEDGE_SWAP_INTERVAL");
        forced = (e && *e) ? atoi(e) : -1;
    }
    if (forced == -1) return;
    if (!fn) fn = (void (WINAPI *)(int))game_ptr(VA_WGL_SWAPINT_PTR);  /* ゲーム解決済みポインタ */
    if (fn) fn(forced);
}

/* o_SwapBuffers 自体の所要時間を測る。33ms ビートが「present 呼び出しの中（vsync/driver ブロック）」か
 * 「外（suspend/resume/描画/wait）」かを局在化する。>20ms のとき present.swapblock を即時ログ（100ms 制限）。 */
static LONGLONG g_sb_last_log;
static void present_swaptime(LONGLONG ticks) {
    if (!g_pd_init || g_qpf.QuadPart <= 0) return;
    LONGLONG us = ticks * 1000000LL / g_qpf.QuadPart;
    if (us <= 20000) return;
    LARGE_INTEGER now; QueryPerformanceCounter(&now);
    if ((now.QuadPart - g_sb_last_log) * 1000LL / g_qpf.QuadPart <= 100) return;
    g_sb_last_log = now.QuadPart;
    char line[128];
    wsprintfA(line, "{\"ev\":\"present.swapblock\",\"swap_us\":%ld}", (long)us);
    host_log("warn", line);
}

static BOOL (WINAPI *o_SwapBuffers)(HDC);
static BOOL (WINAPI *o_wglSwapBuffers)(HDC);
/* GL レンダラを一度だけログ。"GDI Generic"=ソフトウェア（HW アクセラレーション不発）の決定的証拠。 */
static void log_gl_renderer_once(void) {
    static int done;
    if (done) return;
    done = 1;
    const char *rend = glGetString(GL_RENDERER), *vend = glGetString(GL_VENDOR), *ver = glGetString(GL_VERSION);
    char line[384];
    wsprintfA(line, "{\"ev\":\"gl.info\",\"renderer\":\"%s\",\"vendor\":\"%s\",\"version\":\"%s\"}",
              rend ? rend : "(null)", vend ? vend : "(null)", ver ? ver : "(null)");
    host_log("info", line);
}

static BOOL WINAPI d_SwapBuffers(HDC hdc) {
    present_probe(); apply_forced_swapinterval(); capture_check(hdc);
    LARGE_INTEGER a, b; QueryPerformanceCounter(&a);
    BOOL r = o_SwapBuffers(hdc);
    QueryPerformanceCounter(&b); present_swaptime(b.QuadPart - a.QuadPart);
    log_gl_renderer_once();   /* GL context current の swap 後に */
    return r;
}
static BOOL WINAPI d_wglSwapBuffers(HDC hdc) {
    present_probe(); apply_forced_swapinterval(); capture_check(hdc);
    LARGE_INTEGER a, b; QueryPerformanceCounter(&a);
    BOOL r = o_wglSwapBuffers(hdc);
    QueryPerformanceCounter(&b); present_swaptime(b.QuadPart - a.QuadPart);
    return r;
}

static void ch(HMODULE m, const char *fn, void *det, void **orig) {
    if (!m) return;
    void *t = (void *)GetProcAddress(m, fn);
    if (t && MH_CreateHook(t, det, orig) == MH_OK) MH_EnableHook(t);
}

void capture_install(void) {   /* MH_Initialize は hooks_install で実施済 */
    ch(GetModuleHandleW(L"gdi32.dll"),    "SwapBuffers",    (void *)d_SwapBuffers,    (void **)&o_SwapBuffers);
    ch(LoadLibraryW(L"opengl32.dll"),     "wglSwapBuffers", (void *)d_wglSwapBuffers, (void **)&o_wglSwapBuffers);
    host_log("info", "{\"ev\":\"capture.hooks\"}");
}
