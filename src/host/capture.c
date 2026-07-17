#include "host.h"
#include "MinHook.h"
#include <stdlib.h>

__declspec(dllimport) void WINAPI glReadPixels(int x, int y, int w, int h, unsigned fmt, unsigned type, void *data);
__declspec(dllimport) void WINAPI glReadBuffer(unsigned mode);
__declspec(dllimport) const char * WINAPI glGetString(unsigned name);
#define GL_VENDOR   0x1F00u
#define GL_RENDERER 0x1F01u
#define GL_VERSION  0x1F02u
#define GL_BACK          0x0405u
#define GL_BGRA          0x80E1u
#define GL_UNSIGNED_BYTE 0x1401u

typedef struct { UINT32 GdiplusVersion; void *DebugEventCallback; BOOL SuppressBackgroundThread; BOOL SuppressExternalCodecs; } GdiplusStartupInput;
int WINAPI GdiplusStartup(ULONG_PTR *token, const GdiplusStartupInput *in, void *out);
int WINAPI GdipCreateBitmapFromScan0(int w, int h, int stride, int format, BYTE *scan0, void **bitmap);
int WINAPI GdipSaveImageToFile(void *image, const WCHAR *filename, const GUID *clsidEncoder, const void *encoderParams);
int WINAPI GdipDisposeImage(void *image);
#define PixelFormat32bppARGB 0x0026200A
#define PixelFormat32bppRGB  0x00220009
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
    if (GdipCreateBitmapFromScan0(w, h, -stride, PixelFormat32bppARGB,
                                  bgra + (size_t)(h - 1) * stride, &bmp) != 0 || !bmp) return;
    GdipSaveImageToFile(bmp, path, &PNG_ENCODER, NULL);
    GdipDisposeImage(bmp);
}

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
    { size_t px = (size_t)w * h; for (size_t i = 0; i < px; i++) buf[i * 4 + 3] = 0xFF; }
    save_png(buf, w, h, L"capture.png.tmp");
    free(buf);
    MoveFileExA("capture.png.tmp", "capture.png", MOVEFILE_REPLACE_EXISTING);
}

static void capture_check(HDC hdc) {
    static volatile LONG ctr;
    if ((InterlockedIncrement(&ctr) % 30) != 0) return;
    if (GetFileAttributesA("capture.req") == INVALID_FILE_ATTRIBUTES) return;
    DeleteFileA("capture.req");
    do_capture(hdc);
    host_log("info", "{\"ev\":\"capture.saved\",\"file\":\"capture.png\"}");
}

#define IMAGE_BASE 0x400000u
#define VA_SWAP_INTERVAL_CUR 0x016d8284u
#define VA_SWAP_INTERVAL_MIN 0x016d8288u
#define VA_RENDER_THREADED   0x022548c8u
#define VA_WGL_SWAPINT_PTR   0x016f5388u
#define PD_MAXTH 4
#define PD_WINDOW 300u

static LARGE_INTEGER g_qpf;
static CRITICAL_SECTION g_pd_cs;
static int g_pd_init;
static unsigned g_pd_swaps;
static LONGLONG g_pd_last_spike;
static struct { DWORD tid; LONGLONG last; unsigned cnt; LONGLONG sum, mx, mn; unsigned nlong, nshort; } g_pd[PD_MAXTH];

static int game_i32(unsigned va) { return *(volatile int *)((uintptr_t)GetModuleHandleW(NULL) + (va - IMAGE_BASE)); }
static unsigned char game_u8(unsigned va) { return *(volatile unsigned char *)((uintptr_t)GetModuleHandleW(NULL) + (va - IMAGE_BASE)); }
static void *game_ptr(unsigned va) { return *(void *volatile *)((uintptr_t)GetModuleHandleW(NULL) + (va - IMAGE_BASE)); }

static void present_probe(void) {
    if (!g_pd_init) { InitializeCriticalSection(&g_pd_cs); QueryPerformanceFrequency(&g_qpf); g_pd_init = 1; }
    LARGE_INTEGER now; QueryPerformanceCounter(&now);
    DWORD tid = GetCurrentThreadId();

    struct { DWORD tid; unsigned cnt; LONGLONG avg, mn, mx; unsigned nlong, nshort; } snap[PD_MAXTH];
    int nsnap = 0, emit = 0;
    int spike = 0; LONGLONG spike_us = 0;

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
            if (us > 25000) g_pd[slot].nlong++;
            if (us < 8000)  g_pd[slot].nshort++;
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
            g_pd[i].nlong = 0; g_pd[i].nshort = 0;
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

static void apply_forced_swapinterval(void) {
    static int forced = -2;
    static void (WINAPI *fn)(int);
    if (forced == -2) {
        const char *e = getenv("NRSEDGE_SWAP_INTERVAL");
        forced = (e && *e) ? atoi(e) : -1;
    }
    if (forced == -1) return;
    if (!fn) fn = (void (WINAPI *)(int))game_ptr(VA_WGL_SWAPINT_PTR);
    if (fn) fn(forced);
}

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
    log_gl_renderer_once();
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

void capture_install(void) {
    ch(GetModuleHandleW(L"gdi32.dll"),    "SwapBuffers",    (void *)d_SwapBuffers,    (void **)&o_SwapBuffers);
    ch(LoadLibraryW(L"opengl32.dll"),     "wglSwapBuffers", (void *)d_wglSwapBuffers, (void **)&o_wglSwapBuffers);
    host_log("info", "{\"ev\":\"capture.hooks\"}");
}
