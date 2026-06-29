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

/* 要求ファイル検知（毎 swap。GetFileAttributes は軽量）。あれば 1 フレーム保存して req 削除。 */
static void capture_check(HDC hdc) {
    if (GetFileAttributesA("capture.req") == INVALID_FILE_ATTRIBUTES) return;
    DeleteFileA("capture.req");           /* 先に削除＝二重 swap でも 1 回 */
    do_capture(hdc);
    host_log("info", "{\"ev\":\"capture.saved\",\"file\":\"capture.png\"}");
}

static BOOL (WINAPI *o_SwapBuffers)(HDC);
static BOOL (WINAPI *o_wglSwapBuffers)(HDC);
static BOOL WINAPI d_SwapBuffers(HDC hdc)    { capture_check(hdc); return o_SwapBuffers(hdc); }
static BOOL WINAPI d_wglSwapBuffers(HDC hdc) { capture_check(hdc); return o_wglSwapBuffers(hdc); }

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
