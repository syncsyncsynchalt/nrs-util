#include "host.h"
#include "MinHook.h"

static LONG (WINAPI *o_CDSA)(void *, DWORD);
static LONG (WINAPI *o_CDSW)(void *, DWORD);
static LONG (WINAPI *o_CDSExA)(const char *, void *, HWND, DWORD, void *);
static LONG (WINAPI *o_CDSExW)(const wchar_t *, void *, HWND, DWORD, void *);
static HWND (WINAPI *o_CWExA)(DWORD, const char *, const char *, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, void *);
static HWND (WINAPI *o_CWExW)(DWORD, const wchar_t *, const wchar_t *, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, void *);

#define WS_POPUP_            0x80000000u
#define WS_DISABLED_         0x08000000u
#define WS_OVERLAPPEDWINDOW_ 0x00CF0000u
#define WS_EX_TOPMOST_       0x00000008u

static int should_convert(DWORD st, int w, int h) {
    if (!(st & WS_POPUP_))   return 0;
    if (st & WS_DISABLED_)   return 0;
    if (w == 0 && h == 0)    return 0;
    return 1;
}

static LONG WINAPI d_CDSA(void *dm, DWORD f) { (void)dm; (void)f; return 0; }
static LONG WINAPI d_CDSW(void *dm, DWORD f) { (void)dm; (void)f; return 0; }
static LONG WINAPI d_CDSExA(const char *n, void *dm, HWND h, DWORD f, void *p) { (void)n;(void)dm;(void)h;(void)f;(void)p; return 0; }
static LONG WINAPI d_CDSExW(const wchar_t *n, void *dm, HWND h, DWORD f, void *p) { (void)n;(void)dm;(void)h;(void)f;(void)p; return 0; }

static HWND WINAPI d_CWExA(DWORD ex, const char *cn, const char *wn, DWORD st, int x, int y, int w, int h,
                           HWND par, HMENU mn, HINSTANCE in, void *pa) {
    if (should_convert(st, w, h)) { st = (st & ~WS_POPUP_) | WS_OVERLAPPEDWINDOW_; ex &= ~WS_EX_TOPMOST_; }
    return o_CWExA(ex, cn, wn, st, x, y, w, h, par, mn, in, pa);
}
static HWND WINAPI d_CWExW(DWORD ex, const wchar_t *cn, const wchar_t *wn, DWORD st, int x, int y, int w, int h,
                           HWND par, HMENU mn, HINSTANCE in, void *pa) {
    if (should_convert(st, w, h)) { st = (st & ~WS_POPUP_) | WS_OVERLAPPEDWINDOW_; ex &= ~WS_EX_TOPMOST_; }
    return o_CWExW(ex, cn, wn, st, x, y, w, h, par, mn, in, pa);
}

static void wh(HMODULE u, const char *fn, void *det, void **orig) {
    void *t = (void *)GetProcAddress(u, fn);
    if (t && MH_CreateHook(t, det, orig) == MH_OK) MH_EnableHook(t);
}

void windowed_install(void) {
    HMODULE u = LoadLibraryW(L"user32.dll");
    if (!u) return;
    wh(u, "ChangeDisplaySettingsA",   (void *)d_CDSA,   (void **)&o_CDSA);
    wh(u, "ChangeDisplaySettingsW",   (void *)d_CDSW,   (void **)&o_CDSW);
    wh(u, "ChangeDisplaySettingsExA", (void *)d_CDSExA, (void **)&o_CDSExA);
    wh(u, "ChangeDisplaySettingsExW", (void *)d_CDSExW, (void **)&o_CDSExW);
    wh(u, "CreateWindowExA",          (void *)d_CWExA,  (void **)&o_CWExA);
    wh(u, "CreateWindowExW",          (void *)d_CWExW,  (void **)&o_CWExW);
    host_log("info", "{\"ev\":\"windowed.hooks\"}");
}
