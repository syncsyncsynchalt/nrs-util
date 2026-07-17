#include "host.h"

typedef const LogicApi *(*get_api_fn)(void);

static HMODULE g_logic_mod = 0;
static FILETIME g_last_write;

static int file_mtime(const char *path, FILETIME *out) {
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fa)) return -1;
    *out = fa.ftLastWriteTime; return 0;
}

static int g_gen = 0;
static int do_load(void) {
    char tmp[64];
    wsprintfA(tmp, "logic_live_%d.dll", ++g_gen);
    CopyFileA("logic.dll", tmp, FALSE);
    HMODULE m = LoadLibraryA(tmp);
    if (!m) return -1;
    get_api_fn g = (get_api_fn)GetProcAddress(m, "logic_get_api");
    if (!g) { FreeLibrary(m); return -1; }
    const LogicApi *api = g();
    if (!api || api->abi_version != NRSEDGE_ABI_VERSION) { FreeLibrary(m); return -1; }

    if (api->bind) api->bind(&g_host, &g_state);

    AcquireSRWLockExclusive(&g_logic_lock);
    HMODULE old = g_logic_mod;
    g_logic_mod = m;
    g_api = api;
    ReleaseSRWLockExclusive(&g_logic_lock);
    if (old) FreeLibrary(old);
    return 0;
}

int reload_load_initial(void) {
    file_mtime("logic.dll", &g_last_write);
    return do_load();
}

static DWORD WINAPI watcher(LPVOID a) {
    (void)a;
    for (;;) {
        Sleep(400);
        FILETIME ft;
        if (file_mtime("logic.dll", &ft) == 0 && CompareFileTime(&ft, &g_last_write) != 0) {
            g_last_write = ft;
            Sleep(150);
            int r = do_load();
            host_log(r ? "error" : "info",
                     r ? "{\"ev\":\"reload.fail\"}" : "{\"ev\":\"reload.ok\"}");
        }
    }
}

void reload_start_watcher(void) { CreateThread(0, 0, watcher, 0, 0, 0); }
