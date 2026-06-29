/* logic.dll のロードと hot-reload。fn-ptr 差し替えで swap（フックは張り直さない）。
 * 状態は host arena に置くので reload を跨いで生存。 */
#include "host.h"

typedef const LogicApi *(*get_api_fn)(void);

static HMODULE g_logic_mod = 0;
static FILETIME g_last_write;

static int file_mtime(const char *path, FILETIME *out) {
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fa)) return -1;
    *out = fa.ftLastWriteTime; return 0;
}

/* logic.dll を live コピー経由でロード（ビルドが logic.dll を上書きできるように）。
 * 重要: bind() は g_logic_lock を保持せずに呼ぶ。bind 内の host_log→fopen→CreateFile フックが
 * 同一スレッドで shared ロックを取り、exclusive 自己保持と self-deadlock するのを防ぐ。
 * ロックはポインタ swap の一瞬だけ（in-flight な hook dispatch の完了を待ち、安全に差し替え）。 */
static int g_gen = 0;
static int do_load(void) {
    char tmp[64];
    wsprintfA(tmp, "logic_live_%d.dll", ++g_gen);   /* 一意名: 旧 logic_live がロード中でも CopyFile 衝突しない */
    CopyFileA("logic.dll", tmp, FALSE);
    HMODULE m = LoadLibraryA(tmp);
    if (!m) return -1;
    get_api_fn g = (get_api_fn)GetProcAddress(m, "logic_get_api");
    if (!g) { FreeLibrary(m); return -1; }
    const LogicApi *api = g();
    if (!api || api->abi_version != NRSEDGE_ABI_VERSION) { FreeLibrary(m); return -1; }

    if (api->bind) api->bind(&g_host, &g_state);   /* ロック外で state 初期化/再バインド */

    AcquireSRWLockExclusive(&g_logic_lock);        /* swap のみ短時間ロック */
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
            Sleep(150);  /* ビルド完了待ち */
            int r = do_load();   /* swap ロックは do_load 内 */
            host_log(r ? "error" : "info",
                     r ? "{\"ev\":\"reload.fail\"}" : "{\"ev\":\"reload.ok\"}");
        }
    }
}

void reload_start_watcher(void) { CreateThread(0, 0, watcher, 0, 0, 0); }
