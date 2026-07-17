#include "host.h"

SRWLOCK        g_logic_lock;
const LogicApi *g_api   = 0;
LogicState    *g_state  = 0;
HostServices   g_host;

static unsigned char g_arena[1u << 20];
static size_t g_arena_off = 0;
void *host_arena_alloc(size_t n) {
    n = (n + 15) & ~(size_t)15;
    if (g_arena_off + n > sizeof g_arena) return 0;
    void *p = g_arena + g_arena_off; g_arena_off += n; return p;
}

static DWORD WINAPI host_init(LPVOID arg) {
    (void)arg;
    InitializeSRWLock(&g_logic_lock);
    g_host.abi_version = NRSEDGE_ABI_VERSION;
    g_host.log         = host_log;
    g_host.arena_alloc = host_arena_alloc;
    g_host.orig        = host_orig;
    g_host.cfg         = config_load();

    host_log("info", "{\"ev\":\"host.attach\"}");
    if (hooks_install() != 0)        { host_log("error", "{\"ev\":\"hooks.fail\"}"); return 1; }
    host_log("info", "{\"ev\":\"hooks.ok\"}");
    allnet_install();
    exitlog_install();
    if (reload_load_initial() != 0)  { host_log("error", "{\"ev\":\"logic.load.fail\"}"); return 1; }
    host_log("info", "{\"ev\":\"logic.ok\"}");
    if (gamehooks_install() != 0)    { host_log("warn",  "{\"ev\":\"gamehooks.partial\"}"); }
    host_log("info", "{\"ev\":\"gamehooks.ok\"}");
    dbglog_install();
    keychip_server_start();
    if (g_host.cfg && g_host.cfg->windowed) windowed_install();
    capture_install();
    reload_start_watcher();
    host_log("info", "{\"ev\":\"host.ready\"}");
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(0, 0, host_init, 0, 0, 0);
    }
    return TRUE;
}
