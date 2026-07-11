/* host.dll — 注入時に一度ロードされる安定層。
 * 役割: フック設置(一度) / 状態 arena 所有 / logic ロード+reload / HostServices 提供。 */
#include "host.h"

SRWLOCK        g_logic_lock;
const LogicApi *g_api   = 0;
LogicState    *g_state  = 0;
HostServices   g_host;

/* 単純 bump arena（reload を跨いで生存。プロセス終了まで保持）。 */
static unsigned char g_arena[1u << 20];   /* 1 MiB。device 状態用。足りなければ拡張。 */
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
    g_host.cfg         = config_load();   /* nrsedge.cfg（GUI 指定の freeplay/test/windowed/binds）*/

    host_log("info", "{\"ev\":\"host.attach\"}");                                                  /* breadcrumb 0 */
    if (hooks_install() != 0)        { host_log("error", "{\"ev\":\"hooks.fail\"}"); return 1; }
    host_log("info", "{\"ev\":\"hooks.ok\"}");                                                      /* breadcrumb 1 */
    allnet_install();    /* ALL.Net HTTP バックエンド emu（PowerOn/card-info）＋ winsock redirect（netobs 内包）*/
    exitlog_install();   /* 終了経路を早期にフック（なぜ落ちる/終わるかの診断）*/
    if (reload_load_initial() != 0)  { host_log("error", "{\"ev\":\"logic.load.fail\"}"); return 1; }
    host_log("info", "{\"ev\":\"logic.ok\"}");                                                      /* breadcrumb 2 */
    if (gamehooks_install() != 0)    { host_log("warn",  "{\"ev\":\"gamehooks.partial\"}"); }  /* g_api 設定後 */
    host_log("info", "{\"ev\":\"gamehooks.ok\"}");                                                  /* breadcrumb 3 */
    dbglog_install();                /* nrs.exe 本体の amiDebug ログを窓へ（gate は patches.c で開放）*/
    keychip_server_start();          /* PCP keychip サーバ */
    if (g_host.cfg && g_host.cfg->windowed) windowed_install();   /* ウィンドウモード（config 連動）*/
    capture_install();   /* GL フレームキャプチャ（capture.req→capture.png）。テストの唯一の正式手段 */
    reload_start_watcher();
    host_log("info", "{\"ev\":\"host.ready\"}");
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(0, 0, host_init, 0, 0, 0);  /* loader resume 前後の競合を避け別スレッドで初期化 */
    }
    return TRUE;
}
