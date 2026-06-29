/* game-function hooks: nrs.exe 内部関数を VA で hook。
 * reload-safe: detour は安定 host 側に置き、現行 logic を g_api 経由で呼ぶ（logic.dll swap で無効化しない）。
 * 対象（全て void/u32 (void)）: jvs_update_main(0x67B150) / sysinput(0x89B230) / dipsw read(0x45A0E0)。 */
#include "host.h"
#include "MinHook.h"

#define IMAGE_BASE 0x400000u

static void     (*o_jvs_update)(void);
static void     (*o_sysinput)(void);
static unsigned (*o_dipsw)(void);
static int      (*o_kchold)(void);
static long long (__stdcall *o_rtc_get)(void *tm, unsigned *flag);

/* jvs_update_main PRE: 入力を node BSS へ書いてから本体へ（旧 input.js）。 */
static void __cdecl d_jvs_update(void) {
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_jvs_tick) g_api->on_jvs_tick(g_state);
    ReleaseSRWLockShared(&g_logic_lock);
    o_jvs_update();
}
/* system input processor PRE: DAT_0160194c の TEST/SERVICE を読まれる前に確定。 */
static void __cdecl d_sysinput(void) {
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_sys_override) g_api->on_sys_override(g_state);
    ReleaseSRWLockShared(&g_logic_lock);
    o_sysinput();
}
/* dipsw read POST: 本体が DAT_0160194c bit0/1 を立て直すのを打ち消す。 */
static unsigned __cdecl d_dipsw(void) {
    unsigned r = o_dipsw();
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_sys_override) g_api->on_sys_override(g_state);
    ReleaseSRWLockShared(&g_logic_lock);
    return r;
}

/* keychip_errCode1_latcher PRE: 真正 present なら present flag を立て直してから本体へ。 */
static int __cdecl d_kchold(void) {
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_keychip_hold) g_api->on_keychip_hold(g_state);
    ReleaseSRWLockShared(&g_logic_lock);
    return o_kchold();
}

/* amRtcGetServerTime(stdcall, longlong 戻り) POST: orig を呼び、失敗(-1)なら logic が PC 時刻で埋め成功を返す。
 * 規約厳密化が必須（disasm: RET 0x8 = stdcall / EAX:EDX = 64bit 戻り）。誤ると stack 破壊。 */
static long long __stdcall d_rtc_get(void *tm, unsigned *flag) {
    long long r = o_rtc_get(tm, flag);
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_rtc_get) r = g_api->on_rtc_get(g_state, tm, flag, r);
    ReleaseSRWLockShared(&g_logic_lock);
    return r;
}

static int gh(unsigned va, void *det, void **orig) {
    void *a = (void *)((uintptr_t)GetModuleHandleW(NULL) + (va - IMAGE_BASE));
    return (MH_CreateHook(a, det, orig) == MH_OK && MH_EnableHook(a) == MH_OK) ? 0 : -1;
}

int gamehooks_install(void) {   /* MH_Initialize は hooks_install で実施済 */
    int e = 0;
    e |= gh(0x67B150, (void *)d_jvs_update, (void **)&o_jvs_update);
    e |= gh(0x89B230, (void *)d_sysinput,   (void **)&o_sysinput);
    e |= gh(0x45A0E0, (void *)d_dipsw,      (void **)&o_dipsw);
    e |= gh(0x6F0A80, (void *)d_kchold,     (void **)&o_kchold);
    e |= gh(0x974040, (void *)d_rtc_get,    (void **)&o_rtc_get);
    return e;
}
