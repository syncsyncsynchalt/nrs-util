#include "host.h"
#include "MinHook.h"

#define IMAGE_BASE 0x400000u

static void     (*o_jvs_update)(void);
static void     (*o_sysinput)(void);
static unsigned (*o_dipsw)(void);
static int      (*o_kchold)(void);
static long long (__stdcall *o_rtc_get)(void *tm, unsigned *flag);
static int (__fastcall *o_eeprom_init)(unsigned ecx, unsigned edx, void *size_ptr);
static int (*o_dipsw_init)(void);
static void (*o_board_check)(void);
static unsigned (*o_ext_install_kick)(void);
static int      (*o_extimg_gate_probe)(void);

static void __cdecl d_jvs_update(void) {
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_jvs_tick) g_api->on_jvs_tick(g_state);
    ReleaseSRWLockShared(&g_logic_lock);
    o_jvs_update();
}
static void __cdecl d_sysinput(void) {
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_sys_override) g_api->on_sys_override(g_state);
    ReleaseSRWLockShared(&g_logic_lock);
    o_sysinput();
}
static unsigned __cdecl d_dipsw(void) {
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_dipsw_provision) g_api->on_dipsw_provision(g_state);
    ReleaseSRWLockShared(&g_logic_lock);
    unsigned r = o_dipsw();
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_sys_override) g_api->on_sys_override(g_state);
    ReleaseSRWLockShared(&g_logic_lock);
    return r;
}

static int __cdecl d_kchold(void) {
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_keychip_hold) g_api->on_keychip_hold(g_state);
    ReleaseSRWLockShared(&g_logic_lock);
    return o_kchold();
}

static long long __stdcall d_rtc_get(void *tm, unsigned *flag) {
    long long r = o_rtc_get(tm, flag);
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_rtc_get) r = g_api->on_rtc_get(g_state, tm, flag, r);
    ReleaseSRWLockShared(&g_logic_lock);
    return r;
}

static int __fastcall d_eeprom_init(unsigned ecx, unsigned edx, void *size_ptr) {
    (void)ecx; (void)edx; (void)size_ptr;
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_eeprom_init) g_api->on_eeprom_init(g_state);
    ReleaseSRWLockShared(&g_logic_lock);
    return 0;
}

static int __cdecl d_dipsw_init(void) {
    int r = o_dipsw_init();
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_dipsw_provision) g_api->on_dipsw_provision(g_state);
    ReleaseSRWLockShared(&g_logic_lock);
    return r;
}

static void __cdecl d_board_check(void) {
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    *(unsigned char *)(b + (0x1601953u - IMAGE_BASE)) = 2;
    *(unsigned int  *)(b + (0x160194Cu - IMAGE_BASE)) &= ~0x20u;
    o_board_check();
}

static int __cdecl d_extimg_gate_probe(void) {
    int r = o_extimg_gate_probe();
    *(unsigned char *)((uintptr_t)GetModuleHandleW(NULL) + (0x1601B23u - IMAGE_BASE)) = 1;
    return r;
}

static unsigned __cdecl d_ext_install_kick(void) {
    unsigned r = o_ext_install_kick();
    unsigned (*devmgr_ptr)(void) = (unsigned (*)(void))
        ((uintptr_t)GetModuleHandleW(NULL) + (0x72B450u - IMAGE_BASE));
    uintptr_t dm = (uintptr_t)devmgr_ptr();
    if (dm) {
        *(unsigned *)(dm + 0x258) = 0xC;
        *(unsigned *)(dm + 0x284) = 0;
    }
    return r;
}

static void (*o_frametick)(void);
static void (*o_present_drive)(void);
static void (*o_scene_dispatch)(void);
static LARGE_INTEGER g_pq_qpf; static int g_pq_init;
static LONGLONG g_pq_last; static unsigned g_pq_n;
static LONGLONG g_pq_dur_sum, g_pq_dur_max, g_pq_per_sum;
static LONGLONG g_pq_pd_sum, g_pq_pd_max, g_pq_sc_sum, g_pq_sc_max;
static LONGLONG pq_us(LONGLONG t){ return g_pq_qpf.QuadPart > 0 ? t * 1000000LL / g_pq_qpf.QuadPart : 0; }
static void __cdecl d_present_drive(void) {
    LARGE_INTEGER a, b; QueryPerformanceCounter(&a);
    o_present_drive();
    QueryPerformanceCounter(&b); LONGLONG d = b.QuadPart - a.QuadPart;
    g_pq_pd_sum += d; if (d > g_pq_pd_max) g_pq_pd_max = d;
}
static void __cdecl d_scene_dispatch(void) {
    LARGE_INTEGER a, b; QueryPerformanceCounter(&a);
    o_scene_dispatch();
    QueryPerformanceCounter(&b); LONGLONG d = b.QuadPart - a.QuadPart;
    g_pq_sc_sum += d; if (d > g_pq_sc_max) g_pq_sc_max = d;
}
static void __cdecl d_frametick(void) {
    if (!g_pq_init) { QueryPerformanceFrequency(&g_pq_qpf); g_pq_init = 1; }
    LARGE_INTEGER a; QueryPerformanceCounter(&a);
    if (g_pq_last) { LONGLONG p = a.QuadPart - g_pq_last; g_pq_per_sum += p; }
    g_pq_last = a.QuadPart;
    o_frametick();
    LARGE_INTEGER b; QueryPerformanceCounter(&b);
    LONGLONG d = b.QuadPart - a.QuadPart; g_pq_dur_sum += d; if (d > g_pq_dur_max) g_pq_dur_max = d;
    if (++g_pq_n >= 120) {
        char line[320];
        wsprintfA(line, "{\"ev\":\"pace.main\",\"n\":%u,\"frame_avg_us\":%ld,\"frame_max_us\":%ld,"
                  "\"present_avg_us\":%ld,\"present_max_us\":%ld,\"scene_avg_us\":%ld,\"scene_max_us\":%ld}",
                  g_pq_n, (long)pq_us(g_pq_dur_sum / g_pq_n), (long)pq_us(g_pq_dur_max),
                  (long)pq_us(g_pq_pd_sum / g_pq_n), (long)pq_us(g_pq_pd_max),
                  (long)pq_us(g_pq_sc_sum / g_pq_n), (long)pq_us(g_pq_sc_max));
        host_log("info", line);
        g_pq_n = 0; g_pq_dur_sum = g_pq_dur_max = g_pq_per_sum = 0;
        g_pq_pd_sum = g_pq_pd_max = g_pq_sc_sum = g_pq_sc_max = 0;
    }
}

static void *(*o_allnet_url)(void);
static const char g_allnet_url[] = "http://127.0.0.1/nrsedge";
static int g_allnet_url_logged;
static void *__cdecl d_allnet_url(void) {
    void *r = o_allnet_url();
    if (r == 0) return 0;
    if (!g_allnet_url_logged) {
        g_allnet_url_logged = 1;
        host_log("info", "{\"ev\":\"allnet.url.override\",\"uri\":\"http://127.0.0.1/nrsedge\"}");
    }
    return (void *)g_allnet_url;
}

static void (__fastcall *o_recv_parse)(void *self, void *edx, char *body, size_t len);
static void __fastcall d_recv_parse(void *self, void *edx, char *body, size_t len) {
    unsigned char *o = (unsigned char *)self;
    int  d4_pre = o ? *(int *)(o + 0xd4)     : 0;
    int  d8_pre = o ? *(int *)(o + 0xd8)     : 0;
    int  cmp    = o ? *(int *)(o + 0x20130)  : 0;
    int  f20120 = o ? *(int *)(o + 0x20120)  : 0;
    int  f20128 = o ? *(int *)(o + 0x20128)  : 0;
    int  f20134 = o ? *(int *)(o + 0x20134)  : 0;
    char snip[260]; size_t j = 0; snip[j++] = '"';
    for (size_t i = 0; body && i < len && i < 200 && j + 2 < sizeof snip; i++) {
        unsigned char c = (unsigned char)body[i];
        if (c == '"' || c == '\\') { snip[j++] = '\\'; snip[j++] = c; }
        else if (c >= 0x20 && c < 0x7f) snip[j++] = c;
        else snip[j++] = '.';
    }
    snip[j++] = '"'; snip[j] = 0;
    char m[520];
    wsprintfA(m, "{\"ev\":\"recv.parse.pre\",\"len\":%u,\"d4\":%d,\"d8\":%d,\"cmp\":%d,"
                 "\"f20120\":%d,\"f20128\":%d,\"f20134\":%d,\"body\":%s}",
              (unsigned)len, d4_pre, d8_pre, cmp, f20120, f20128, f20134, snip);
    host_log("info", m);

    o_recv_parse(self, edx, body, len);

    int d4_post = o ? *(int *)(o + 0xd4) : 0;
    int d8_post = o ? *(int *)(o + 0xd8) : 0;
    char m2[160];
    wsprintfA(m2, "{\"ev\":\"recv.parse.post\",\"d4\":%d,\"d8\":%d,\"changed\":%d}",
              d4_post, d8_post, (d4_post != d4_pre || d8_post != d8_pre));
    host_log("info", m2);
}

static void (__fastcall *o_cardinfo_send)(int *ctx, int edx);
static void __fastcall d_cardinfo_send(int *ctx, int edx) {
    unsigned uid = 0, slot = 0;
    if (ctx) { slot = (unsigned)ctx[2]; if (ctx[0]) uid = *(unsigned *)(ctx[0] + 0x3c); }
    char m[128];
    wsprintfA(m, "{\"ev\":\"cardinfo.send\",\"slot\":%u,\"uid_field\":%u}", slot, uid);
    host_log("info", m);
    o_cardinfo_send(ctx, edx);
}

static void (__cdecl *o_boot_sm)(int mgr);
static int g_bt_state = -1;
static int g_bt_subidx = -1;

static const char *bt_at(unsigned va) {
    return (const char *)((uintptr_t)GetModuleHandleW(NULL) + (va - IMAGE_BASE));
}
static const char *bt_state_label(int st) {
    unsigned va;
    switch (st) {
    case 2: va = 0xC811A0; break;
    case 3: va = 0xC811BC; break;
    case 4: va = 0xC811D8; break;
    case 5: va = 0xC811F0; break;
    case 6: va = 0xC81258; break;
    case 7: va = 0xC81280; break;
    default: return 0;
    }
    return bt_at(va);
}
static const char *bt_state_name(int st) {
    switch (st) {
    case 0:  return "init";
    case 1:  return "appdata-reload";
    case 2:  return "IC CARD R/W";
    case 3:  return "TOUCH PANEL";
    case 4:  return "NETWORK";
    case 5:  return "EXTEND IMAGE";
    case 6:  return "CONNECTION";
    case 7:  return "P-ras";
    case 8:  return "COMPLETE";
    case 9:  return "ERROR";
    case 10: return "done";
    default: return "?";
    }
}
static void bt_clean_label(const char *src, char *dst, size_t cap) {
    size_t len = 0, n = 0;
    if (!src) { dst[0] = 0; return; }
    while (*src == ' ') src++;
    while (src[len]) len++;
    while (len && (src[len-1] == ' ' || src[len-1] == '.')) len--;
    for (size_t i = 0; i < len && n + 1 < cap; i++) {
        char c = src[i];
        dst[n++] = (c >= 0x20 && c < 0x7f) ? c : '.';
    }
    dst[n] = 0;
}
static void bt_emit(int state, int idx, const char *label, const char *result) {
    char name[64]; bt_clean_label(label, name, sizeof name);
    char m[192];
    if (idx >= 0)
        wsprintfA(m, "{\"ev\":\"boot.check\",\"state\":%d,\"idx\":%d,\"check\":\"%s\",\"result\":\"%s\"}",
                  state, idx, name, result);
    else
        wsprintfA(m, "{\"ev\":\"boot.check\",\"state\":%d,\"check\":\"%s\",\"result\":\"%s\"}",
                  state, name, result);
    host_log("info", m);
}

static void __cdecl d_boot_sm(int mgr) {
    o_boot_sm(mgr);
    if (!mgr) return;
    int st  = *(int *)(mgr + 4);
    int sub = *(int *)(mgr + 0x14);

    if (g_bt_state == 6 && st == 6 && g_bt_subidx >= 1 && sub != g_bt_subidx) {
        int idx = g_bt_subidx;
        unsigned (*devmgr_ptr)(void) = (unsigned (*)(void))bt_at(0x72B450);
        uintptr_t dm = (uintptr_t)devmgr_ptr();
        const char *lbl = *(const char **)(bt_at(0xCF5464) + idx * 4);
        if (dm && lbl && *lbl) {
            int status = *(int *)(dm + 0x1d4 + idx * 4);
            const char *res = status == 2 ? "OK" : status == 3 ? "NG" : status == 0 ? "NA" : "?";
            bt_emit(6, idx, lbl, res);
        }
    }

    if (st != g_bt_state) {
        int prev = g_bt_state;
        char m0[128];
        wsprintfA(m0, "{\"ev\":\"boot.state\",\"from\":%d,\"to\":%d,\"state\":\"%s\"}",
                  prev, st, bt_state_name(st));
        host_log("info", m0);
        if (prev >= 2 && prev <= 7) {
            const char *lbl = bt_state_label(prev);
            if (st == 9) {
                int ec = *(int *)bt_at(0x16F5AF0);
                char m[192], name[64]; bt_clean_label(lbl, name, sizeof name);
                wsprintfA(m, "{\"ev\":\"boot.check\",\"state\":%d,\"check\":\"%s\",\"result\":\"NG\",\"errCode\":%d}",
                          prev, name, ec);
                host_log("warn", m);
            } else if (prev == 5) {
                bt_emit(5, -1, lbl, *(unsigned char *)bt_at(0x1601B23) ? "OK" : "NG");
            } else if (prev != 6) {
                bt_emit(prev, -1, lbl, "OK");
            }
        }
        if (st == 6 && prev != 6) {
            char name[64]; bt_clean_label(bt_state_label(6), name, sizeof name);
            char m[128];
            wsprintfA(m, "{\"ev\":\"boot.check\",\"state\":6,\"check\":\"%s\"}", name);
            host_log("info", m);
        }
        if (st == 10)
            host_log("info", "{\"ev\":\"boot.complete\"}");
        g_bt_state = st;
    }
    g_bt_subidx = sub;
}

static int gh(unsigned va, void *det, void **orig) {
    void *a = (void *)((uintptr_t)GetModuleHandleW(NULL) + (va - IMAGE_BASE));
    return (MH_CreateHook(a, det, orig) == MH_OK && MH_EnableHook(a) == MH_OK) ? 0 : -1;
}

int gamehooks_install(void) {
    int e = 0;
    e |= gh(0x67B150, (void *)d_jvs_update, (void **)&o_jvs_update);
    e |= gh(0x89B230, (void *)d_sysinput,   (void **)&o_sysinput);
    e |= gh(0x45A0E0, (void *)d_dipsw,      (void **)&o_dipsw);
    e |= gh(0x6F0A80, (void *)d_kchold,     (void **)&o_kchold);
    e |= gh(0x974040, (void *)d_rtc_get,    (void **)&o_rtc_get);
    e |= gh(0x985160, (void *)d_eeprom_init,(void **)&o_eeprom_init);
    e |= gh(0x9842A0, (void *)d_dipsw_init, (void **)&o_dipsw_init);
    e |= gh(0x679CB0, (void *)d_board_check,(void **)&o_board_check);
    e |= gh(0x45A8F0, (void *)d_extimg_gate_probe,(void **)&o_extimg_gate_probe);
    e |= gh(0x72EAF0, (void *)d_ext_install_kick,(void **)&o_ext_install_kick);
    e |= gh(0x6FF7E0, (void *)d_allnet_url,      (void **)&o_allnet_url);
    e |= gh(0x643DE0, (void *)d_frametick,     (void **)&o_frametick);
    e |= gh(0x6C3930, (void *)d_present_drive,  (void **)&o_present_drive);
    e |= gh(0x89DAC0, (void *)d_scene_dispatch, (void **)&o_scene_dispatch);
    e |= gh(0x712710, (void *)d_recv_parse,     (void **)&o_recv_parse);
    e |= gh(0x7203E0, (void *)d_cardinfo_send,  (void **)&o_cardinfo_send);
    e |= gh(0x89A010, (void *)d_boot_sm,        (void **)&o_boot_sm);
    return e;
}
