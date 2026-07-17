#include "abi.h"
#include "driver/mxjvs.h"
#include "driver/input.h"
#include "driver/mxdevices.h"
#include "driver/touch.h"
#include "driver/card.h"
#include "patches.h"
#include <string.h>

struct LogicState {
    HostServices *host;
    int patched;
    unsigned tick;
    unsigned last_keys;
    unsigned sys_tick;
    int      test_entered;
    int      eeprom_fixed;
    HANDLE   eeprom_mutex;
    int      dipsw_fixed;
    HANDLE   dipsw_mutex;
    HANDLE   dipsw_event;
    HANDLE   sysver_handle;
    int      sysver_off;
    HANDLE   jvs_handle;
    JvsBoard jvs;
    uint8_t  jvs_resp[512];
    int      jvs_resp_len;
    int      jvs_resp_off;
    HANDLE     touch_handle;
    TouchPanel touch;
    int        touch_opened_logged;
    uint8_t    touch_last_press;
    int        touch_winwarn;
    HANDLE     card_handle;
    CardReader card;
    int        card_opened_logged;
    int        netauth_logged;
    int        card_ctl_seen;
    FILETIME   card_ctl_mtime;
    unsigned   card_ctl_gen;
    wchar_t    card_img_path[MAX_PATH];
    int        card_force_logged;
    int        card_accept_logged;
    int        touch_ctl_seen;
    FILETIME   touch_ctl_mtime;
    int        touch_force;
    uint8_t    touch_force_press;
    uint16_t   touch_force_x, touch_force_y;
};

static void l_bind(HostServices *host, LogicState **state) {
    if (!*state) {
        *state = (LogicState *)host->arena_alloc(sizeof(LogicState));
        memset(*state, 0, sizeof(LogicState));
        mxjvs_init(&(*state)->jvs);
        touch_init(&(*state)->touch);
        card_init(&(*state)->card);
    }
    (*state)->host = host;
    mxdev_init(host);
    if (!(*state)->patched) { patches_apply(host); (*state)->patched = 1; }
    host->log("info", "{\"ev\":\"logic.bind\",\"abi\":1}");
}

static int is_com(const wchar_t *name, const wchar_t *want) {
    if (!name) return 0;
    size_t ln = wcslen(name), lw = wcslen(want);
    return ln >= lw && _wcsicmp(name + (ln - lw), want) == 0;
}

static int jvs_com_port(LogicState *st) {
    int p = (st->host && st->host->cfg) ? st->host->cfg->jvs_com : 0;
    return p ? p : 4;
}
static int is_jvs_com(LogicState *st, const wchar_t *name) {
    wchar_t want[8]; wsprintfW(want, L"COM%d", jvs_com_port(st));
    return is_com(name, want);
}

static HANDLE on_create_file(LogicState *st, const wchar_t *name, DWORD a, DWORD s,
                             DWORD d, DWORD f, int *handled) {
    (void)a; (void)s; (void)d; (void)f;
    if (is_jvs_com(st, name)) {
        st->jvs_handle = (HANDLE)(uintptr_t)0xC0114000;   /* sentinel */
        st->jvs_resp_len = st->jvs_resp_off = 0;
        char m[64]; wsprintfA(m, "{\"ev\":\"jvs.open\",\"port\":\"COM%d\"}", jvs_com_port(st));
        st->host->log("info", m);
        *handled = 1;
        return st->jvs_handle;
    }
    if (is_com(name, L"COM1") && !is_jvs_com(st, name)) {
        st->touch_handle = (HANDLE)(uintptr_t)0xC0114001;   /* sentinel */
        touch_init(&st->touch);
        st->touch_opened_logged = 0;
        st->host->log("info", "{\"ev\":\"touch.open\",\"port\":\"COM1\"}");
        *handled = 1;
        return st->touch_handle;
    }
    if (is_com(name, L"COM2") && !is_jvs_com(st, name)) {
        st->card_handle = (HANDLE)(uintptr_t)0xC0114003;   /* sentinel */
        card_init(&st->card);
        st->card_opened_logged = 0;
        st->host->log("info", "{\"ev\":\"card.open\",\"port\":\"COM2\"}");
        *handled = 1;
        return st->card_handle;
    }
    if (is_com(name, L"SystemVersion.txt")) {
        st->sysver_handle = (HANDLE)(uintptr_t)0xC0114002;   /* sentinel */
        st->sysver_off = 0;
        st->host->log("info", "{\"ev\":\"sysver.open\",\"file\":\"SystemVersion.txt\"}");
        *handled = 1;
        return st->sysver_handle;
    }
    {
        HANDLE mh;
        if (mxdev_create(name, &mh)) { *handled = 1; return mh; }
    }
    *handled = 0;
    return INVALID_HANDLE_VALUE;
}

static int jvs_to_hex(char *dst, int cap, const uint8_t *p, int n) {
    int o = 0;
    for (int i = 0; i < n && o + 3 < cap; i++) o += wsprintfA(dst + o, "%02x", p[i]);
    return o;
}

static void jvs_io_log(LogicState *st, const uint8_t *req, int rn, const uint8_t *resp, int sn) {
    static uint8_t last_req[260];  static int last_rn = -1;
    static uint8_t last_resp[260]; static int last_sn = -1;
    int rc = rn < (int)sizeof last_req, sc = sn < (int)sizeof last_resp;
    if (rc && sc && rn == last_rn && sn == last_sn
        && memcmp(req, last_req, rn) == 0 && memcmp(resp, last_resp, sn) == 0) return;
    char m[700]; int o = wsprintfA(m, "{\"ev\":\"jvs.io\",\"cmd\":\"%02x\",\"wr\":\"",
                                   rn > 3 ? req[3] : 0);
    o += jvs_to_hex(m + o, (int)sizeof m - o - 12, req, rn);
    o += wsprintfA(m + o, "\",\"rd\":\"");
    o += jvs_to_hex(m + o, (int)sizeof m - o - 4, resp, sn);
    wsprintfA(m + o, "\"}");
    if (st->host && st->host->log) st->host->log("info", m);
    if (rc) { memcpy(last_req, req, rn); last_rn = rn; }
    if (sc) { memcpy(last_resp, resp, sn); last_sn = sn; }
}

static BOOL on_write_file(LogicState *st, HANDLE h, const void *buf, DWORD n, DWORD *put, int *hd) {
    if (h == st->jvs_handle) {
        NrsInput in; nrs_poll_input(&in, st->host && st->host->cfg ? st->host->cfg->bind : 0);
        mxjvs_set_input(&st->jvs, &in);
        st->jvs_resp_len = mxjvs_handle_frame(&st->jvs, (const uint8_t *)buf, (int)n,
                                              st->jvs_resp, (int)sizeof st->jvs_resp);
        st->jvs_resp_off = 0;
        jvs_io_log(st, (const uint8_t *)buf, (int)n, st->jvs_resp, st->jvs_resp_len);
        if (put) *put = n;
        *hd = 1;
        return TRUE;
    }
    if (h == st->touch_handle) {
        {
            const uint8_t *b = (const uint8_t *)buf;
            char m[160]; int o = wsprintfA(m, "{\"ev\":\"touch.write\",\"n\":%d,\"hex\":\"", (int)n);
            for (DWORD i = 0; i < n && i < 16 && o + 3 < (int)sizeof m; i++) o += wsprintfA(m + o, "%02x", b[i]);
            wsprintfA(m + o, "\"}");
            if (st->host && st->host->log) st->host->log("info", m);
        }
        touch_on_write(&st->touch, (const uint8_t *)buf, (int)n);
        if (put) *put = n;
        *hd = 1;
        return TRUE;
    }
    if (h == st->card_handle) {
        {
            const uint8_t *b = (const uint8_t *)buf;
            char m[160]; int o = wsprintfA(m, "{\"ev\":\"card.write\",\"n\":%d,\"hex\":\"", (int)n);
            for (DWORD i = 0; i < n && i < 16 && o + 3 < (int)sizeof m; i++) o += wsprintfA(m + o, "%02x", b[i]);
            wsprintfA(m + o, "\"}");
            if (st->host && st->host->log) st->host->log("info", m);
        }
        card_on_write(&st->card, (const uint8_t *)buf, (int)n);
        if (put) *put = n;
        *hd = 1;
        return TRUE;
    }
    return mxdev_write(h, buf, n, put, hd);
}

static BOOL on_read_file(LogicState *st, HANDLE h, void *buf, DWORD n, DWORD *got, int *hd) {
    if (h == st->jvs_handle) {
        int avail = st->jvs_resp_len - st->jvs_resp_off;
        int k = ((int)n < avail) ? (int)n : avail;
        if (k < 0) k = 0;
        memcpy(buf, st->jvs_resp + st->jvs_resp_off, (size_t)k);
        st->jvs_resp_off += k;
        if (got) *got = (DWORD)k;
        *hd = 1;
        return TRUE;
    }
    if (h == st->touch_handle) {
        if (st->touch_force) {
            st->touch.x = st->touch_force_x; st->touch.y = st->touch_force_y;
            st->touch.pressed = st->touch_force_press;
        } else {
            HWND w = FindWindowW(NULL, L"WGL"); touch_sample_mouse(&st->touch, w ? w : GetForegroundWindow());
        }
        int k = touch_on_read(&st->touch, (uint8_t *)buf, (int)n);
        if (got) *got = (DWORD)k;
        if (st->host && st->host->log) {
            unsigned r = st->touch.reads;
            if (!st->touch_opened_logged || st->touch.pressed != st->touch_last_press || (r % 120) == 0) {
                char m[180];
                wsprintfA(m, "{\"ev\":\"touch.read\",\"x\":%u,\"y\":%u,\"press\":%u,\"bytes\":%d,\"reads\":%u}",
                          st->touch.x, st->touch.y, st->touch.pressed, k, r);
                st->host->log("info", m);
                st->touch_opened_logged = 1;
                st->touch_last_press = st->touch.pressed;
            }
        }
        *hd = 1;
        return TRUE;
    }
    if (h == st->card_handle) {
        int k = card_on_read(&st->card, (uint8_t *)buf, (int)n);
        if (got) *got = (DWORD)k;
        if (st->host && st->host->log && (!st->card_opened_logged || k > 0)) {
            char m[200]; int o = wsprintfA(m, "{\"ev\":\"card.read\",\"bytes\":%d,\"reads\":%u,\"hex\":\"",
                                           k, st->card.reads);
            for (int i = 0; i < k && i < 16 && o + 3 < (int)sizeof m; i++)
                o += wsprintfA(m + o, "%02x", ((uint8_t *)buf)[i]);
            wsprintfA(m + o, "\"}");
            st->host->log("info", m);
            st->card_opened_logged = 1;
        }
        *hd = 1;
        return TRUE;
    }
    if (h == st->sysver_handle) {
        static const char ver[8] = { '2','0','1','1','0','7','2','8' };
        int avail = (int)sizeof ver - st->sysver_off;
        int k = ((int)n < avail) ? (int)n : avail;
        if (k < 0) k = 0;
        if (k > 0) memcpy(buf, ver + st->sysver_off, k);
        st->sysver_off += k;
        if (got) *got = (DWORD)k;
        *hd = 1;
        return TRUE;
    }
    return mxdev_read(h, buf, n, got, hd);
}

static BOOL on_ioctl(LogicState *st, HANDLE h, DWORD c, void *i, DWORD il, void *o, DWORD ol,
                     DWORD *r, int *hd) {
    (void)st;
    return mxdev_ioctl(h, c, i, il, o, ol, r, hd);
}

static DWORD on_set_file_pointer(LogicState *st, HANDLE h, long dist, long *dist_high,
                                 DWORD method, int *hd) {
    (void)st;
    return mxdev_seek(h, dist, dist_high, method, hd);
}

static BOOL on_close(LogicState *st, HANDLE h, int *hd) {
    uintptr_t v = (uintptr_t)h;
    if (h == st->jvs_handle) { st->jvs_handle = 0; *hd = 1; return TRUE; }
    if (h == st->touch_handle) { st->touch_handle = 0; *hd = 1; return TRUE; }
    if (h == st->card_handle) { st->card_handle = 0; *hd = 1; return TRUE; }
    if (v >= 0xD0000001u && v <= 0xD0000005u) { *hd = 1; return TRUE; }
    *hd = 0; return FALSE;
}

static BOOL on_comm_control(LogicState *st, HANDLE h, int op, void *p1, DWORD p2, void *p3, int *hd) {
    if (h == st->touch_handle) {
        (void)p2;
        *hd = 1;
        if (op == COMCTL_GET_MODEM_STATUS) { if (p1) *(DWORD *)p1 = 0; }
        else if (op == COMCTL_CLEAR_ERROR) {
            if (p1) *(DWORD *)p1 = 0;
            if (p3) { COMSTAT *cs = (COMSTAT *)p3; memset(cs, 0, sizeof *cs);
                      cs->cbInQue = TOUCH_FRAME_LEN; }
        }
        return TRUE;
    }
    if (h == st->card_handle) {
        (void)p2;
        *hd = 1;
        if (op == COMCTL_GET_MODEM_STATUS) { if (p1) *(DWORD *)p1 = 0; }
        else if (op == COMCTL_CLEAR_ERROR) {
            if (p1) *(DWORD *)p1 = 0;
            if (p3) { COMSTAT *cs = (COMSTAT *)p3; memset(cs, 0, sizeof *cs);
                      cs->cbInQue = (DWORD)card_rx_pending(&st->card); }
        }
        return TRUE;
    }
    if (h != st->jvs_handle) { *hd = 0; return FALSE; }
    (void)p2;
    *hd = 1;
    switch (op) {
    case COMCTL_GET_MODEM_STATUS:
        if (p1) *(DWORD *)p1 = st->jvs.sense ? 0 : MS_DSR_ON;
        break;
    case COMCTL_CLEAR_ERROR:
        if (p1) *(DWORD *)p1 = 0;
        if (p3) memset(p3, 0, sizeof(COMSTAT));
        break;
    default: break;
    }
    return TRUE;
}

static void eeprom_force_ready(LogicState *st) {
    if (st->eeprom_fixed) return;
    st->eeprom_fixed = 1;
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    volatile uint32_t *initFlag = (uint32_t *)(b + (0xCCF4E0u - 0x400000u));
    if (*initFlag != 0) return;
    if (!st->eeprom_mutex) st->eeprom_mutex = CreateMutexA(NULL, FALSE, NULL);
    *(uint32_t *)(b + (0xCCF4E4u - 0x400000u)) = 6;
    *(uint32_t *)(b + (0xCCF4E8u - 0x400000u)) = 6;
    *(HANDLE   *)(b + (0xCCF4ECu - 0x400000u)) = st->eeprom_mutex;
    *(HANDLE   *)(b + (0xCCF4F0u - 0x400000u)) = mxdev_smbus_handle();
    *(uint8_t  *)(b + (0xCCF4F4u - 0x400000u)) = 0x57;
    *initFlag = 1;
    if (st->host && st->host->log)
        st->host->log("info", "{\"ev\":\"eeprom.force_ready\",\"dev\":\"mxsmbus\",\"hdl\":\"H_MXSMBUS\"}");
}

static void dipsw_force_ready(LogicState *st) {
    if (st->dipsw_fixed) return;
    st->dipsw_fixed = 1;
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    HANDLE *handle = (HANDLE *)(b + (0xCCF490u - 0x400000u));
    if (*handle != INVALID_HANDLE_VALUE && *handle != (HANDLE)0) return;
    if (!st->dipsw_mutex) st->dipsw_mutex = CreateMutexA(NULL, FALSE, NULL);
    if (!st->dipsw_event) st->dipsw_event = CreateEventA(NULL, FALSE, FALSE, NULL);
    *(HANDLE   *)(b + (0xCCF48Cu - 0x400000u)) = st->dipsw_mutex;
    *(HANDLE   *)(b + (0xCCF490u - 0x400000u)) = mxdev_smbus_handle();
    *(uint8_t  *)(b + (0xCCF494u - 0x400000u)) = 0x20;
    *(uint32_t *)(b + (0xCCF4C0u - 0x400000u)) = 0;
    *(HANDLE   *)(b + (0xCCF4D8u - 0x400000u)) = st->dipsw_event;
    *(uint32_t *)(b + (0xCCF488u - 0x400000u)) = 1;
    if (st->host && st->host->log)
        st->host->log("info", "{\"ev\":\"dipsw.force_ready\",\"dev\":\"mxsmbus\",\"addr\":\"0x20\"}");
}

static void network_nic_bridge(LogicState *st) {
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    *(uint8_t *)(b + (0x16019A5u - 0x400000u)) = 1;
    *(uint8_t *)(b + (0x16019A6u - 0x400000u)) = 1;
    if (!st->netauth_logged && st->host && st->host->log) {
        st->host->log("info", "{\"ev\":\"net.nic_bridge\",\"note\":\"genuine ALL.Net auth via allnet.c (LAN IP presentation)\"}");
        st->netauth_logged = 1;
    }
}

static void mmgp_diag(LogicState *st) {
    static unsigned n; static int last_state = -99, last_sub = -99;
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    unsigned svc6c = *(uint32_t *)(b + (0x0227FE6Cu - 0x400000u));
    int svc70 = (*(uint32_t *)(b + (0x0227FE70u - 0x400000u)) & 4) ? 1 : 0;
    unsigned subsys = *(uint32_t *)(b + (0x16B8B54u - 0x400000u));
    int lockout = *(uint8_t *)(b + (0x16B8B6Bu - 0x400000u));
    int state = -1, sub = -1, accept = -1, req = -1, msgres = -2, msgst = -2, found = 0;
    int *node = *(int **)(b + (0x16DB564u - 0x400000u));
    for (int guard = 0; node && guard < 64; guard++) {
        if (node[1] == 0x50474d4d) {
            unsigned char *so = (unsigned char *)(uintptr_t)node[4];
            if (so) {
                found = 1; state = *(int *)so; sub = *(int *)(so + 4);
                accept = so[0xc]; req = so[0xd];
                int msg = *(int *)(so + 8);
                if (msg) { msgres = *(int *)((uintptr_t)msg + 0x1ac); msgst = *(int *)((uintptr_t)msg + 8); }
            }
            break;
        }
        node = (int *)(uintptr_t)node[0xf];
    }
    if (state != last_state || sub != last_sub || (n++ % 120) == 0) {
        char m[320];
        wsprintfA(m, "{\"ev\":\"mmgp.diag\",\"svc6c\":\"%x\",\"gate0x400\":%d,\"svc70_4\":%d,\"subsys\":%u,"
                     "\"lockout\":%d,\"found\":%d,\"state\":%d,\"sub\":%d,\"accept\":%d,\"req\":%d,"
                     "\"msgres\":%d,\"msgst\":%d}",
                  svc6c & 0x700, (svc6c & 0x400) ? 1 : 0, svc70, subsys, lockout, found,
                  state, sub, accept, req, msgres, msgst);
        if (st->host && st->host->log) st->host->log("info", m);
        last_state = state; last_sub = sub;
    }
}

static unsigned char *touch_data_ctx(void) {
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    int *node = *(int **)(b + (0x16d8690u - 0x400000u));
    if (!node) {
        node = *(int **)(b + (0x16db564u - 0x400000u));
        while (node && (node[0] != 0x22 || node[1] != 0x22)) node = (int *)node[0xf];
        if (!node) return 0;
    }
    return (unsigned char *)(uintptr_t)node[4];
}

static void touch_diag(LogicState *st) {
    static unsigned n;
    unsigned char *c0 = touch_data_ctx();
    if (c0) {
        static int last_act = -1;
        int act = (c0[0x211] != 0) | ((c0[0x166] & 3) ? 2 : 0) | (c0[0x210] ? 4 : 0);
        if (act != last_act) {
            char e[200];
            wsprintfA(e, "{\"ev\":\"touch.event\",\"active211\":%d,\"status166\":%d,\"edge210\":%d,"
                         "\"x234\":%d,\"y238\":%d,\"rawX\":%d}",
                      c0[0x211], c0[0x166], c0[0x210], (int)*(float *)(c0 + 0x234),
                      (int)*(float *)(c0 + 0x238), *(unsigned short *)(c0 + 0x216));
            if (st->host && st->host->log) st->host->log("info", e);
            last_act = act;
        }
    }
    if ((n++ % 120) != 0) return;
    unsigned char *c = touch_data_ctx();
    if (!c) { if (st->host && st->host->log) st->host->log("info", "{\"ev\":\"touch.diag\",\"ctx\":0}"); return; }
    char m[256];
    wsprintfA(m, "{\"ev\":\"touch.diag\",\"ctx\":1,\"present_18\":%d,\"mode_4\":%d,\"conn_3c\":%d,"
                 "\"hs_8\":%d,\"p28\":%d,\"consume_210\":%d,\"rawX_216\":%d,\"rawY_218\":%d,"
                 "\"x234\":%d,\"y238\":%d,\"dirty_30c\":%d}",
             c[0x18], *(int *)(c + 4), *(int *)(c + 0x3c), *(int *)(c + 8), *(int *)(c + 0x28),
             c[0x210], *(unsigned short *)(c + 0x216), *(unsigned short *)(c + 0x218),
             (int)*(float *)(c + 0x234), (int)*(float *)(c + 0x238), c[0x30c]);
    if (st->host && st->host->log) st->host->log("info", m);

    {
        char cb[256];
        unsigned char dbg = *(unsigned char *)((uintptr_t)GetModuleHandleW(NULL) + (0x1696F2Cu - 0x400000u));
        wsprintfA(cb, "{\"ev\":\"touch.calib\",\"en198\":%d,\"en199\":%d,"
                      "\"Xmin_19c\":%d,\"Xmax_1a4\":%d,\"Ymin_1a0\":%d,\"Ymax_1a8\":%d,"
                      "\"amDebug\":%d,\"inv21c\":%d,\"inv220\":%d,\"normX228x1k\":%d,\"normY22cx1k\":%d}",
                  c[0x198], c[0x199], *(int *)(c + 0x19c), *(int *)(c + 0x1a4),
                  *(int *)(c + 0x1a0), *(int *)(c + 0x1a8),
                  (dbg & 1), (int)*(float *)(c + 0x21c), (int)*(float *)(c + 0x220),
                  (int)(*(float *)(c + 0x228) * 1000.0f), (int)(*(float *)(c + 0x22c) * 1000.0f));
        if (st->host && st->host->log) st->host->log("info", cb);
    }

    {
        uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
        unsigned char *arr = (unsigned char *)(b + (0x16b8678u - 0x400000u));
        char s[300]; int o = wsprintfA(s, "{\"ev\":\"serial.diag\",\"ready\":%d,\"thr\":\"%08x\",\"ports\":[",
            *(int *)(b + (0x16b87c8u - 0x400000u)), *(unsigned *)(b + (0x16b87ccu - 0x400000u)));
        for (int i = 0; i < 3; i++) {
            unsigned char *sp = arr + (size_t)i * 0x70;
            o += wsprintfA(s + o, "%s{\"h\":\"%08x\",\"tx\":%d,\"fl\":\"%x\"}", i ? "," : "",
                           *(unsigned *)(sp + 4), *(int *)(sp + 0x14), *(unsigned *)(sp + 0x6c));
        }
        wsprintfA(s + o, "]}");
        if (st->host && st->host->log) st->host->log("info", s);
    }
}

static const char *scene_va_name(unsigned va) {
    switch (va) {
        case 0x5e6200: return "EntryModeCheckCard";
        case 0x5eaae0: return "EntryModeGamePoint";
        case 0x5e90b0: return "EntryModeNameEntry";
        case 0x5e8710: return "EntryModeSelectChara";
        case 0x5eb000: return "EntryModeDotNetRegist";
        case 0x5ec340: return "EntryModePassword";
        case 0x5eb6b0: return "EntryModeReIssue";
        case 0x62fb50: return "EntryModeBase";
        default:       return 0;
    }
}

static void scene_tag_fourcc(char out[5], unsigned tag) {
    for (int i = 0; i < 4; i++) {
        unsigned c = (tag >> (i * 8)) & 0xffu;
        out[i] = (c >= 0x20 && c < 0x7f && c != '"' && c != '\\') ? (char)c : '.';
    }
    out[4] = 0;
}

static int scene_node_json(char *dst, int cap, unsigned va, unsigned tag) {
    char fc[5]; scene_tag_fourcc(fc, tag);
    const char *cls = scene_va_name(va);
    (void)cap;
    if (cls) return wsprintfA(dst, "{\"va\":\"%x\",\"tag\":\"%x\",\"tag4\":\"%s\",\"cls\":\"%s\"}",
                              va, tag, fc, cls);
    return wsprintfA(dst, "{\"va\":\"%x\",\"tag\":\"%x\",\"tag4\":\"%s\",\"cls\":null}", va, tag, fc);
}

#define SCENE_CAP 64
static void scene_diag(LogicState *st) {
    static unsigned n; static unsigned last_sig = 0xFFFFFFFFu; static int last_flags = -1;
    static unsigned prev_va[SCENE_CAP], prev_tag[SCENE_CAP]; static int prev_n = 0, seeded = 0;
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    unsigned char *node = *(unsigned char **)(b + (0x16DB564u - 0x400000u));
    unsigned sig = 0; int active_attract = 0, active_credit = 0, active_cardauth = 0, nact = 0;
    int seen_credit = 0, seen_cardauth = 0;
    unsigned cur_va[SCENE_CAP], cur_tag[SCENE_CAP]; int cur_n = 0, trunc = 0;
    for (int guard = 0; node && guard < 128; guard++) {
        unsigned flags = *(unsigned *)(node + 8);
        unsigned tag = *(unsigned *)(node + 4);
        uintptr_t upd = *(uintptr_t *)(node + 0x24);
        unsigned va = upd ? (unsigned)(upd - b + 0x400000u) : 0;
        if (va == 0x5eaae0) { seen_credit = 1; if (flags & 1) active_credit = 1; }
        if (va == 0x5e6200) { seen_cardauth = 1; if (flags & 1) active_cardauth = 1; }
        if (va == 0x7274d0 && (flags & 1)) active_attract = 1;
        if (flags & 1) {
            nact++; sig = sig * 31u + va;
            if (cur_n < SCENE_CAP) { cur_va[cur_n] = va; cur_tag[cur_n] = tag; cur_n++; }
            else trunc = 1;
        }
        node = *(unsigned char **)(node + 0x3c);
    }
    if (!seeded) {
        for (int i = 0; i < cur_n; i++) { prev_va[i] = cur_va[i]; prev_tag[i] = cur_tag[i]; }
        prev_n = cur_n; seeded = 1;
    } else {
        char used[SCENE_CAP]; for (int i = 0; i < prev_n; i++) used[i] = 0;
        char dl[760]; int dn = 0, ao = 0, ro = 0;
        char rm[380];
        for (int i = 0; i < cur_n; i++) {
            int hit = -1;
            for (int j = 0; j < prev_n; j++)
                if (!used[j] && prev_va[j] == cur_va[i] && prev_tag[j] == cur_tag[i]) { hit = j; break; }
            if (hit >= 0) used[hit] = 1;
            else if (ao < (int)sizeof dl - 80) {
                ao += wsprintfA(dl + ao, "%s", dn++ ? "," : "");
                ao += scene_node_json(dl + ao, (int)sizeof dl - ao, cur_va[i], cur_tag[i]);
            }
        }
        int rn = 0;
        for (int j = 0; j < prev_n; j++) {
            if (used[j]) continue;
            if (ro < (int)sizeof rm - 80) {
                ro += wsprintfA(rm + ro, "%s", rn++ ? "," : "");
                ro += scene_node_json(rm + ro, (int)sizeof rm - ro, prev_va[j], prev_tag[j]);
            }
        }
        if (dn || rn) {
            char m[1200];
            wsprintfA(m, "{\"ev\":\"scene.delta\",\"f\":%u,\"nact\":%d,\"trunc\":%d,"
                         "\"add\":[%s],\"del\":[%s]}", st->tick, nact, trunc,
                      dn ? dl : "", rn ? rm : "");
            if (st->host && st->host->log) st->host->log("info", m);
        }
        for (int i = 0; i < cur_n; i++) { prev_va[i] = cur_va[i]; prev_tag[i] = cur_tag[i]; }
        prev_n = cur_n;
    }
    int flagbits = active_attract | (active_credit << 1) | (active_cardauth << 2)
                 | (seen_credit << 3) | (seen_cardauth << 4);
    if (sig != last_sig || flagbits != last_flags || (n++ % 120) == 0) {
        char m[256];
        wsprintfA(m, "{\"ev\":\"scene.diag\",\"nact\":%d,\"sig\":\"%x\",\"attract\":%d,"
                     "\"credit_active\":%d,\"cardauth_active\":%d,\"credit_seen\":%d,\"cardauth_seen\":%d}",
                  nact, sig, active_attract, active_credit, active_cardauth, seen_credit, seen_cardauth);
        if (st->host && st->host->log) st->host->log("info", m);
        if (sig != last_sig) {
            char d[600]; int o = wsprintfA(d, "{\"ev\":\"scene.list\",\"va\":[");
            node = *(unsigned char **)(b + (0x16DB564u - 0x400000u));
            int first = 1;
            for (int guard = 0; node && guard < 128 && o < 540; guard++) {
                unsigned flags = *(unsigned *)(node + 8);
                uintptr_t upd = *(uintptr_t *)(node + 0x24);
                if (flags & 1) {
                    unsigned va = upd ? (unsigned)(upd - b + 0x400000u) : 0;
                    o += wsprintfA(d + o, "%s\"%x\"", first ? "" : ",", va);
                    first = 0;
                }
                node = *(unsigned char **)(node + 0x3c);
            }
            wsprintfA(d + o, "]}");
            if (st->host && st->host->log) st->host->log("info", d);
        }
        last_sig = sig; last_flags = flagbits;
    }
}

static void touch_inject(LogicState *st) {
    { uint8_t *f = (uint8_t *)((uintptr_t)GetModuleHandleW(NULL) + (0x1696F2Cu - 0x400000u)); *f &= (uint8_t)~1u; }
    unsigned char *c = touch_data_ctx();
    if (!c) return;
    HWND w = FindWindowW(NULL, L"WGL");
    if (!w) {
        if (!st->touch_winwarn) { st->touch_winwarn = 1;
            if (st->host && st->host->log) st->host->log("warn", "{\"ev\":\"touch.inject\",\"err\":\"WGL not found\"}"); }
        return;
    }
    RECT rc; POINT p;
    if (!GetClientRect(w, &rc) || rc.right <= 0 || rc.bottom <= 0) return;
    GetCursorPos(&p); ScreenToClient(w, &p);
    long cw = rc.right, ch = rc.bottom;
    if (p.x < 0) p.x = 0; if (p.x >= cw) p.x = cw - 1;
    if (p.y < 0) p.y = 0; if (p.y >= ch) p.y = ch - 1;
    float nx = (float)p.x * (1024.0f / (float)cw);
    float ny = (float)p.y * (600.0f  / (float)ch);
    int press = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) ? 1 : 0;
    int down  = (press && !st->touch_last_press) ? 1 : 0;

    c[0x2b8] = (unsigned char)press;
    c[0x2b9] = (unsigned char)down;
    c[0x2ba] = (unsigned char)press;
    *(float *)(c + 0x2dc) = nx;
    *(float *)(c + 0x2e0) = ny;
    c[0x30c] = 1;

    {
        unsigned rawX = (unsigned)((long long)p.x * 4095 / (cw > 1 ? cw - 1 : 1));
        unsigned rawY = (unsigned)((long long)p.y * 4095 / (ch > 1 ? ch - 1 : 1));
        unsigned rawZ = press ? 0xFF : 0;
        c[0x166] = (unsigned char)(press ? 1 : 0);
        *(uint16_t *)(c + 0x160) = (uint16_t)rawX;
        *(uint16_t *)(c + 0x162) = (uint16_t)rawY;
        *(uint16_t *)(c + 0x164) = (uint16_t)rawZ;
        *(uint16_t *)(c + 0x216) = (uint16_t)rawX;
        *(uint16_t *)(c + 0x218) = (uint16_t)rawY;
        *(uint16_t *)(c + 0x21a) = (uint16_t)rawZ;
        *(float *)(c + 0x21c) = (float)(int)(0xfff - rawX);
        *(float *)(c + 0x220) = (float)(int)(0xfff - rawY);
        *(float *)(c + 0x228) = (float)rawX * 0.00024420025874860585f;
        *(float *)(c + 0x224) = (float)rawZ;
        *(float *)(c + 0x22c) = (float)rawY * 0.00024420025874860585f;
        *(float *)(c + 0x230) = (float)rawZ * 0.003921568859368563f;
    }
    st->touch_last_press = (uint8_t)press;
}

static void dinput_diag(LogicState *st) {
    static int last_count = -1, last_state = -1; static unsigned n;
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    int   count = *(int   *)(b + (0x16B88DCu - 0x400000u));
    void *ctx   = *(void **)(b + (0x16F3A4Cu - 0x400000u));
    void *dev0  = *(void **)(b + (0x16F3A50u - 0x400000u));
    void *dev1  = *(void **)(b + (0x16F3A54u - 0x400000u));
    void *dev2  = *(void **)(b + (0x16F3A58u - 0x400000u));
    void *hwnd  = *(void **)(b + (0x1696E0Cu - 0x400000u));
    HWND  wgl   = FindWindowW(NULL, L"WGL");
    int   state = (ctx?1:0) | (dev0?2:0) | (dev1?4:0) | (dev2?8:0) | (hwnd?16:0);
    if (count != last_count || state != last_state || (n++ % 240) == 0) {
        char m[280];
        wsprintfA(m, "{\"ev\":\"dinput.diag\",\"count\":%d,\"ctx\":\"%p\",\"dev0\":\"%p\",\"dev1\":\"%p\","
                     "\"mouse\":\"%p\",\"hwnd\":\"%p\",\"wgl\":\"%p\"}",
                  count, ctx, dev0, dev1, dev2, hwnd, wgl);
        if (st->host && st->host->log) st->host->log("info", m);
        last_count = count; last_state = state;
    }
}

typedef HANDLE (WINAPI *CreateFileW_fn)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL   (WINAPI *ReadFile_fn)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *WriteFile_fn)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *CloseHandle_fn)(HANDLE);

static void card_ctl_path(wchar_t *out, int cap) {
    GetModuleFileNameW(NULL, out, (DWORD)cap);
    wchar_t *p = wcsrchr(out, L'\\');
    if (p) p[1] = 0; else out[0] = 0;
    wcsncat(out, L"nrsedge.card.json", (size_t)cap - wcslen(out) - 1);
}

static int card_read_raw(LogicState *st, const wchar_t *path, void *buf, int cap) {
    if (!st->host) return -1;
    CreateFileW_fn  cf = (CreateFileW_fn)st->host->orig(ORIG_CREATE_FILE_W);
    ReadFile_fn     rf = (ReadFile_fn)st->host->orig(ORIG_READ_FILE);
    CloseHandle_fn  ch = (CloseHandle_fn)st->host->orig(ORIG_CLOSE_HANDLE);
    if (!cf || !rf || !ch) return -1;
    HANDLE f = cf(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (f == INVALID_HANDLE_VALUE) return -1;
    DWORD got = 0; BOOL ok = rf(f, buf, (DWORD)cap, &got, 0);
    ch(f);
    return ok ? (int)got : -1;
}

static int card_save_image(LogicState *st) {
    if (!st->host || !st->card_img_path[0]) return 0;
    CreateFileW_fn  cf = (CreateFileW_fn)st->host->orig(ORIG_CREATE_FILE_W);
    WriteFile_fn    wf = (WriteFile_fn)st->host->orig(ORIG_WRITE_FILE);
    CloseHandle_fn  ch = (CloseHandle_fn)st->host->orig(ORIG_CLOSE_HANDLE);
    if (!cf || !wf || !ch) return 0;
    HANDLE f = cf(st->card_img_path, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (f == INVALID_HANDLE_VALUE) return 0;
    DWORD put = 0; BOOL ok = wf(f, st->card.image, CARD_IMAGE_BYTES, &put, 0);
    ch(f);
    if (ok) { st->card.dirty = 0;
        if (st->host->log) st->host->log("info", "{\"ev\":\"card.save\",\"bytes\":4104}");
    }
    return ok ? 1 : 0;
}

static int cj_int(const char *j, const char *key, int def) {
    char needle[40]; wsprintfA(needle, "\"%s\"", key);
    const char *p = strstr(j, needle); if (!p) return def;
    p += strlen(needle);
    while (*p && (*p == ':' || *p == ' ' || *p == '\t')) p++;
    int neg = 0; if (*p == '-') { neg = 1; p++; }
    int v = 0, any = 0;
    while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; any = 1; }
    return any ? (neg ? -v : v) : def;
}
static int cj_str(const char *j, const char *key, char *out, int cap) {
    char needle[40]; wsprintfA(needle, "\"%s\"", key);
    const char *p = strstr(j, needle); out[0] = 0; if (!p) return 0;
    p += strlen(needle);
    while (*p && (*p == ':' || *p == ' ' || *p == '\t')) p++;
    if (*p != '"') return 0; p++;
    int i = 0;
    while (*p && *p != '"' && i < cap - 1) {
        if (*p == '\\' && p[1]) p++;
        out[i++] = *p++;
    }
    out[i] = 0; return i;
}

static void card_control_poll(LogicState *st) {
    wchar_t path[MAX_PATH]; card_ctl_path(path, MAX_PATH);
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fa)) return;
    if (st->card_ctl_seen
        && fa.ftLastWriteTime.dwLowDateTime  == st->card_ctl_mtime.dwLowDateTime
        && fa.ftLastWriteTime.dwHighDateTime == st->card_ctl_mtime.dwHighDateTime)
        return;
    char buf[1024];
    int n = card_read_raw(st, path, buf, sizeof buf - 1);
    if (n <= 0) return;
    buf[n] = 0;
    st->card_ctl_mtime = fa.ftLastWriteTime;
    st->card_ctl_seen = 1;

    int present = cj_int(buf, "present", 0);
    int type    = cj_int(buf, "type", st->card.card_type);
    unsigned gen = (unsigned)cj_int(buf, "gen", 0);
    char img[512]; cj_str(buf, "image", img, sizeof img);
    st->card_ctl_gen = gen;

    if (present) {
        if (img[0]) {
            wchar_t wimg[MAX_PATH];
            MultiByteToWideChar(CP_UTF8, 0, img, -1, wimg, MAX_PATH);
            wcsncpy(st->card_img_path, wimg, MAX_PATH - 1); st->card_img_path[MAX_PATH - 1] = 0;
            memset(st->card.image, 0, CARD_IMAGE_BYTES);
            card_read_raw(st, wimg, st->card.image, CARD_IMAGE_BYTES);
            const uint8_t *h = st->card.image;
            st->card.uid = ((uint32_t)h[CARD_HDR_UID_OFF] << 24) | ((uint32_t)h[CARD_HDR_UID_OFF + 1] << 16)
                         | ((uint32_t)h[CARD_HDR_UID_OFF + 2] << 8) | h[CARD_HDR_UID_OFF + 3];
        }
        if (type) st->card.card_type = (uint8_t)type;
        st->card.present = 1;
        st->card.read_cursor = 0; st->card.read_len = 0;
        st->card.dirty = 0;
        if (st->host && st->host->log) {
            char m[400], pu[300]; WideCharToMultiByte(CP_UTF8, 0, st->card_img_path, -1, pu, sizeof pu, 0, 0);
            wsprintfA(m, "{\"ev\":\"card.insert\",\"present\":1,\"type\":\"%02x\",\"uid\":\"%08x\",\"gen\":%u,\"image\":\"%s\"}",
                      st->card.card_type, st->card.uid, gen, pu);
            st->host->log("info", m);
        }
    } else {
        if (st->card.present && st->card.dirty) card_save_image(st);
        st->card.present = 0;
        if (st->host && st->host->log) {
            char m[80]; wsprintfA(m, "{\"ev\":\"card.eject\",\"present\":0,\"gen\":%u}", gen);
            st->host->log("info", m);
        }
    }
}

static void touch_control_poll(LogicState *st) {
    wchar_t path[MAX_PATH]; GetModuleFileNameW(NULL, path, MAX_PATH);
    wchar_t *p = wcsrchr(path, L'\\'); if (p) p[1] = 0; else path[0] = 0;
    wcsncat(path, L"nrsedge.touch.json", MAX_PATH - wcslen(path) - 1);
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fa)) { st->touch_force = 0; return; }
    if (st->touch_ctl_seen
        && fa.ftLastWriteTime.dwLowDateTime  == st->touch_ctl_mtime.dwLowDateTime
        && fa.ftLastWriteTime.dwHighDateTime == st->touch_ctl_mtime.dwHighDateTime)
        return;
    char buf[256];
    int n = card_read_raw(st, path, buf, sizeof buf - 1);
    if (n <= 0) return;
    buf[n] = 0;
    st->touch_ctl_mtime = fa.ftLastWriteTime;
    st->touch_ctl_seen = 1;
    int press = cj_int(buf, "press", 0);
    int xm = cj_int(buf, "xm", 500), ym = cj_int(buf, "ym", 500);
    if (xm < 0) xm = 0; if (xm > 1000) xm = 1000;
    if (ym < 0) ym = 0; if (ym > 1000) ym = 1000;
    st->touch_force = 1;
    st->touch_force_press = (uint8_t)(press ? 1 : 0);
    st->touch_force_x = (uint16_t)(xm * TOUCH_MAX / 1000);
    st->touch_force_y = (uint16_t)(ym * TOUCH_MAX / 1000);
    if (st->host && st->host->log) {
        char m[160];
        wsprintfA(m, "{\"ev\":\"touch.force\",\"press\":%u,\"xm\":%d,\"ym\":%d,\"x\":%u,\"y\":%u}",
                  st->touch_force_press, xm, ym, st->touch_force_x, st->touch_force_y);
        st->host->log("info", m);
    }
}

static int *cardrw_object(uintptr_t b);

static void card_sm_diag(LogicState *st) {
    static int last = -0x7fffffff; static unsigned n; static int wl_logged = 0;
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    if (!wl_logged && st->host && st->host->log) {
        wl_logged = 1;
        unsigned cnt  = *(uint8_t  *)(b + (0x16A55ADu - 0x400000u));
        unsigned byp  = *(uint8_t  *)(b + (0x16A55BAu - 0x400000u));
        unsigned nblk = *(uint8_t  *)(b + (0x16A55ACu - 0x400000u));
        unsigned mlen = *(uint16_t *)(b + (0x16A55B8u - 0x400000u));
        uint32_t *wl  = (uint32_t *)(b + (0x16A55B0u - 0x400000u));
        char m[300]; int o = wsprintfA(m, "{\"ev\":\"card.whitelist\",\"count\":%u,\"bypass\":%u,\"nblk\":%u,\"maxlen\":%u,\"uids\":[",
                                       cnt, byp, nblk, mlen);
        for (unsigned i = 0; i < cnt && i < 6; i++) o += wsprintfA(m + o, "%s\"%08x\"", i ? "," : "", wl[i]);
        wsprintfA(m + o, "]}");
        st->host->log("info", m);
    }
    unsigned devf = *(uint8_t  *)(b + (0x16AE538u - 0x400000u));
    int sub  = *(int *)(b + (0x16AE53Cu - 0x400000u));
    int cls  = *(int *)(b + (0x16AE5C8u - 0x400000u));
    int req  = *(int *)(b + (0x16AE5CCu - 0x400000u));
    int cnt  = *(int *)(b + (0x16AE5E0u - 0x400000u));
    int res  = *(int *)(b + (0x16AE540u - 0x400000u));
    unsigned dsf=0, pres=0; int s2=-1, have=0;
    int *obj = cardrw_object(b);
    if (obj) { uintptr_t ds=(uintptr_t)obj+4; dsf=*(uint32_t*)(ds); s2=*(int*)(ds+8); pres=*(uint32_t*)(ds+0x5628); have=1; }
    int sig = (int)(devf + sub*7 + cls*101 + (req+2)*1009 + s2*31 + (int)(dsf&0xfff)*131 + (pres?1:0));
    if (sig != last || (n++ % 180) == 0) {
        char m[360];
        wsprintfA(m, "{\"ev\":\"card.sm\",\"devf\":%u,\"sub\":%d,\"cls\":%d,\"req\":%d,\"cnt\":%d,\"res\":%d,"
                     "\"have\":%d,\"dsflags\":\"%x\",\"state2\":%d,\"presence\":%u,\"present\":%u}",
                  devf, sub, cls, req, cnt, res, have, dsf, s2, pres, st->card.present);
        if (st->host && st->host->log) st->host->log("info", m);
        last = sig;
    }
}

static int *cardrw_object(uintptr_t b) {
    int *node = *(int **)(b + (0x16D868Cu - 0x400000u));
    if (!node) {
        node = *(int **)(b + (0x16DB564u - 0x400000u));
        while (node && (node[0] != 0x21 || node[1] != 0x21)) node = (int *)(uintptr_t)node[0xf];
    }
    if (!node) return 0;
    return (int *)(uintptr_t)node[4];
}

static void card_patch_diag(LogicState *st) {
    static unsigned last_sig = 0xffffffff;
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    unsigned pa = *(uint8_t *)(b + (0x671AACu - 0x400000u));
    unsigned pf = *(uint8_t *)(b + (0x6717D5u - 0x400000u));
    unsigned cnt = *(uint8_t *)(b + (0x16A55ADu - 0x400000u));
    unsigned byp = *(uint8_t *)(b + (0x16A55BAu - 0x400000u));
    uint32_t wl0 = *(uint32_t *)(b + (0x16A55B0u - 0x400000u));
    uint32_t ruid = *(uint32_t *)(b + (0x169E314u - 0x400000u));
    unsigned sig = pa * 131 + pf * 31 + cnt * 7 + byp + (wl0 & 0xffff) + (ruid & 0xffff);
    if (sig != last_sig && st->host && st->host->log) {
        last_sig = sig;
        char m[220];
        wsprintfA(m, "{\"ev\":\"card.patchdiag\",\"halt_671aac\":\"%02x\",\"first_6717d5\":\"%02x\","
                     "\"wl_count\":%u,\"bypass\":%u,\"wl_uid0\":\"%08x\",\"read_uid\":\"%08x\"}",
                  pa, pf, cnt, byp, wl0, ruid);
        st->host->log("info", m);
    }
}

static int *amlib_devmgr(uintptr_t b) {
    int *node = *(int **)(b + (0x16D8688u - 0x400000u));
    if (!node) {
        node = *(int **)(b + (0x16DB564u - 0x400000u));
        while (node && (node[0] != 0x20 || node[1] != 0x20)) node = (int *)(uintptr_t)node[0xf];
    }
    if (!node || !node[4]) return 0;
    return (int *)(uintptr_t)(*(int *)(uintptr_t)node[4]);
}

static void amlib_devstat_diag(LogicState *st) {
    static unsigned last = 0xffffffff;
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    int *mgr = amlib_devmgr(b);
    int s0=-1,s1=-1,s2=-1,s3=-1,s4=-1,s5=-1; unsigned m1ec=0;
    int xstate=-1, xstat=-1, xctype=-1;
    if (mgr) {
        s0=mgr[0x1d4/4]; s1=mgr[0x1d8/4]; s2=mgr[0x1dc/4]; s3=mgr[0x1e0/4]; s4=mgr[0x1e4/4]; s5=mgr[0x1e8/4];
        m1ec = *(unsigned *)((uintptr_t)mgr + 0x1ec);
        xstate = *(int *)((uintptr_t)mgr + 0x1f8);
        xstat  = *(int *)((uintptr_t)mgr + 0x204);
        xctype = *(int *)((uintptr_t)mgr + 0x210);
    }
    unsigned g_connres = *(unsigned *)(b + (0x020f493cu - 0x400000u));
    unsigned g_ready   = *(unsigned char *)(b + (0x020f4934u - 0x400000u));
    unsigned g_armed   = *(unsigned char *)(b + (0x020f4940u - 0x400000u));
    unsigned g_reqno   = *(unsigned short *)(b + (0x020f496cu - 0x400000u));
    unsigned g_busy    = *(unsigned char *)(b + (0x020f4939u - 0x400000u));
    char uri[80]; uri[0]=0;
    unsigned usz=0, ucap=0;
    {
        uintptr_t sp = b + (0x0126591cu - 0x400000u);
        usz  = *(unsigned *)(sp + 0x10);
        ucap = *(unsigned *)(sp + 0x14);
        const char *us = (ucap > 15) ? *(const char **)sp : (const char *)sp;
        if (us && usz < 0x1000) { unsigned n = usz < 79 ? usz : 79; for (unsigned i=0;i<n;i++){ char c=us[i]; uri[i]=(c>=32&&c<127)?c:'.'; } uri[n]=0; }
    }
    unsigned b50a = *(uint8_t *)(b + (0x210B50Au - 0x400000u));
    unsigned b50b = *(uint8_t *)(b + (0x210B50Bu - 0x400000u));
    unsigned lan  = *(uint8_t *)(b + (0x210B50Cu - 0x400000u));
    int ns[3], nip[3];
    for (int i = 0; i < 3; i++) {
        int *d = *(int **)(b + ((0x210B5BCu + i*8) - 0x400000u));
        ns[i]  = d ? d[0] : -1;
        nip[i] = d ? d[1] : 0;
    }
    unsigned sig = (unsigned)(s0+s1*3+s2*7+s3*13+s4*17+s5*19) + m1ec + b50a*131 + b50b*137 + lan*139
                 + ns[0]*211 + ns[1]*223 + ns[2]*227 + (unsigned)(nip[0]^nip[1]^nip[2])
                 + (unsigned)(xstate*29 + xstat*31 + xctype*37) + g_connres*41 + g_ready*43 + g_armed*47 + g_busy*53;
    if (sig != last && st->host && st->host->log) {
        last = sig;
        char m[520];
        wsprintfA(m, "{\"ev\":\"amlib.devstat\",\"s\":[%d,%d,%d,%d,%d,%d],\"m1ec\":\"%x\","
                     "\"exec\":{\"state\":%d,\"stat\":%d,\"ctype\":%d,\"connres\":%d,\"ready\":%u,\"armed\":%u,\"busy\":%u,\"reqno\":%u,\"urisz\":%u,\"uricap\":%u,\"uri\":\"%s\"},"
                     "\"b50a\":%u,\"b50b\":%u,\"lan\":%u,"
                     "\"nic\":[{\"st\":%d,\"ip\":\"%08x\"},{\"st\":%d,\"ip\":\"%08x\"},{\"st\":%d,\"ip\":\"%08x\"}]}",
                  s0,s1,s2,s3,s4,s5, m1ec,
                  xstate,xstat,xctype,(int)g_connres,g_ready,g_armed,g_busy,g_reqno,usz,ucap,uri,
                  b50a,b50b,lan,
                  ns[0],(unsigned)nip[0], ns[1],(unsigned)nip[1], ns[2],(unsigned)nip[2]);
        st->host->log("info", m);
    }
}

static void card_force_present(LogicState *st) {
    if (!st->card.present) return;
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    int *obj = cardrw_object(b);
    if (!obj) return;
    uintptr_t ds = (uintptr_t)obj + 4;
    if ((*(uint32_t *)ds & 0x10u) != 0) return;
    volatile int *presence = (int *)(ds + 0x5628);
    if (*presence == 0) {
        *presence = 1;
        if (!st->card_force_logged && st->host && st->host->log) {
            st->host->log("info", "{\"ev\":\"card.force_present\",\"set\":\"ds+0x5628=1\"}");
            st->card_force_logged = 1;
        }
    }
}

static void card_accept_gate(LogicState *st) {
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    volatile uint8_t *bypass = (uint8_t *)(b + (0x16A55BAu - 0x400000u));
    volatile uint8_t *wl_cnt = (uint8_t *)(b + (0x16A55ADu - 0x400000u));
    int changed = (*bypass != 1 || *wl_cnt != 0);
    *bypass = 1;
    *wl_cnt = 0;
    if (changed && !st->card_accept_logged && st->host && st->host->log) {
        st->host->log("info", "{\"ev\":\"card.accept_gate\",\"set\":\"bypass=1,wl_count=0\"}");
        st->card_accept_logged = 1;
    }
}

static void json_escape(char *dst, int cap, const char *s, int maxlen) {
    int j = 0;
    if (cap < 3) { if (cap > 0) dst[0] = 0; return; }
    dst[j++] = '"';
    for (int i = 0; s && s[i] && i < maxlen && j + 2 < cap; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') { dst[j++] = '\\'; dst[j++] = (char)c; }
        else if (c >= 0x20 && c < 0x7f) dst[j++] = (char)c;
        else dst[j++] = '.';
    }
    dst[j++] = '"'; dst[j] = 0;
}

static void nupl_diag(LogicState *st) {
    static int last_sig = -0x7fffffff, logged_bad = 0;
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    int *node = *(int **)(b + (0x16DB564u - 0x400000u));
    for (int g = 0; node && g < 128; g++) {
        if (node[1] == 0x4C50554E) {
            int *slot = (int *)(uintptr_t)node[4];
            unsigned char *obj = slot ? (unsigned char *)(uintptr_t)slot[0] : 0;
            if (!obj || (uintptr_t)obj < 0x10000) {
                if (!logged_bad && st->host && st->host->log) {
                    logged_bad = 1; st->host->log("warn", "{\"ev\":\"nupl.obj_bad\"}");
                }
                return;
            }
            uint32_t cap  = *(uint32_t *)(obj + 0x1c);
            uint32_t size = *(uint32_t *)(obj + 0x18);
            int state = *(int *)(obj + 0x200fc);
            int d8    = *(int *)(obj + 0xd8);
            int exp_id = *(int *)(obj + 0x20130);
            int req_id = *(int *)(obj + 0x20134);
            int sig = state * 131 + d8 * 17 + (int)size + exp_id * 7;
            if (sig != last_sig && st->host && st->host->log) {
                const char *cstr = (cap < 0x10) ? (const char *)(obj + 8) : *(const char **)(obj + 8);
                char m[300], ub[128];
                json_escape(ub, sizeof ub, cstr, 60);
                wsprintfA(m, "{\"ev\":\"nupl.state\",\"url\":%s,\"size\":%u,\"cap\":%u,\"d8\":%d,\"sm\":%d,\"exp_id\":%d,\"req_id\":%d}",
                          ub, size, cap, d8, state, exp_id, req_id);
                st->host->log("info", m);
                last_sig = sig;
            }
            if (state == 2) {
                static unsigned n2 = 0;
                if ((n2++ % 60) == 0 && st->host && st->host->log) {
                    int d4    = *(int *)(obj + 0xd4);
                    int dc    = *(int *)(obj + 0xdc);
                    int tflag = *(int *)(obj + 0x2012c);
                    int tdur  = *(int *)(obj + 0x20124);
                    int tstart= *(int *)(obj + 0x20120);
                    int tnow  = *(int *)(obj + 0x20128);
                    char m2[220];
                    wsprintfA(m2, "{\"ev\":\"nupl.s2\",\"d4\":%d,\"dc\":%d,\"tflag\":%d,\"tdur\":%d,"
                                  "\"tstart\":%d,\"tnow\":%d,\"elapsed\":%d}",
                              d4, dc, tflag, tdur, tstart, tnow, tnow - tstart);
                    st->host->log("info", m2);
                }
            }
            return;
        }
        node = (int *)(uintptr_t)node[0xf];
    }
}

static void alabex_diag(LogicState *st) {
    static int last = -0x7fffffff;
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    int status  = *(int32_t *)(b + (0x0249682Cu - 0x400000u));
    int started = *(uint8_t *)(b + (0x210AED0u - 0x400000u));
    int authok  = *(uint8_t *)(b + (0x210AED2u - 0x400000u));
    int complete= *(uint8_t *)(b + (0x210B508u - 0x400000u));
    int reval   = *(int32_t *)(b + (0x210AF48u - 0x400000u));
    int lan     = *(uint8_t *)(b + (0x210B509u - 0x400000u));
    int phase   = *(int32_t *)(b + (0x210AEE0u - 0x400000u));
    int lanflag = *(uint8_t *)(b + (0x210B50Cu - 0x400000u));
    int sig = status * 7 + started * 3 + authok * 5 + complete * 11 + phase * 131 + (reval ? 1 : 0);
    if (sig != last && st->host && st->host->log) {
        char m[260];
        wsprintfA(m, "{\"ev\":\"alabex.diag\",\"status\":%d,\"started\":%d,\"authok\":%d,\"complete\":%d,"
                     "\"phase\":%d,\"lanflag\":%d,\"reval_gate\":%d,\"lan\":%d}",
                  status, started, authok, complete, phase, lanflag, reval, lan);
        st->host->log("info", m);
        last = sig;
    }
}

static void on_jvs_tick(LogicState *st) {
    const NrsConfig *cfg = st->host ? st->host->cfg : 0;
    NrsInput in; nrs_poll_input(&in, cfg ? cfg->bind : 0);


    dinput_diag(st);
    eeprom_force_ready(st);
    dipsw_force_ready(st);
    network_nic_bridge(st);
    mmgp_diag(st);
    touch_diag(st);
    scene_diag(st);
    touch_control_poll(st);
    card_control_poll(st);
    card_force_present(st);
    card_accept_gate(st);
    card_sm_diag(st);
    card_patch_diag(st);
    amlib_devstat_diag(st);
    nupl_diag(st);
    alabex_diag(st);

    {
        uint32_t *sw = (uint32_t *)((uintptr_t)GetModuleHandleW(NULL) + (0x160194Cu - 0x400000u));
        *sw = (*sw & ~3u) | (in.test ? 1u : 0u) | (in.service ? 2u : 0u);
    }

    if (cfg && cfg->freeplay) {
        uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
        uint32_t *initf = (uint32_t *)(b + (0x1288550u - 0x400000u));
        uint8_t  *fp    = (uint8_t  *)(b + (0x128855Au - 0x400000u));
        if (*initf != 0 && *fp != 1) *fp = 1;
    }

    st->tick++;
    unsigned keys = in.test | (in.service<<1) | (in.coin<<2) | (in.start<<3) | (in.up<<4) | (in.down<<5)
                  | (in.left<<6) | (in.right<<7) | (in.jump<<8) | (in.dash<<9) | (in.action<<10);
    if (st->tick <= 2 || keys != st->last_keys) {
        uintptr_t bb = (uintptr_t)GetModuleHandleW(NULL);
        unsigned sw194c = *(uint32_t *)(bb + (0x160194Cu - 0x400000u));
        unsigned cook   = *(uint32_t *)(bb + (0x2282A64u - 0x400000u)) & 0xFFFF;
        unsigned node643 = *(uint8_t *)(bb + (0x16B7860u - 0x400000u) + 0x643);
        char m[300];
        wsprintfA(m, "{\"ev\":\"input.state\",\"test\":%d,\"service\":%d,\"coin\":%d,\"start\":%d,"
                     "\"up\":%d,\"down\":%d,\"left\":%d,\"right\":%d,\"jump\":%d,\"dash\":%d,\"action\":%d,"
                     "\"ax\":%u,\"ay\":%u,\"node643\":%u,\"sw194c\":%u,\"cook\":%u}",
                  in.test, in.service, in.coin, in.start, in.up, in.down, in.left, in.right,
                  in.jump, in.dash, in.action, (unsigned)in.analog_x, (unsigned)in.analog_y,
                  node643, sw194c, cook);
        if (st->host && st->host->log) st->host->log("info", m);
        st->last_keys = keys;
    }
}

static void on_sys_override(LogicState *st) {
    const NrsConfig *cfg = st->host ? st->host->cfg : 0;
    NrsInput in; nrs_poll_input(&in, cfg ? cfg->bind : 0);
    uint32_t *p = (uint32_t *)((uintptr_t)GetModuleHandleW(NULL) + (0x160194Cu - 0x400000u));
    *p = (*p & ~3u) | (in.test ? 1u : 0u) | (in.service ? 2u : 0u);
    st->sys_tick++;

    if (cfg && cfg->test_mode && !st->test_entered && st->sys_tick > 20) {
        *(uint32_t *)((uintptr_t)GetModuleHandleW(NULL) + (0x16B8B54u - 0x400000u)) = 13;
        st->test_entered = 1;
        if (st->host && st->host->log) st->host->log("info", "{\"ev\":\"testmenu.enter\",\"scene\":13}");
    }

    if (st->sys_tick <= 3) {
        char m[120];
        wsprintfA(m, "{\"ev\":\"sys.ovr\",\"n\":%u,\"T\":%d,\"S\":%d,\"194c\":%u}", st->sys_tick, in.test, in.service, *p);
        if (st->host && st->host->log) st->host->log("info", m);
    }

}

static void on_keychip_hold(LogicState *st) {
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    uint32_t  c = *(uint32_t *)(b + (0xCCF000u - 0x400000u));
    uint8_t  *a2 = (uint8_t *)(b + (0x16014A2u - 0x400000u));
    if (c) {
        const uint32_t *ctx = (const uint32_t *)(uintptr_t)c;
        if (ctx[1] != 0 && ctx[2] != 0 && *a2 == 0) *a2 = 1;
    }
    (void)st;
}

static long long on_rtc_get(LogicState *st, void *time_out, unsigned *flag_out, long long orig_ret) {
    if (orig_ret != -1) return orig_ret;
    if (!time_out) return orig_ret;
    SYSTEMTIME lt;
    GetLocalTime(&lt);
    uint8_t *t = (uint8_t *)time_out;
    *(uint16_t *)(t + 0) = (uint16_t)lt.wYear;
    t[2] = (uint8_t)lt.wMonth;
    t[3] = (uint8_t)lt.wDay;
    t[4] = (uint8_t)lt.wHour;
    t[5] = (uint8_t)lt.wMinute;
    t[6] = (uint8_t)(lt.wSecond == 60 ? 59 : lt.wSecond);
    if (flag_out) *flag_out = 0;
    if (st && st->host && st->host->log) {
        char m[160];
        wsprintfA(m, "{\"ev\":\"rtc.get\",\"src\":\"localtime\",\"y\":%u,\"mo\":%u,\"d\":%u,\"h\":%u,\"mi\":%u,\"s\":%u}",
                  lt.wYear, lt.wMonth, lt.wDay, lt.wHour, lt.wMinute, lt.wSecond);
        st->host->log("info", m);
    }
    return 0;
}

static void on_eeprom_init(LogicState *st) {
    eeprom_force_ready(st);
}

static void on_dipsw_provision(LogicState *st) {
    dipsw_force_ready(st);
}

static const LogicApi g_api = {
    NRSEDGE_ABI_VERSION, l_bind,
    on_create_file, on_read_file, on_write_file, on_ioctl, on_close, on_comm_control,
    on_set_file_pointer,
    on_jvs_tick, on_sys_override, on_keychip_hold,
    on_rtc_get,
    on_eeprom_init,
    on_dipsw_provision,
};

const LogicApi *logic_get_api(void) { return &g_api; }
