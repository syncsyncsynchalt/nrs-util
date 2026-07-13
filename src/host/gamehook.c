/* game-function hooks: nrs.exe 内部関数を VA で hook。
 * reload-safe: detour は host 側に置き、現行 logic を g_api 経由で呼ぶ（logic.dll swap で無効化しない）。
 * hook 一覧は gamehooks_install() 末尾。 */
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

/* jvs_update_main PRE: 入力を node BSS へ書いてから本体へ。 */
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
/* dipsw read PRE+POST: PRE で dipsw ctx を provisioning（board_index を本体が読む前に H_MXSMBUS 化＝errCode 0xa→errNo 910 解消）、
 * POST で本体が DAT_0160194c bit0/1 を立て直すのを打ち消す。 */
static unsigned __cdecl d_dipsw(void) {
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_dipsw_provision) g_api->on_dipsw_provision(g_state);  /* PRE: 読取前に ctx provisioning */
    ReleaseSRWLockShared(&g_logic_lock);
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

/* amEepromInit(0x985160) 完全置換 detour（__thiscall, RET 4 → __fastcall で捕捉）。orig は呼ばず
 * （SetupDi 失敗経路を回避）、logic に EEPROM ctx を provisioning させ 0(成功)を返す。 */
static int __fastcall d_eeprom_init(unsigned ecx, unsigned edx, void *size_ptr) {
    (void)ecx; (void)edx; (void)size_ptr;
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_eeprom_init) g_api->on_eeprom_init(g_state);
    ReleaseSRWLockShared(&g_logic_lock);
    return 0;   /* amEepromInit 成功（amlib_eeprom_ok=1）*/
}

/* amDipswInit(0x9842A0) POST: orig の SetupDi 失敗直後に dipsw ctx を H_MXSMBUS へ provisioning。続く amDipswRead が
 * IOCTL(cmd5,vcode0)→0x20 で board_index=2 を読む。read hook の PRE では最初の read に間に合わないため init で前倒し。 */
static int __cdecl d_dipsw_init(void) {
    int r = o_dipsw_init();   /* 実 amDipswInit（standalone は失敗・handle=-1・initFlag=1）*/
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_dipsw_provision) g_api->on_dipsw_provision(g_state);
    ReleaseSRWLockShared(&g_logic_lock);
    return r;
}

/* amlib_storage_board_check(0x679CB0) PRE: board-table 判定の消費直前に board index(=2, table[2]=8) と
 * dipsw flag(0x20=0) を供給する。ctx provisioning は board_index を確定する最初の read に間に合わないため、
 * consumer 側で供給して dipsw read のタイミングに非依存で errCode 0xa(errNo 910)/0xb を断つ。 */
static void __cdecl d_board_check(void) {
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    *(unsigned char *)(b + (0x1601953u - IMAGE_BASE)) = 2;     /* board_index = 2（table[2]=8）*/
    *(unsigned int  *)(b + (0x160194Cu - IMAGE_BASE)) &= ~0x20u; /* DAT_0160194c bit0x20=0（0xb 回避）*/
    o_board_check();
}

/* keychip_appdata_delete_gate_probe(0x45A8F0) POST: この probe は extend-image ファイル存在+検証で image-present gate
 * DAT_01601b23=1 にする判定。standalone はファイルが無く gate=0 → state5 が "EXTEND IMAGE … NG"→install 試行。
 * gate=1 を force すると substate1 が skip 枝→"… OK"→state6（install 完全 skip）。下の install kicker POST は fallback。 */
static int __cdecl d_extimg_gate_probe(void) {
    int r = o_extimg_gate_probe();
    *(unsigned char *)((uintptr_t)GetModuleHandleW(NULL) + (0x1601B23u - IMAGE_BASE)) = 1; /* image-present gate=1 */
    return r;
}

/* extend-image install kicker (FUN_0072eaf0, boot SM state5 substate2) POST: orig は install を開始させるが実体が
 * ALL.Net 配信タスクで standalone では詰まる。install_ctx(devMgr+0x258)に state=0xc(完了)/error(+0x284)=0 を provisioning
 * すると、同 tick fall-through の substate3 が extend_image_install_status(0x72b3a0) を return 4・error 0 と読み state6 前進。
 * xref は boot SM 一箇所のみ。真の install SM 完走化は ALL.Net 層エミュが前提。 */
static unsigned __cdecl d_ext_install_kick(void) {
    unsigned r = o_ext_install_kick();   /* orig: devMgr+0x26d/0x26e=1（install 開始トリガ）*/
    unsigned (*devmgr_ptr)(void) = (unsigned (*)(void))
        ((uintptr_t)GetModuleHandleW(NULL) + (0x72B450u - IMAGE_BASE));   /* amlib_device_manager_ptr */
    uintptr_t dm = (uintptr_t)devmgr_ptr();
    if (dm) {
        *(unsigned *)(dm + 0x258) = 0xC;   /* install_ctx state = 0xc（完了→getter return 4）*/
        *(unsigned *)(dm + 0x284) = 0;     /* install_ctx error(param_2[0xb]) = 0（errCode latch 回避）*/
    }
    return r;
}

/* ---- main per-frame 実時間計時（チラつき=30fps 二重 present の 33ms 在処を局在化） ----
 * amApp_main_loop はフレーム制限なしのスピンなので FUN_00643de0(per-frame tick) の実時間 ≈ フレーム周期。
 * 120 frame 毎に集約 1 行。 */
static void (*o_frametick)(void);
static void (*o_present_drive)(void);   /* FUN_006c3930: frame_present_main + render kick + post */
static void (*o_scene_dispatch)(void);  /* scene_list_render_dispatch 0x89dac0: scene 走査+GL 発行 */
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

/* ALL.Net uri getter (FUN_006ff7e0) override: orig は auth flags(started && auth_ok)成立時に uri の c_str を返す
 * （唯一の caller FUN_00559270 が upload/matching タスク URL に代入）。detour は orig 非null(=flags 成立)なら loopback
 * backend URL を返し、card POST を allnet.c の HTTP サーバへ導く。null(未成立)なら null 維持で gating 温存。 */
static void *(*o_allnet_url)(void);
static const char g_allnet_url[] = "http://127.0.0.1/nrsedge";   /* 127.0.0.1:80 → connect hook が :40080 へ */
static int g_allnet_url_logged;
static void *__cdecl d_allnet_url(void) {
    void *r = o_allnet_url();                 /* orig: flags 成立時のみ非null（副作用なし）*/
    if (r == 0) return 0;                     /* flags 未成立→null 維持 */
    if (!g_allnet_url_logged) {               /* 初回: uri override が発火した証跡（obj+8 供給経路の確認）*/
        g_allnet_url_logged = 1;
        host_log("info", "{\"ev\":\"allnet.url.override\",\"uri\":\"http://127.0.0.1/nrsedge\"}");
    }
    return (void *)g_allnet_url;              /* uri を loopback backend へ override */
}

/* ALL.Net NUPL 応答パーサ (FUN_00712710, __thiscall→__fastcall) READ-ONLY 診断。DFI 復号済み body を受け取り
 * id/status 照合で NUPL obj +0xd8(status: 0 ok,1 inflight,-1 err) を確定する。orig 前後で決定入力を丸ごとログ。 */
static void (__fastcall *o_recv_parse)(void *self, void *edx, char *body, size_t len);
static void __fastcall d_recv_parse(void *self, void *edx, char *body, size_t len) {
    unsigned char *o = (unsigned char *)self;
    int  d4_pre = o ? *(int *)(o + 0xd4)     : 0;
    int  d8_pre = o ? *(int *)(o + 0xd8)     : 0;
    int  cmp    = o ? *(int *)(o + 0x20130)  : 0;   /* パーサが id 一致に使う照合先 */
    int  f20120 = o ? *(int *)(o + 0x20120)  : 0;   /* id-callback キャッシュ */
    int  f20128 = o ? *(int *)(o + 0x20128)  : 0;
    int  f20134 = o ? *(int *)(o + 0x20134)  : 0;   /* 送信カウンタ(=req_id) */
    /* body（DFI 復号済み平文）先頭を JSON エスケープして記録＝我々の応答が正しく届いたかの確証 */
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

/* NetDataCardinfoRequest 送信ビルダ (FUN_007203e0, __fastcall(int* ctx)) の READ-ONLY 診断。
 * これが呼ばれる = card-auth scene(0x5e6200) が case2 に到達し UID を cardinfo として送信しようとしている証跡。
 * 呼ばれなければ scene が card-auth 送信点まで進んでいない（card-select→card-auth 遷移が起きていない）。 */
static void (__fastcall *o_cardinfo_send)(int *ctx, int edx);
static void __fastcall d_cardinfo_send(int *ctx, int edx) {
    unsigned uid = 0, slot = 0;
    if (ctx) { slot = (unsigned)ctx[2]; if (ctx[0]) uid = *(unsigned *)(ctx[0] + 0x3c); }
    char m[128];
    wsprintfA(m, "{\"ev\":\"cardinfo.send\",\"slot\":%u,\"uid_field\":%u}", slot, uid);
    host_log("info", m);
    o_cardinfo_send(ctx, edx);
}

/* [撤去 2026-07-12] card_read_sm(0x671470) への hook（whitelist bypass 目的）は CrackProof が起動~13s の
 * 整合性 scan で MinHook detour jump を復元し無効化（res:1→-97 に戻る）。同関数への code patch も同時復元＝
 * card_read_sm は CrackProof 保護領域。card 受理は hook/patch 不可。whitelist DATA 供給 or card UID 一致で
 * 対処すべき（facts/devices.md 参照）。 */

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
    e |= gh(0x985160, (void *)d_eeprom_init,(void **)&o_eeprom_init);
    e |= gh(0x9842A0, (void *)d_dipsw_init, (void **)&o_dipsw_init);   /* amDipswInit POST: dipsw ctx 早期 provisioning */
    e |= gh(0x679CB0, (void *)d_board_check,(void **)&o_board_check);  /* board check PRE: board index=2/flag 供給（errCode 0xa→errNo 910 解消）*/
    e |= gh(0x45A8F0, (void *)d_extimg_gate_probe,(void **)&o_extimg_gate_probe); /* image-present gate POST: DAT_01601b23=1（EXTEND IMAGE→OK skip）*/
    e |= gh(0x72EAF0, (void *)d_ext_install_kick,(void **)&o_ext_install_kick); /* extend-image install kicker POST: install_ctx 完了 provision */
    e |= gh(0x6FF7E0, (void *)d_allnet_url,      (void **)&o_allnet_url);        /* ALL.Net uri getter override: 空 uri を loopback backend URL に（card-auth の NetDataCardinfoRequest を allnet.c へ導く）*/
    e |= gh(0x643DE0, (void *)d_frametick,     (void **)&o_frametick);      /* main per-frame 実時間計時（pace.main）*/
    e |= gh(0x6C3930, (void *)d_present_drive,  (void **)&o_present_drive);  /* present 駆動部の実時間（内訳）*/
    e |= gh(0x89DAC0, (void *)d_scene_dispatch, (void **)&o_scene_dispatch); /* scene dispatch の実時間（内訳）*/
    e |= gh(0x712710, (void *)d_recv_parse,     (void **)&o_recv_parse);     /* ALL.Net NUPL 応答パーサ診断（init 応答拒否 d8→-1 の切り分け・READ ONLY）*/
    e |= gh(0x7203E0, (void *)d_cardinfo_send,  (void **)&o_cardinfo_send);  /* cardinfo 送信ビルダ診断（card-auth 到達＝cardinfo 発火の切り分け・READ ONLY）*/
    return e;
}
