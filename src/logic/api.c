/* logic.dll エントリ: host へ LogicApi を公開し Win32 フックを各 device へ振り分ける。
 * 状態は host arena に置く（永続 global 禁止）。abi.h と各 device の .h のみ依存。 */
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
    int patched;                /* 静的パッチ適用済みフラグ（reload で再適用しない）*/
    unsigned tick;              /* on_jvs_tick 呼出カウント（診断）*/
    unsigned last_keys;         /* 直近の入力ビットマスク（変化時のみ input.state を出す）*/
    unsigned sys_tick;          /* on_sys_override 呼出カウント（診断）*/
    int      test_entered;      /* test_mode 入口 scene 要求を1回だけ出すためのワンショットフラグ */
    int      eeprom_fixed;      /* EEPROM 強制 provisioning 済み（one-shot）*/
    HANDLE   eeprom_mutex;      /* 強制 provisioning 用 mutex（arena 上で生存）*/
    int      dipsw_fixed;       /* dipsw ctx 強制 provisioning 済み（one-shot）*/
    HANDLE   dipsw_mutex;       /* dipsw 強制 provisioning 用 mutex（arena 上で生存）*/
    HANDLE   dipsw_event;       /* dipsw overlapped 用 event（同期完了なら未使用だが ctx に要る）*/
    HANDLE   sysver_handle;     /* 仮想 C:\System\SystemVersion.txt（amPlatformGetOsVersion 用）sentinel */
    int      sysver_off;        /* 仮想 SystemVersion.txt read オフセット */
    /* --- COM4 / JVS --- */
    HANDLE   jvs_handle;
    JvsBoard jvs;
    uint8_t  jvs_resp[512];     /* 直近フレームの応答バッファ（簡易同期シリアル）*/
    int      jvs_resp_len;
    int      jvs_resp_off;
    /* --- COM1 / touch --- */
    HANDLE     touch_handle;
    TouchPanel touch;
    int        touch_opened_logged;  /* read ログ初回フラグ */
    uint8_t    touch_last_press;     /* 押下状態変化検出用 */
    int        touch_winwarn;        /* WGL 窓 not found 警告を1回だけ */
    /* --- COM2 / card（IC Card R/W, class 0x21）--- */
    HANDLE     card_handle;
    CardReader card;
    int        card_opened_logged;   /* read ログ初回フラグ */
    int        netauth_logged;       /* netauth.force_ready 初回ログフラグ */
    /* --- カード制御ファイル(nrsedge.card.json, loader が抜き差しで書く)の poll キャッシュ --- */
    int        card_ctl_seen;        /* 一度でも制御ファイルを読めたか（初回判定）*/
    FILETIME   card_ctl_mtime;       /* 最後に適用した last-write time（変化検知）*/
    unsigned   card_ctl_gen;         /* 最後に適用した gen（同一秒書込でも変化検知）*/
    wchar_t    card_img_path[MAX_PATH]; /* アクティブ card.bin パス（dirty 保存先）*/
    int        card_force_logged;    /* card.force_present 初回ログフラグ */
    int        card_accept_logged;   /* card.accept_gate 初回ログフラグ */
    /* --- headless タッチ注入（nrsedge.touch.json, テスト自動化用）--- */
    int        touch_ctl_seen;       /* 制御ファイルを一度読めたか */
    FILETIME   touch_ctl_mtime;      /* 最後に適用した last-write time */
    int        touch_force;          /* 1=注入有効（マウス sampling を置換）*/
    uint8_t    touch_force_press;    /* 注入押下 */
    uint16_t   touch_force_x, touch_force_y;  /* 注入座標（0..TOUCH_MAX 生値）*/
    /* TODO(P2+): overlapped 対応 / 可変長フレーム組立 */
};

static void l_bind(HostServices *host, LogicState **state) {
    if (!*state) {
        *state = (LogicState *)host->arena_alloc(sizeof(LogicState));
        memset(*state, 0, sizeof(LogicState));
        mxjvs_init(&(*state)->jvs);
        touch_init(&(*state)->touch);
        card_init(&(*state)->card);
    }
    (*state)->host = host;   /* reload 後の再バインド（状態は arena 上で生存）*/
    mxdev_init(host);        /* nvram 永続バッキング用（map は初回 IO で遅延）*/
    if (!(*state)->patched) { patches_apply(host); (*state)->patched = 1; }
    host->log("info", "{\"ev\":\"logic.bind\",\"abi\":1}");
}

static int is_com(const wchar_t *name, const wchar_t *want) {
    if (!name) return 0;
    /* "COM4" / "\\\\.\\COM4" 等の末尾一致 */
    size_t ln = wcslen(name), lw = wcslen(want);
    return ln >= lw && _wcsicmp(name + (ln - lw), want) == 0;
}

/* JVS が開く COM 番号は config.jvs_com（既定 4）。patches.c が 0xAE11F0 を同番号にパッチするので一致する。 */
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
    /* COM1 = タッチパネル（class 0x22, 9600 8N1）。standalone は kdserial OFF で COM1 固定。 */
    if (is_com(name, L"COM1") && !is_jvs_com(st, name)) {
        st->touch_handle = (HANDLE)(uintptr_t)0xC0114001;   /* sentinel */
        touch_init(&st->touch);
        st->touch_opened_logged = 0;
        st->host->log("info", "{\"ev\":\"touch.open\",\"port\":\"COM1\"}");
        *handled = 1;
        return st->touch_handle;
    }
    /* COM2 = IC Card R/W（class 0x21, SEGA 独自・Aime 非該当）。 */
    if (is_com(name, L"COM2") && !is_jvs_com(st, name)) {
        st->card_handle = (HANDLE)(uintptr_t)0xC0114003;   /* sentinel */
        card_init(&st->card);
        st->card_opened_logged = 0;
        st->host->log("info", "{\"ev\":\"card.open\",\"port\":\"COM2\"}");
        *handled = 1;
        return st->card_handle;
    }
    /* C:\System\SystemVersion.txt（amPlatformGetOsVersion 0x981d60 が読む）を仮想化。8 バイトが非ゼロ version に
       parse されれば DAT_00ccf44c!=0 → gate FUN_0045a6f0 戻り 0。欠損だと -3→errCode 3。 */
    if (is_com(name, L"SystemVersion.txt")) {          /* is_com は汎用 suffix マッチ */
        st->sysver_handle = (HANDLE)(uintptr_t)0xC0114002;   /* sentinel */
        st->sysver_off = 0;
        st->host->log("info", "{\"ev\":\"sysver.open\",\"file\":\"SystemVersion.txt\"}");
        *handled = 1;
        return st->sysver_handle;
    }
    {
        HANDLE mh;
        if (mxdev_create(name, &mh)) { *handled = 1; return mh; }   /* columba/mxsram/mxsmbus/… */
    }
    *handled = 0;
    return INVALID_HANDLE_VALUE;
}

/* バイト列を hex 文字列へ（cap-8 で安全に打ち切り）。戻り=書込み長。 */
static int jvs_to_hex(char *dst, int cap, const uint8_t *p, int n) {
    int o = 0;
    for (int i = 0; i < n && o + 3 < cap; i++) o += wsprintfA(dst + o, "%02x", p[i]);
    return o;
}

/* JVS 1 トランザクション(req+resp)をログ。連続同一フレームは dedup（READ_SW poll が ~60Hz で回るため）。 */
static void jvs_io_log(LogicState *st, const uint8_t *req, int rn, const uint8_t *resp, int sn) {
    static uint8_t last_req[260];  static int last_rn = -1;
    static uint8_t last_resp[260]; static int last_sn = -1;
    int rc = rn < (int)sizeof last_req, sc = sn < (int)sizeof last_resp;
    if (rc && sc && rn == last_rn && sn == last_sn
        && memcmp(req, last_req, rn) == 0 && memcmp(resp, last_resp, sn) == 0) return;  /* 変化なし */
    char m[700]; int o = wsprintfA(m, "{\"ev\":\"jvs.io\",\"cmd\":\"%02x\",\"wr\":\"",
                                   rn > 3 ? req[3] : 0);   /* req[3]=先頭コマンド（E0 dst len cmd..） */
    o += jvs_to_hex(m + o, (int)sizeof m - o - 12, req, rn);
    o += wsprintfA(m + o, "\",\"rd\":\"");
    o += jvs_to_hex(m + o, (int)sizeof m - o - 4, resp, sn);
    wsprintfA(m + o, "\"}");
    if (st->host && st->host->log) st->host->log("info", m);
    if (rc) { memcpy(last_req, req, rn); last_rn = rn; }
    if (sc) { memcpy(last_resp, resp, sn); last_sn = sn; }
}

/* WriteFile(COM4): 書込みバイトを 1 JVS フレームとして処理し応答をバッファ（write 時に応答生成）。
 * 入力は毎フレーム poll → mxjvs_set_input → READ_SW 応答に乗る。JVS はマスタ駆動 req/resp なので
 * 「1 write=1 frame」同期で十分（logic にスレッドを持たず reload 安全）。 */
static BOOL on_write_file(LogicState *st, HANDLE h, const void *buf, DWORD n, DWORD *put, int *hd) {
    if (h == st->jvs_handle) {
        NrsInput in; nrs_poll_input(&in, st->host && st->host->cfg ? st->host->cfg->bind : 0);
        mxjvs_set_input(&st->jvs, &in);  /* 入力を反映 */
        st->jvs_resp_len = mxjvs_handle_frame(&st->jvs, (const uint8_t *)buf, (int)n,
                                              st->jvs_resp, (int)sizeof st->jvs_resp);
        st->jvs_resp_off = 0;
        jvs_io_log(st, (const uint8_t *)buf, (int)n, st->jvs_resp, st->jvs_resp_len);
        if (put) *put = n;
        *hd = 1;
        return TRUE;
    }
    if (h == st->touch_handle) {                  /* COM1: game→panel コマンド（'p'/'P'/'R'）→ ack 積む */
        {   /* game が COM1 に書くバイトをログ */
            const uint8_t *b = (const uint8_t *)buf;
            char m[160]; int o = wsprintfA(m, "{\"ev\":\"touch.write\",\"n\":%d,\"hex\":\"", (int)n);
            for (DWORD i = 0; i < n && i < 16 && o + 3 < (int)sizeof m; i++) o += wsprintfA(m + o, "%02x", b[i]);
            wsprintfA(m + o, "\"}");
            if (st->host && st->host->log) st->host->log("info", m);
        }
        touch_on_write(&st->touch, (const uint8_t *)buf, (int)n);
        if (put) *put = n;                        /* 全消費（serial TX は常に成功）*/
        *hd = 1;
        return TRUE;
    }
    if (h == st->card_handle) {                   /* COM2: game→reader コマンド（生バイト観測）*/
        {   /* game が COM2 に書く opcode 列をログ */
            const uint8_t *b = (const uint8_t *)buf;
            char m[160]; int o = wsprintfA(m, "{\"ev\":\"card.write\",\"n\":%d,\"hex\":\"", (int)n);
            for (DWORD i = 0; i < n && i < 16 && o + 3 < (int)sizeof m; i++) o += wsprintfA(m + o, "%02x", b[i]);
            wsprintfA(m + o, "\"}");
            if (st->host && st->host->log) st->host->log("info", m);
        }
        card_on_write(&st->card, (const uint8_t *)buf, (int)n);
        if (put) *put = n;                        /* 全消費（serial TX は常に成功）*/
        *hd = 1;
        return TRUE;
    }
    return mxdev_write(h, buf, n, put, hd);   /* mxsram データ面（記録書込み）*/
}

/* ReadFile(COM4): バッファ済み応答をストリーム的に排出（残量 < 要求なら部分返し。native は header→残りと分割読みする）。 */
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
    if (h == st->touch_handle) {                  /* COM1: マウス位置 or 注入座標→'T' フレームをストリーム */
        if (st->touch_force) {                    /* headless 注入（nrsedge.touch.json）: mouse sampling を置換 */
            st->touch.x = st->touch_force_x; st->touch.y = st->touch_force_y;
            st->touch.pressed = st->touch_force_press;
        } else {
            HWND w = FindWindowW(NULL, L"WGL"); touch_sample_mouse(&st->touch, w ? w : GetForegroundWindow());
        }
        int k = touch_on_read(&st->touch, (uint8_t *)buf, (int)n);
        if (got) *got = (DWORD)k;
        /* 初回・押下状態変化・約2秒毎にログ（streaming 確認＋座標観測。常時は出さない）*/
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
    if (h == st->card_handle) {                   /* COM2: reader→game 応答（ACK/status/data）を排出 */
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
    if (h == st->sysver_handle) {                 /* 仮想 SystemVersion.txt: 8 バイト ASCII 版番号を返す */
        static const char ver[8] = { '2','0','1','1','0','7','2','8' };  /* 非ゼロに parse される（BIOS 日付相当）*/
        int avail = (int)sizeof ver - st->sysver_off;
        int k = ((int)n < avail) ? (int)n : avail;
        if (k < 0) k = 0;
        if (k > 0) memcpy(buf, ver + st->sysver_off, k);
        st->sysver_off += k;
        if (got) *got = (DWORD)k;
        *hd = 1;
        return TRUE;
    }
    return mxdev_read(h, buf, n, got, hd);   /* mxsram データ面（記録読込み）*/
}

static BOOL on_ioctl(LogicState *st, HANDLE h, DWORD c, void *i, DWORD il, void *o, DWORD ol,
                     DWORD *r, int *hd) {
    (void)st;
    return mxdev_ioctl(h, c, i, il, o, ol, r, hd);   /* columba/mxsram/mxsuperio/mxsmbus/mxhwreset */
}

/* SetFilePointer 傍受 → mxsram の記録位置決め（amSram の SetFilePointer→ReadFile/WriteFile 経路）。 */
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
    if (v >= 0xD0000001u && v <= 0xD0000005u) { *hd = 1; return TRUE; }  /* mxdev 擬似ハンドル */
    *hd = 0; return FALSE;
}

/* COM 制御傍受。仮想 COM ハンドルなら成功を返す。DCB は埋めなくてよい（game は設定するだけで読まない）。
 * serial RX ポンプ(FUN_0067c0c0)は ClearCommError の cbInQue!=0 のときだけ ReadFile するので cbInQue を申告する。 */
static BOOL on_comm_control(LogicState *st, HANDLE h, int op, void *p1, DWORD p2, void *p3, int *hd) {
    if (h == st->touch_handle) {
        (void)p2;
        *hd = 1;
        if (op == COMCTL_GET_MODEM_STATUS) { if (p1) *(DWORD *)p1 = 0; }
        else if (op == COMCTL_CLEAR_ERROR) {
            /* touch はストリーミング型（panel が 'T' を常時送出）→ 常に 1 フレーム受信待ちと申告。
               cbInQue=0 だと ReadFile が来ず touch 入力ゼロ。 */
            if (p1) *(DWORD *)p1 = 0;
            if (p3) { COMSTAT *cs = (COMSTAT *)p3; memset(cs, 0, sizeof *cs);
                      cs->cbInQue = TOUCH_FRAME_LEN; }
        }
        return TRUE;
    }
    if (h == st->card_handle) {
        /* card は request/response → cbInQue はキュー済み応答の残量（応答がある時だけ RX ポンプが ReadFile）。 */
        (void)p2;
        *hd = 1;
        if (op == COMCTL_GET_MODEM_STATUS) { if (p1) *(DWORD *)p1 = 0; }
        else if (op == COMCTL_CLEAR_ERROR) {
            if (p1) *(DWORD *)p1 = 0;                                      /* errors = 0 */
            if (p3) { COMSTAT *cs = (COMSTAT *)p3; memset(cs, 0, sizeof *cs);
                      cs->cbInQue = (DWORD)card_rx_pending(&st->card); }   /* 応答残量のみ受信待ち申告 */
        }
        return TRUE;
    }
    if (h != st->jvs_handle) { *hd = 0; return FALSE; }
    (void)p2;
    *hd = 1;
    switch (op) {
    case COMCTL_GET_MODEM_STATUS:
        /* JVS SENSE = modem status DSR ビット。sense=1(未割当)→0、sense=0(割当済=終端)→MS_DSR_ON。
           無いとマスタが SETADDR を無限に振り node 確定しない。 */
        if (p1) *(DWORD *)p1 = st->jvs.sense ? 0 : MS_DSR_ON;
        break;
    case COMCTL_CLEAR_ERROR:
        if (p1) *(DWORD *)p1 = 0;                                      /* errors = 0 */
        if (p3) memset(p3, 0, sizeof(COMSTAT));                        /* 空キュー */
        break;
    default: break;   /* Get/SetCommState, Get/SetCommTimeouts, SetupComm, PurgeComm: 成功のみ */
    }
    return TRUE;
}

/* EEPROM ctx(base 0xccf4e0) を再現し provisioning。standalone では amEepromInit(0x985160) の SetupDi 列挙失敗で
 * initFlag==0 → write fn が -3 洪水化。device handle を H_MXSMBUS にすると read/write fn の
 * DeviceIoControl(0x9c40200c,i2c@0x57)が mxsmbus エミュ(→eeprom.bin)へ流れる。
 * ctx: +0x00 initFlag / +0x04,+0x08 サイズ=6 / +0x0c mutex / +0x10 handle / +0x14 i2c addr=0x57。詳細 facts/mxdrivers.md。*/
static void eeprom_force_ready(LogicState *st) {
    if (st->eeprom_fixed) return;
    st->eeprom_fixed = 1;
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    volatile uint32_t *initFlag = (uint32_t *)(b + (0xCCF4E0u - 0x400000u));
    if (*initFlag != 0) return;                                  /* 実 amEepromInit 成功 → 触らない */
    if (!st->eeprom_mutex) st->eeprom_mutex = CreateMutexA(NULL, FALSE, NULL);
    *(uint32_t *)(b + (0xCCF4E4u - 0x400000u)) = 6;
    *(uint32_t *)(b + (0xCCF4E8u - 0x400000u)) = 6;
    *(HANDLE   *)(b + (0xCCF4ECu - 0x400000u)) = st->eeprom_mutex;     /* mutex（write fn が Wait/Release）*/
    *(HANDLE   *)(b + (0xCCF4F0u - 0x400000u)) = mxdev_smbus_handle(); /* device handle = H_MXSMBUS */
    *(uint8_t  *)(b + (0xCCF4F4u - 0x400000u)) = 0x57;                 /* AT24C64AN i2c addr */
    *initFlag = 1;
    if (st->host && st->host->log)
        st->host->log("info", "{\"ev\":\"eeprom.force_ready\",\"dev\":\"mxsmbus\",\"hdl\":\"H_MXSMBUS\"}");
}

/* dipsw ctx(base 0xccf488) を再現し provisioning。standalone では amDipswInit(0x9842a0) の SetupDi 列挙失敗で
 * handle=-1 → amDipswReadByte 即 return → board index ゴミ → errCode 0xa/0xb。ctx 再現で read fn の
 * DeviceIoControl(0x9c402004,cmd=5)が mxsmbus エミュへ流れ index0=0x20 → board index=(0x20>>4)&7=2。
 * ctx: +0x00 initFlag / +0x04 mutex / +0x08 handle / +0x0c smbus addr=0x20 / +0x38 busy=0 / +0x50 event。詳細 facts/devices.md。*/
static void dipsw_force_ready(LogicState *st) {
    if (st->dipsw_fixed) return;
    st->dipsw_fixed = 1;
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    HANDLE *handle = (HANDLE *)(b + (0xCCF490u - 0x400000u));
    if (*handle != INVALID_HANDLE_VALUE && *handle != (HANDLE)0) return;  /* 実 amDipswInit 成功 → 触らない */
    if (!st->dipsw_mutex) st->dipsw_mutex = CreateMutexA(NULL, FALSE, NULL);
    if (!st->dipsw_event) st->dipsw_event = CreateEventA(NULL, FALSE, FALSE, NULL);
    *(HANDLE   *)(b + (0xCCF48Cu - 0x400000u)) = st->dipsw_mutex;      /* +0x04 mutex（Read/Write fn が Wait/Release）*/
    *(HANDLE   *)(b + (0xCCF490u - 0x400000u)) = mxdev_smbus_handle(); /* +0x08 device handle = H_MXSMBUS */
    *(uint8_t  *)(b + (0xCCF494u - 0x400000u)) = 0x20;                 /* +0x0c smbus addr（addr 自体は handler 非依存）*/
    *(uint32_t *)(b + (0xCCF4C0u - 0x400000u)) = 0;                    /* +0x38 busy=0 */
    *(HANDLE   *)(b + (0xCCF4D8u - 0x400000u)) = st->dipsw_event;      /* +0x50 overlapped event */
    *(uint32_t *)(b + (0xCCF488u - 0x400000u)) = 1;                    /* initFlag（最後に立てる）*/
    if (st->host && st->host->log)
        st->host->log("info", "{\"ev\":\"dipsw.force_ready\",\"dev\":\"mxsmbus\",\"addr\":\"0x20\"}");
}

/* NIC link/ip（amNet NIC-level）の暫定橋渡し。alAbEx auth は allnet.c の ALL.Net HTTP サーバで genuine に成立させる
 * ため poke しない（擬似 LAN IP 192.168.11.1 解決 → LAN 判定 FUN_006ff140 が network_type_LAN_flag=1 →
 * PowerOn POST → 0x67 → AuthEvent → uri 供給）。詳細 facts/mxnetwork.md。 */
static void network_nic_bridge(LogicState *st) {
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    *(uint8_t *)(b + (0x16019A5u - 0x400000u)) = 1;   /* g_net_link_up */
    *(uint8_t *)(b + (0x16019A6u - 0x400000u)) = 1;   /* g_net_ip_match */
    if (!st->netauth_logged && st->host && st->host->log) {
        st->host->log("info", "{\"ev\":\"net.nic_bridge\",\"note\":\"genuine ALL.Net auth via allnet.c (LAN IP presentation)\"}");
        st->netauth_logged = 1;
    }
}

/* MMGP play-session タスクの状態を診断（attract→credit→card 連鎖のどこで止まるか確定）。
 * task list(0x16db564) を uid="MMGP"(0x50474d4d) で walk し subobj(node+0x10)を読む:
 *   subobj[0]=state(0=gate待ち/1=keepalive/2=start-txn) / subobj[1]=substate / +0xc=accept / +0xd=request /
 *   subobj[2]=msg ptr → msg+0x1ac=txn result, msg+8=msg status。
 * gate globals: DAT_0227fe6c(&0x700), DAT_0227fe70(&4), amlib_subsystem_state(0x16b8b54), lockout(0x16b8b6b)。*/
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
        if (node[1] == 0x50474d4d) {                       /* uid "MMGP" */
            unsigned char *so = (unsigned char *)(uintptr_t)node[4];   /* +0x10 ctx */
            if (so) {
                found = 1; state = *(int *)so; sub = *(int *)(so + 4);
                accept = so[0xc]; req = so[0xd];
                int msg = *(int *)(so + 8);
                if (msg) { msgres = *(int *)((uintptr_t)msg + 0x1ac); msgst = *(int *)((uintptr_t)msg + 8); }
            }
            break;
        }
        node = (int *)(uintptr_t)node[0xf];                /* next +0x3c */
    }
    /* state/substate 変化時 ＋ 約2秒毎にログ */
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

/* touch device データ構造体を取得（getter FUN_008b3b90 と同じ: DAT_016d8690 cache or class 0x22 list walk）*/
static unsigned char *touch_data_ctx(void) {
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    int *node = *(int **)(b + (0x16d8690u - 0x400000u));   /* DAT_016d8690 cache（node ptr）*/
    if (!node) {
        node = *(int **)(b + (0x16db564u - 0x400000u));    /* DAT_016db564 list head */
        while (node && (node[0] != 0x22 || node[1] != 0x22)) node = (int *)node[0xf];  /* next=+0x3c */
        if (!node) return 0;
    }
    return (unsigned char *)(uintptr_t)node[4];            /* data struct at +0x10 */
}

/* touch device の内部状態を ~120 フレーム毎に記録（serial→consumer の到達を診断）。 */
static void touch_diag(LogicState *st) {
    static unsigned n;
    unsigned char *c0 = touch_data_ctx();
    /* per-frame: touch-active(+0x211)/status(+0x166)/down-edge(+0x210[0]) の変化を即ログ（押下到達の確認）*/
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

    /* 校正矩形（touch_set_calib_window 0x8B3D60 が DAT_00bb30d8/e0 を積む）。
       cal_en=+0x198,+0x199 / X=[+0x19c,+0x1a4] / Y=[+0x1a0,+0x1a8]（int, poll_update が float 比較）。
       これが画面(1024x600)より小さい矩形なら中心引き込み k<1 の正体。実値からゲインを解析導出する。 */
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

    /* serial struct 配列 DAT_016b8678（3×0x70）を走査: 各 +4=handle / +0x14=TX count / +0x6c=flags。
       SerialThread: 0x16b87c8=ready, 0x16b87cc=obj。touch handle(0xC0114001)を持つ struct と TX 滞留を見る。 */
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

/* scene_va_name — task node の update slot(+0x24) VA → 実 C++ クラス名（RTTI 由来: vtable[-4]=COL →
 * +0x0c=TypeDescriptor → +0x08=mangled name）。VA は static_VA。継承で slot#2 を共有する組（Regist/
 * UpdateBase/… = 0x5ea0a0）と非クラスの task callback（attract=0x7274d0 等）は名付けず生 VA で出す。 */
static const char *scene_va_name(unsigned va) {
    switch (va) {
        case 0x5e6200: return "EntryModeCheckCard";    /* COL 0xca9538 / vtbl 0xbb34bc */
        case 0x5eaae0: return "EntryModeGamePoint";    /* COL 0xca9318 / vtbl 0xbb3584（GP 入金）*/
        case 0x5e90b0: return "EntryModeNameEntry";    /* COL 0xca94a0 / vtbl 0xbb34ec */
        case 0x5e8710: return "EntryModeSelectChara";  /* COL 0xca94ec / vtbl 0xbb34d4 */
        case 0x5eb000: return "EntryModeDotNetRegist"; /* COL 0xca92cc / vtbl 0xbb359c */
        case 0x5ec340: return "EntryModePassword";     /* COL 0xca9234 / vtbl 0xbb35cc */
        case 0x5eb6b0: return "EntryModeReIssue";      /* COL 0xca9280 / vtbl 0xbb35b4 */
        case 0x62fb50: return "EntryModeBase";         /* COL 0xca9584 / vtbl 0xbb34a4（基底）*/
        default:       return 0;                        /* RTTI 未解決/非クラス → 生 VA */
    }
}

/* scene_tag_fourcc — uid(tag) を ASCII FourCC へ（低位バイト順、amTaskOpen の重複警告と同順）。
 * 非表示文字と " \ は '.'（JSON 安全）。例: 0x50474d4d→"MMGP"。 */
static void scene_tag_fourcc(char out[5], unsigned tag) {
    for (int i = 0; i < 4; i++) {
        unsigned c = (tag >> (i * 8)) & 0xffu;
        out[i] = (c >= 0x20 && c < 0x7f && c != '"' && c != '\\') ? (char)c : '.';
    }
    out[4] = 0;
}

/* scene_node_json — delta の 1 エントリ。cls=RTTI クラス名(無ければ null) / tag=uid hex / tag4=FourCC。 */
static int scene_node_json(char *dst, int cap, unsigned va, unsigned tag) {
    char fc[5]; scene_tag_fourcc(fc, tag);
    const char *cls = scene_va_name(va);
    (void)cap;
    if (cls) return wsprintfA(dst, "{\"va\":\"%x\",\"tag\":\"%x\",\"tag4\":\"%s\",\"cls\":\"%s\"}",
                              va, tag, fc, cls);
    return wsprintfA(dst, "{\"va\":\"%x\",\"tag\":\"%x\",\"tag4\":\"%s\",\"cls\":null}", va, tag, fc);
}

/* scene_diag — task/scene list(DAT_016db564) を walk し active ノードの update VA(+0x24) を観測。
 * ノード: +4=uid tag / +8=flags(&1 active,&2 init,&4 remove) / +0x24=update / +0x3c=next。
 * 既知 update VA: attract=0x7274d0 / credit=0x5eaae0 / card-auth=0x5e6200。変化時＋約2秒毎にログ。 */
#define SCENE_CAP 64   /* active set ~35。超過分は trunc */
static void scene_diag(LogicState *st) {
    static unsigned n; static unsigned last_sig = 0xFFFFFFFFu; static int last_flags = -1;
    /* delta 用の前フレーム snapshot（(va,tag) の多重集合）。reload で 0 → 1 度だけ無音 seed。 */
    static unsigned prev_va[SCENE_CAP], prev_tag[SCENE_CAP]; static int prev_n = 0, seeded = 0;
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    unsigned char *node = *(unsigned char **)(b + (0x16DB564u - 0x400000u));
    unsigned sig = 0; int active_attract = 0, active_credit = 0, active_cardauth = 0, nact = 0;
    int seen_credit = 0, seen_cardauth = 0;   /* present at all（active 否かに依らず）*/
    unsigned cur_va[SCENE_CAP], cur_tag[SCENE_CAP]; int cur_n = 0, trunc = 0;
    for (int guard = 0; node && guard < 128; guard++) {
        unsigned flags = *(unsigned *)(node + 8);
        unsigned tag = *(unsigned *)(node + 4);            /* uid tag: 0x21=card,0x45='E',MMGP… */
        uintptr_t upd = *(uintptr_t *)(node + 0x24);
        unsigned va = upd ? (unsigned)(upd - b + 0x400000u) : 0;
        if (va == 0x5eaae0) { seen_credit = 1; if (flags & 1) active_credit = 1; }
        if (va == 0x5e6200) { seen_cardauth = 1; if (flags & 1) active_cardauth = 1; }
        if (va == 0x7274d0 && (flags & 1)) active_attract = 1;
        if (flags & 1) {
            nact++; sig = sig * 31u + va;                  /* active set の署名 */
            if (cur_n < SCENE_CAP) { cur_va[cur_n] = va; cur_tag[cur_n] = tag; cur_n++; }
            else trunc = 1;
        }
        node = *(unsigned char **)(node + 0x3c);
    }
    /* scene.delta — active(va,tag) 多重集合を前フレームと diff し add/del を出す。未知 VA は生 hex で温存。 */
    if (!seeded) {                                          /* 初回（reload 後含む）は無音で baseline を確定 */
        for (int i = 0; i < cur_n; i++) { prev_va[i] = cur_va[i]; prev_tag[i] = cur_tag[i]; }
        prev_n = cur_n; seeded = 1;
    } else {
        char used[SCENE_CAP]; for (int i = 0; i < prev_n; i++) used[i] = 0;
        char dl[760]; int dn = 0, ao = 0, ro = 0;          /* dl: add[] 群 / 別 buf に del[] 群 */
        char rm[380];
        for (int i = 0; i < cur_n; i++) {                  /* cur にあって prev に無い = add */
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
        for (int j = 0; j < prev_n; j++) {                 /* prev に残った = del */
            if (used[j]) continue;
            if (ro < (int)sizeof rm - 80) {
                ro += wsprintfA(rm + ro, "%s", rn++ ? "," : "");
                ro += scene_node_json(rm + ro, (int)sizeof rm - ro, prev_va[j], prev_tag[j]);
            }
        }
        if (dn || rn) {                                    /* 変化フレームだけ出す */
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
        /* sig 変化時のみ active node の update VA 一覧をダンプ（title scene と touch 追加ノードを特定）。 */
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

/* 実マウス→消費側 report バッファへ直接注入（report_promote 0x8B37F0 と同機構）。現在は未使用（serial 経路で足りる）。
 * ctx: +0x2b8[0]=press / +0x2b9,+0x2ba=down/move / +0x2dc(float)=X / +0x2e0(float)=Y → promote で +0x210/+0x234/+0x238。
 * 座標空間は native(1024x600)。窓 client を native へスケール。 */
static void touch_inject(LogicState *st) {
    /* amDebug_flag_hi(demo 自動入力)が +0x2b8 を奪うので毎フレーム clear。 */
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
    float nx = (float)p.x * (1024.0f / (float)cw);   /* client → native X（想定 1024）*/
    float ny = (float)p.y * (600.0f  / (float)ch);   /* client → native Y（想定 600）*/
    int press = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) ? 1 : 0;
    int down  = (press && !st->touch_last_press) ? 1 : 0;   /* 押下エッジ */

    /* (A) report_promote 経路: +0x2b8→+0x210/+0x234（press と pixel 座標）。dirty で昇格。 */
    c[0x2b8] = (unsigned char)press;          /* → +0x210（押下保持）*/
    c[0x2b9] = (unsigned char)down;           /* → +0x211（押下エッジ）*/
    c[0x2ba] = (unsigned char)press;          /* → +0x212 */
    *(float *)(c + 0x2dc) = nx;               /* → +0x234（X pixel）*/
    *(float *)(c + 0x2e0) = ny;               /* → +0x238（Y pixel）*/
    c[0x30c] = 1;                             /* dirty → report_promote */

    /* (B) decode_T_coord(0x8B31E0) の全フィールド直接再現（hit-test 系が読む raw/正規化座標）。
       +0x228/+0x22c = 正規化 0..1（DAT_00c916d0=1/4095）, +0x21c/+0x220 = 軸反転 raw(0xfff-X)。 */
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

/* DirectInput/951 診断: dinput_create_device(0x67CBE0)が count を立てたか、どこで count=0(Error 951)になるか観測。
 *   usbio_board_count(0x16b88dc): <1 で errCode 0xf→951 / dinput_ctx(0x16f3a4c): IDirectInput8*(0=Create 失敗) /
 *   dev0/dev1(0x16f3a50/54): GAMECTRL joystick / mouse(0x16f3a58): SysMouse device / hwnd(0x1696e0c): SetCoopLevel 用。 */
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

/* カード制御ファイル（loader → 稼働中 logic）: loader が抜き差しで nrsedge.card.json を書き、logic は
 * last-write 変化時のみ再読込。ファイル I/O は host->orig（自フック再入＝SRW deadlock 回避）。 */

typedef HANDLE (WINAPI *CreateFileW_fn)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL   (WINAPI *ReadFile_fn)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *WriteFile_fn)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *CloseHandle_fn)(HANDLE);

/* nrsedge.card.json のフルパス（ゲーム exe と同 dir）。 */
static void card_ctl_path(wchar_t *out, int cap) {
    GetModuleFileNameW(NULL, out, (DWORD)cap);
    wchar_t *p = wcsrchr(out, L'\\');
    if (p) p[1] = 0; else out[0] = 0;
    wcsncat(out, L"nrsedge.card.json", (size_t)cap - wcslen(out) - 1);
}

/* 小ファイルを orig(CreateFileW/ReadFile/CloseHandle) で丸読み。戻り=読込バイト数（<=0 失敗）。 */
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

/* st->card.image(4104B) を path へ書き戻す（orig 経由）。戻り=成功(1)/失敗(0)。 */
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

/* control JSON から整数値を取る（"key": <int>）。不在/不正は def。 */
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
/* control JSON から文字列値（"key":"..."）を取る。\\ → \ をアンエスケープ。戻り=長さ。 */
static int cj_str(const char *j, const char *key, char *out, int cap) {
    char needle[40]; wsprintfA(needle, "\"%s\"", key);
    const char *p = strstr(j, needle); out[0] = 0; if (!p) return 0;
    p += strlen(needle);
    while (*p && (*p == ':' || *p == ' ' || *p == '\t')) p++;
    if (*p != '"') return 0; p++;
    int i = 0;
    while (*p && *p != '"' && i < cap - 1) {
        if (*p == '\\' && p[1]) p++;     /* \\ → \ , \" → " */
        out[i++] = *p++;
    }
    out[i] = 0; return i;
}

static void card_control_poll(LogicState *st) {
    wchar_t path[MAX_PATH]; card_ctl_path(path, MAX_PATH);
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fa)) return;   /* 制御ファイル未作成 */
    if (st->card_ctl_seen
        && fa.ftLastWriteTime.dwLowDateTime  == st->card_ctl_mtime.dwLowDateTime
        && fa.ftLastWriteTime.dwHighDateTime == st->card_ctl_mtime.dwHighDateTime)
        return;                                                           /* 無変化 */
    char buf[1024];
    int n = card_read_raw(st, path, buf, sizeof buf - 1);
    if (n <= 0) return;                                                   /* 読めなければ mtime も更新せず再試行 */
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
            card_read_raw(st, wimg, st->card.image, CARD_IMAGE_BYTES);   /* 4104B 未満は 0 埋めのまま */
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
        if (st->card.present && st->card.dirty) card_save_image(st);     /* 取出前に永続化 */
        st->card.present = 0;
        if (st->host && st->host->log) {
            char m[80]; wsprintfA(m, "{\"ev\":\"card.eject\",\"present\":0,\"gen\":%u}", gen);
            st->host->log("info", m);
        }
    }
}

/* headless タッチ注入（nrsedge.touch.json）: loader/スクリプトが press/xm/ym を書く。card_control_poll と同流儀。
 * touch_force 有効時は on_read_file(COM1) が touch_sample_mouse を置換し serial 'T' 経路へ流す（窓/カーソル非依存）。 */
static void touch_control_poll(LogicState *st) {
    wchar_t path[MAX_PATH]; GetModuleFileNameW(NULL, path, MAX_PATH);
    wchar_t *p = wcsrchr(path, L'\\'); if (p) p[1] = 0; else path[0] = 0;
    wcsncat(path, L"nrsedge.touch.json", MAX_PATH - wcslen(path) - 1);
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fa)) { st->touch_force = 0; return; }
    if (st->touch_ctl_seen
        && fa.ftLastWriteTime.dwLowDateTime  == st->touch_ctl_mtime.dwLowDateTime
        && fa.ftLastWriteTime.dwHighDateTime == st->touch_ctl_mtime.dwHighDateTime)
        return;                                                           /* 無変化 */
    char buf[256];
    int n = card_read_raw(st, path, buf, sizeof buf - 1);
    if (n <= 0) return;
    buf[n] = 0;
    st->touch_ctl_mtime = fa.ftLastWriteTime;
    st->touch_ctl_seen = 1;
    int press = cj_int(buf, "press", 0);
    /* x/y は 0..1000 の千分率整数として渡す（cj_int は整数のみ）。既定 = 中央 500。*/
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

static int *cardrw_object(uintptr_t b);   /* 前方宣言（card_force_present の手前で定義）*/

/* card SM 診断: カード検出が serial SEARCH を撃たない理由を特定する。cardrw 状態機械の核 globals と
 * cardrw オブジェクト(node DAT_016d868c → node[4], stride 0x6714)の flags/state2/state3 を変化時に記録。
 *   ae538=device-found / ae53c=pump substate(10=READY) / ae5c8=cmd class(0idle/2read/3write) /
 *   ae5cc=request(-1=none,2=read要求) / ae5e0=read count / ae540=sm result。
 *   obj[0]=flags / obj[2]=state2(0poll/1detect/2present) / obj[3]=state3(0wait-slot/3,4=read/5write)。 */
static void card_sm_diag(LogicState *st) {
    static int last = -0x7fffffff; static unsigned n; static int wl_logged = 0;
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    /* カード受理ゲート = UID whitelist（card_read_sm 0x671470）。一度だけ実値をダンプして判断材料にする:
       DAT_016a55ad=件数 / DAT_016a55ba=bypass / DAT_016a55ac=必要block数 / DAT_016a55b8=maxlen / DAT_016a55b0[]=UID群。*/
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
    /* device_status = object+4（cardrw_device_status_ptr 0x4f3e30）。flags=+0 / state2=+8 / presence=+0x5628。 */
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

/* cardrw デバイスオブジェクト(class 0x21,0x21)を取得（cardrw_device_status_ptr 0x4f3e30 と同じ探索）。
 * 戻り = object base = node[4]（device_status は object+4）。無ければ 0。 */
static int *cardrw_object(uintptr_t b) {
    int *node = *(int **)(b + (0x16D868Cu - 0x400000u));   /* DAT_016d868c キャッシュ */
    if (!node) {
        node = *(int **)(b + (0x16DB564u - 0x400000u));    /* DAT_016db564 list head */
        while (node && (node[0] != 0x21 || node[1] != 0x21)) node = (int *)(uintptr_t)node[0xf];
    }
    if (!node) return 0;
    return (int *)(uintptr_t)node[4];                       /* object base（無ければ 0）*/
}

/* 仮想カード present 時、cardrw presence フィールド(device_status+0x5628)を 1 に供給する。standalone には実機の
 * カード挿入検出信号が無く、card-select scene(0x5e6200)の present ゲート `+0x5628!=0` が立たない。これに 1 を書くと
 * read シーケンサ FUN_004f30a0 が read 列に入り presence query FUN_004f6a30 も present を返す。SM 中間 state は触らない。
 * offset: cardrw_device_status_ptr(0x4f3e30): object=node[4] / device_status=object+4 / presence=+0x5628。*/
/* CrackProof 復元 vs whitelist 後ロードの切り分け診断（変化時のみ記録）: card_read_sm(0x671470) の patch バイト
 * (0x671aac=EB?7E? / 0x6717d5=90?75?) と whitelist count/bypass/UID[0]/読取UID を追う。 */
static void card_patch_diag(LogicState *st) {
    static unsigned last_sig = 0xffffffff;
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    unsigned pa = *(uint8_t *)(b + (0x671AACu - 0x400000u));   /* halt patch: EB=生存 / 7E=復元 */
    unsigned pf = *(uint8_t *)(b + (0x6717D5u - 0x400000u));   /* first patch: 90=生存 / 75=復元 */
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

/* amlib device manager(class 0x20/0x20 タスクの *(node[4]))を取得。SYSTEM STARTUP boot SM の CONNECTION
 * チェックは status 配列 manager+0x1d4+idx*4 を各項目(AUTH/UPLOAD/GAME SERVER/LOCAL)について読む（2=ready）。 */
static int *amlib_devmgr(uintptr_t b) {
    int *node = *(int **)(b + (0x16D8688u - 0x400000u));       /* DAT_016d8688 cache */
    if (!node) {
        node = *(int **)(b + (0x16DB564u - 0x400000u));        /* DAT_016db564 task list head */
        while (node && (node[0] != 0x20 || node[1] != 0x20)) node = (int *)(uintptr_t)node[0xf];
    }
    if (!node || !node[4]) return 0;
    return (int *)(uintptr_t)(*(int *)(uintptr_t)node[4]);      /* *(node[4]) = manager object */
}

/* device status 配列 + network フラグ + NIC ディスクリプタの観測（ALL.Net パッチ撤去後の genuine emulation 設計用）。
 * NIC slot 配列 base=0x210b5b8 stride8, +4=descriptor ptr（[+0]=state 2=接続, [+4]=IP）。flags 0x210b50a/b/c。 */
static void amlib_devstat_diag(LogicState *st) {
    static unsigned last = 0xffffffff;
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    int *mgr = amlib_devmgr(b);
    int s0=-1,s1=-1,s2=-1,s3=-1,s4=-1,s5=-1; unsigned m1ec=0;
    /* exec SM(amlib_conn_exec_sm 0x72a200)観測: mgr+0x1f8=state, +0x204=status(idx4 gate), +0x210=conn-type */
    int xstate=-1, xstat=-1, xctype=-1;
    if (mgr) {
        s0=mgr[0x1d4/4]; s1=mgr[0x1d8/4]; s2=mgr[0x1dc/4]; s3=mgr[0x1e0/4]; s4=mgr[0x1e4/4]; s5=mgr[0x1e8/4];
        m1ec = *(unsigned *)((uintptr_t)mgr + 0x1ec);
        xstate = *(int *)((uintptr_t)mgr + 0x1f8);
        xstat  = *(int *)((uintptr_t)mgr + 0x204);
        xctype = *(int *)((uintptr_t)mgr + 0x210);
    }
    /* ALL.Net async client グローバル（絶対VA）: 020f493c=connect結果(0=OK), 4934=client-ready, 4940=armed, 496c=req#, 4939=busy */
    unsigned g_connres = *(unsigned *)(b + (0x020f493cu - 0x400000u));
    unsigned g_ready   = *(unsigned char *)(b + (0x020f4934u - 0x400000u));
    unsigned g_armed   = *(unsigned char *)(b + (0x020f4940u - 0x400000u));
    unsigned g_reqno   = *(unsigned short *)(b + (0x020f496cu - 0x400000u));
    unsigned g_busy    = *(unsigned char *)(b + (0x020f4939u - 0x400000u));
    /* URI 文字列 DAT_0126591c（std::string MSVC: [0..15]=SSO buf / cap>15 なら [0..3]=heap ptr, [16]=size, [20]=cap）。
       規模判定のため size/cap と内容を生ダンプ（SSO/heap 両対応）。 */
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
    /* NIC ディスクリプタ 3 slot: state / IP */
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
    if ((*(uint32_t *)ds & 0x10u) != 0) return;        /* error 中は触らない */
    volatile int *presence = (int *)(ds + 0x5628);
    if (*presence == 0) {
        *presence = 1;                                  /* カード挿入検出信号を供給 */
        if (!st->card_force_logged && st->host && st->host->log) {
            st->host->log("info", "{\"ev\":\"card.force_present\",\"set\":\"ds+0x5628=1\"}");
            st->card_force_logged = 1;
        }
    }
}

/* カード受理ゲート（card_read_sm 0x671470 の UID whitelist）を毎フレーム無条件で通す: bypass=1（最初の
 * whitelist 照合を skip し data 読取へ）＋ whitelist count=0（halt 再照合を skip し state9=成功へ）。standalone は
 * 正規発行カードの whitelist を持たず game が周期的に count を再populate するため、card.present に依らず毎フレーム
 * 再供給して race を潰す（card_read_sm は別スレッドで走るため頻繁な reset が要る）。res:-97「このカードは使用
 * できません」を解消。globals: bypass=0x16a55ba / count=0x16a55ad。 */
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

/* JSON 文字列値の最小エスケープ（"..."付き, 制御/非ASCII は '.'）。診断ログ用。 */
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

/* NUPL(ALL.Net セッションタスク) READ-ONLY 診断。POST 先 URL = obj+8(std::string) は genuine PowerOn の uri。
 * node: +0x04=uid("NUPL"=0x4c50554e) / +0x10=&object-ptr / +0x3c=next。object = *(int*)(node[4])（double deref）。
 * obj+8=URL(+0x18 size/+0x1c cap、SSO は cap<0x10) / +0xd8=status(0 ok,1 inprogress,-1 err) / +0x200fc=SM state(3=準備完了)。 */
static void nupl_diag(LogicState *st) {
    static int last_sig = -0x7fffffff, logged_bad = 0;
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    int *node = *(int **)(b + (0x16DB564u - 0x400000u));   /* DAT_016db564 task list head */
    for (int g = 0; node && g < 128; g++) {
        if (node[1] == 0x4C50554E) {                        /* uid "NUPL" */
            int *slot = (int *)(uintptr_t)node[4];          /* node+0x10 = &object-ptr */
            unsigned char *obj = slot ? (unsigned char *)(uintptr_t)slot[0] : 0;  /* *(node[4]) = object */
            if (!obj || (uintptr_t)obj < 0x10000) {
                if (!logged_bad && st->host && st->host->log) {
                    logged_bad = 1; st->host->log("warn", "{\"ev\":\"nupl.obj_bad\"}");
                }
                return;
            }
            uint32_t cap  = *(uint32_t *)(obj + 0x1c);      /* URL std::string capacity */
            uint32_t size = *(uint32_t *)(obj + 0x18);      /* URL std::string size */
            int state = *(int *)(obj + 0x200fc);            /* SM state */
            int d8    = *(int *)(obj + 0xd8);               /* 応答 status */
            int exp_id = *(int *)(obj + 0x20130);           /* recv が待つ command_common id */
            int req_id = *(int *)(obj + 0x20134);           /* 送信時の command_common id */
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
            /* state2 停滞の解剖: state2 handler(FUN_007137a0)が tick されているか＝timer(0x20128 clock)が進むかを
               ~1s 毎に観測。tnow が毎回変われば handler は回っている＝advance 条件(FUN_00714230)側の問題、
               tnow が static なら tick が止まっている＝SM 駆動が停止（別 driver 要）。d4/dc も併記。 */
            if (state == 2) {
                static unsigned n2 = 0;
                if ((n2++ % 60) == 0 && st->host && st->host->log) {
                    int d4    = *(int *)(obj + 0xd4);
                    int dc    = *(int *)(obj + 0xdc);
                    int tflag = *(int *)(obj + 0x2012c);   /* timer active flag */
                    int tdur  = *(int *)(obj + 0x20124);   /* timeout 閾値(60000) */
                    int tstart= *(int *)(obj + 0x20120);   /* timer start */
                    int tnow  = *(int *)(obj + 0x20128);   /* timer now (clock) */
                    char m2[220];
                    wsprintfA(m2, "{\"ev\":\"nupl.s2\",\"d4\":%d,\"dc\":%d,\"tflag\":%d,\"tdur\":%d,"
                                  "\"tstart\":%d,\"tnow\":%d,\"elapsed\":%d}",
                              d4, dc, tflag, tdur, tstart, tnow, tnow - tstart);
                    st->host->log("info", m2);
                }
            }
            return;
        }
        node = (int *)(uintptr_t)node[0xf];                 /* next +0x3c */
    }
}

/* alAbEx ALL.Net auth SM READ-ONLY 診断。status = *(0x0249682c): 0x65 REVALIDATION / 0x66 BUSY / 0x67 AUTH-OK /
 *   0x69 RETRY-WAIT / 0x6a,0x6b DownloadOrder / 負値=error(-0xc6 SYSTEM/-0x1f1 COMM/-499 NG/-0x1f2 TIMEOUT/-199 NOINIT)。
 * flags: 0x210AED0 started / 0x210AED2 auth_ok / 0x210B508 complete / 0x210AF48 reval_gate / 0x210B509 lan_reachable。*/
static void alabex_diag(LogicState *st) {
    static int last = -0x7fffffff;
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    int status  = *(int32_t *)(b + (0x0249682Cu - 0x400000u));
    int started = *(uint8_t *)(b + (0x210AED0u - 0x400000u));
    int authok  = *(uint8_t *)(b + (0x210AED2u - 0x400000u));
    int complete= *(uint8_t *)(b + (0x210B508u - 0x400000u));
    int reval   = *(int32_t *)(b + (0x210AF48u - 0x400000u));
    int lan     = *(uint8_t *)(b + (0x210B509u - 0x400000u));
    int phase   = *(int32_t *)(b + (0x210AEE0u - 0x400000u));   /* alAbEx driver phase */
    int lanflag = *(uint8_t *)(b + (0x210B50Cu - 0x400000u));   /* network_type_LAN_flag */
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


    dinput_diag(st);          /* DirectInput/951 状態観測（実 SysMouse 供給で 951 純正解消する前提調査）*/
    eeprom_force_ready(st);   /* EEPROM 未 provisioning なら provisioning（amBackup -3 洪水の解消）*/
    dipsw_force_ready(st);    /* dipsw ctx 未 provisioning なら provisioning（board index errCode 0xa/0xb の解消）*/
    network_nic_bridge(st);   /* NIC link/ip 暫定橋渡し（alAbEx auth 詐称は撤去＝genuine ALL.Net を allnet.c で成立させる）*/
    mmgp_diag(st);            /* MMGP play-session 連鎖の診断（gate/state/txn のどこで止まるか確定）*/
    touch_diag(st);           /* touch device 内部状態の診断（serial→consumer 到達確認）*/
    scene_diag(st);           /* attract→credit→card-auth の scene 活性化を観測（Phase B2 停止点の切分け）*/
    touch_control_poll(st);   /* nrsedge.touch.json を反映（headless タッチ注入→attract 進行の自動テスト）*/
    card_control_poll(st);    /* loader の nrsedge.card.json を反映（カードのライブ抜き差し→present/image）*/
    card_force_present(st);   /* present 時、cardrw presence フィールドを供給（standalone のカード挿入信号欠落を補完）*/
    card_accept_gate(st);     /* 無条件: card_read_sm の UID whitelist を bypass（所有カード受理・res:-97 解消）*/
    card_sm_diag(st);         /* カード検出 SM の観測（card-select 画面でのゲート解析用・読取専用）*/
    card_patch_diag(st);      /* CrackProof 復元 vs whitelist 後ロードの切り分け（patch バイト+count 追跡・読取専用）*/
    amlib_devstat_diag(st);   /* SYSTEM STARTUP CONNECTION チェックの device status 配列観測（device_status パッチ撤去後の emulation 設計用）*/
    nupl_diag(st);            /* NUPL(ALL.Net card-info)タスクの URL/status/SM を観測（正しい ALL.Net auth→uri 供給の検証）*/
    alabex_diag(st);          /* alAbEx ALL.Net auth SM の status 観測（genuine PowerOn auth が走るか＝POST 不発の切り分け）*/

    /* touch_inject は不要（serial 経路でタッチが流れる）。 */

    /* 筐体 TEST/SERVICE 毎フレーム上書き（dipsw byte2=3 の常時 ON を入力で打ち消す）。on_sys_override は
       attract 中に発火しない場合があるため、毎フレーム呼ばれる本フックでも DAT_0160194c bit0/1 を書く。 */
    {
        uint32_t *sw = (uint32_t *)((uintptr_t)GetModuleHandleW(NULL) + (0x160194Cu - 0x400000u));
        *sw = (*sw & ~3u) | (in.test ? 1u : 0u) | (in.service ? 2u : 0u);
    }

    /* freeplay（config 連動）: credit init 済なら free-play flag を保証 */
    if (cfg && cfg->freeplay) {
        uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
        uint32_t *initf = (uint32_t *)(b + (0x1288550u - 0x400000u));  /* credit_init_flag */
        uint8_t  *fp    = (uint8_t  *)(b + (0x128855Au - 0x400000u));  /* free_play_flag   */
        if (*initf != 0 && *fp != 1) *fp = 1;
    }

    /* 入力状態を GUI（入力テストタブ）へ: 変化時のみ input.state を出力（先頭2フレームは hook 確認用）*/
    st->tick++;
    unsigned keys = in.test | (in.service<<1) | (in.coin<<2) | (in.start<<3) | (in.up<<4) | (in.down<<5)
                  | (in.left<<6) | (in.right<<7) | (in.jump<<8) | (in.dash<<9) | (in.action<<10);
    if (st->tick <= 2 || keys != st->last_keys) {
        uintptr_t bb = (uintptr_t)GetModuleHandleW(NULL);
        unsigned sw194c = *(uint32_t *)(bb + (0x160194Cu - 0x400000u));   /* 筐体 TEST/SERVICE reg */
        unsigned cook   = *(uint32_t *)(bb + (0x2282A64u - 0x400000u)) & 0xFFFF; /* FUN_0089b230 cooked */
        unsigned node643 = *(uint8_t *)(bb + (0x16B7860u - 0x400000u) + 0x643); /* native 経路がデコードした P1 sw（COM4 入力反映の検証用）*/
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

/* DAT_0160194c の TEST(bit0)/SERVICE(bit1) を入力で上書き（dipsw byte2=3 の常時 ON を入力で打ち消す）。
 * 加えて test_mode のとき「テストメニュー入口」をワンショットで要求する（下記）。 */
static void on_sys_override(LogicState *st) {
    const NrsConfig *cfg = st->host ? st->host->cfg : 0;
    NrsInput in; nrs_poll_input(&in, cfg ? cfg->bind : 0);
    uint32_t *p = (uint32_t *)((uintptr_t)GetModuleHandleW(NULL) + (0x160194Cu - 0x400000u));
    *p = (*p & ~3u) | (in.test ? 1u : 0u) | (in.service ? 2u : 0u);
    st->sys_tick++;

    /* テストメニュー入口: 入口は TEST スイッチではなく scene 要求。scene_request_consume(0x6F0750)が要求 scene id
       DAT_016B8B54 を読み ≠-1 なら生成→id を -1（ワンショット）。id=13 = テストモード容器 scene。standalone は
       通常の要求フラグ(DAT_016F5A9C)が立たないため、boot 完了後に id=13 を一度だけ書いて入場させる。
       TEST は保持しない（メニュー内ナビはエッジ駆動、保持すると即退出）。 */
    if (cfg && cfg->test_mode && !st->test_entered && st->sys_tick > 20) {
        *(uint32_t *)((uintptr_t)GetModuleHandleW(NULL) + (0x16B8B54u - 0x400000u)) = 13;  /* requested scene id */
        st->test_entered = 1;
        if (st->host && st->host->log) st->host->log("info", "{\"ev\":\"testmenu.enter\",\"scene\":13}");
    }

    if (st->sys_tick <= 3) {   /* このフックが発火しているかの診断（先頭3回のみ）*/
        char m[120];
        wsprintfA(m, "{\"ev\":\"sys.ovr\",\"n\":%u,\"T\":%d,\"S\":%d,\"194c\":%u}", st->sys_tick, in.test, in.service, *p);
        if (st->host && st->host->log) st->host->log("info", m);
    }

}

/* keychip present flag hold: ctx(0xCCF000)+4 && +8 が非ゼロ＝真正 present のとき keychip_present_flag(0x16014A2)=1
 * を保持（一方向ラッチの誤クリアを打ち消す）。真正 present 化には PCP サーバ(keychip_server)が前提。 */
static void on_keychip_hold(LogicState *st) {
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    uint32_t  c = *(uint32_t *)(b + (0xCCF000u - 0x400000u));   /* keychip ctx ptr */
    uint8_t  *a2 = (uint8_t *)(b + (0x16014A2u - 0x400000u));   /* keychip_present_flag */
    if (c) {
        const uint32_t *ctx = (const uint32_t *)(uintptr_t)c;
        if (ctx[1] != 0 && ctx[2] != 0 && *a2 == 0) *a2 = 1;   /* ctx+4 && ctx+8 */
    }
    (void)st;
}

/* amRtcGetServerTime(0x974040) POST, only-on-failure: 実 RTC 応答(orig!=-1)は温存、失敗(-1)時のみ PC ローカル時刻で
 * amRtcTime を埋め成功(0)を返す。構造体: +0 WORD year / +2 month / +3 day / +4 hour / +5 min / +6 sec(60→59 クランプ)。 */
static long long on_rtc_get(LogicState *st, void *time_out, unsigned *flag_out, long long orig_ret) {
    if (orig_ret != -1) return orig_ret;          /* 実 RTC 成功 → 温存 */
    if (!time_out) return orig_ret;
    SYSTEMTIME lt;
    GetLocalTime(&lt);
    uint8_t *t = (uint8_t *)time_out;
    *(uint16_t *)(t + 0) = (uint16_t)lt.wYear;
    t[2] = (uint8_t)lt.wMonth;
    t[3] = (uint8_t)lt.wDay;
    t[4] = (uint8_t)lt.wHour;
    t[5] = (uint8_t)lt.wMinute;
    t[6] = (uint8_t)(lt.wSecond == 60 ? 59 : lt.wSecond);   /* converter と同じ閏秒クランプ */
    if (flag_out) *flag_out = 0;                  /* DST 相当フラグ: 0（未使用・診断のみ）*/
    if (st && st->host && st->host->log) {
        char m[160];
        wsprintfA(m, "{\"ev\":\"rtc.get\",\"src\":\"localtime\",\"y\":%u,\"mo\":%u,\"d\":%u,\"h\":%u,\"mi\":%u,\"s\":%u}",
                  lt.wYear, lt.wMonth, lt.wDay, lt.wHour, lt.wMinute, lt.wSecond);
        st->host->log("info", m);
    }
    return 0;   /* ≠ -1 = success */
}

/* amEepromInit(0x985160) detour: storage-init の最中に EEPROM ctx を早期 provisioning（per-frame force は init 後で遅い）。 */
static void on_eeprom_init(LogicState *st) {
    eeprom_force_ready(st);
}

/* amDipswRead(0x45A0E0) PRE detour: board check が使う board_index の読取前に dipsw ctx を provisioning（per-frame force は遅い）。 */
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
