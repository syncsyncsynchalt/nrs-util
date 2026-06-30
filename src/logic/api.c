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
    (*state)->host = host;   /* reload 後の再バインド（jvs 状態は arena 上で生存）*/
    mxdev_init(host);        /* nvram 永続バッキング用に host サービスを渡す（map は初回 IO で遅延）*/
    if (!(*state)->patched) { patches_apply(host); (*state)->patched = 1; }  /* 旧 impl 静的パッチ */
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
    /* COM1 = タッチパネル（class 0x22, 9600 8N1）。実機 standalone は kdserial OFF で COM1 固定。
       JVS が COM1 に設定されている異常時は JVS を優先（上の is_jvs_com で既に処理済み）。 */
    if (is_com(name, L"COM1") && !is_jvs_com(st, name)) {
        st->touch_handle = (HANDLE)(uintptr_t)0xC0114001;   /* sentinel */
        touch_init(&st->touch);
        st->touch_opened_logged = 0;
        st->host->log("info", "{\"ev\":\"touch.open\",\"port\":\"COM1\"}");
        *handled = 1;
        return st->touch_handle;
    }
    /* COM2 = IC Card R/W（class 0x21, SEGA 独自・Aime 非該当）。bring-up: 仮想化して open を成功させ、
       game の TX/RX 生バイトを観測する（フレーミング確証 → protocol logic 確定の順）。 */
    if (is_com(name, L"COM2") && !is_jvs_com(st, name)) {
        st->card_handle = (HANDLE)(uintptr_t)0xC0114003;   /* sentinel */
        card_init(&st->card);
        st->card_opened_logged = 0;
        st->host->log("info", "{\"ev\":\"card.open\",\"port\":\"COM2\"}");
        *handled = 1;
        return st->card_handle;
    }
    /* C:\System\SystemVersion.txt（amPlatformGetOsVersion 0x981d60 が読む）を仮想化。gate FUN_0045a6f0 は
       OsVersion の戻り 0 のみ要求し値は捨てる（直後の memory size 取得で上書き）。8 バイトが非ゼロ version に
       parse されれば DAT_00ccf44c!=0 → 戻り 0。standalone に実ファイルが無く欠損＝戻り -3→errCode 3 なので host で供給。 */
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

/* JVS 1 トランザクション(req+resp)をログ出力。連続同一フレームは dedup（READ_SW poll が ~60Hz で回るため、
 * idle 中は無音・入力やコマンドが変化したときだけ出る）。dedup 状態は ephemeral(reload でリセット可・診断用)。 */
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

/* WriteFile(COM4): 書込みバイトを 1 JVS フレームとして処理し応答をバッファ（同期: write 時に応答生成）。
 * 入力は毎フレーム poll → mxjvs_set_input でボードへ反映 → READ_SW 応答に乗る。native amJvst poll スレッドが
 * overlapped で write→read する（host が overlapped 完了をシグナル, hook.c）。JVS はマスタ駆動の req/resp なので
 * 「1 write=1 frame」同期で十分（logic にスレッドを持たず reload 安全）。実機 discovery〜polling 動作を実走確認済み。 */
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
        {   /* 診断: game が COM1 に何を書くか（handshake が動いているかの確証）*/
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
        {   /* 診断: game が COM2 に書く opcode 列（フレーミング確証用の核データ）*/
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
    if (h == st->touch_handle) {                  /* COM1: 現マウス位置→'T' フレームをストリーム */
        { HWND w = FindWindowW(NULL, L"WGL"); touch_sample_mouse(&st->touch, w ? w : GetForegroundWindow()); }
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

/* COM 制御傍受。仮想 COM(JVS)ハンドルなら成功を返す（amJvstThreadInit の comm-config を満たす）。
 * GetCommState 等は DCB を埋めなくてよい（ゲームは設定値を上書きするだけで読まない。micetools comdevice 同様）。 */
static BOOL on_comm_control(LogicState *st, HANDLE h, int op, void *p1, DWORD p2, void *p3, int *hd) {
    if (h == st->touch_handle) {
        /* COM1 タッチ: serial_open_comport(GetCommState→SetCommState→PurgeComm) と poll の COM 制御を
           全て成功化（micetools comdevice 同様、DCB は埋めなくてよい＝game は設定するだけで読まない）。 */
        (void)p2;
        *hd = 1;
        if (op == COMCTL_GET_MODEM_STATUS) { if (p1) *(DWORD *)p1 = 0; }       /* modem status = 0 */
        else if (op == COMCTL_CLEAR_ERROR) {
            /* serial RX ポンプ(FUN_0067c0c0)は ClearCommError の cbInQue!=0 のときだけ ReadFile する。
               touch はストリーミング型（panel が 'T' を常時送出）なので「常に 1 フレーム受信待ち」と申告し、
               ポンプに ReadFile を発行させる（→ on_read_file が現マウス座標の 'T' フレームを返す）。
               cbInQue=0 を返すと ReadFile が一度も来ず touch 入力がゼロになる。 */
            if (p1) *(DWORD *)p1 = 0;                                          /* errors = 0 */
            if (p3) { COMSTAT *cs = (COMSTAT *)p3; memset(cs, 0, sizeof *cs);
                      cs->cbInQue = TOUCH_FRAME_LEN; }                         /* 1 フレーム受信待ち */
        }
        return TRUE;
    }
    if (h == st->card_handle) {
        /* COM2 card: serial_open_comport の COM 制御を全成功化（DCB は埋めなくてよい）。
           card は request/response ゆえ CLEAR_ERROR の cbInQue は「キュー済み応答の残量」を申告する
           （touch の常時 1 フレームと違い、応答がある時だけ RX ポンプに ReadFile を発行させる）。 */
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
        /* JVS SENSE ライン = modem status の DSR ビットで伝える（micetools mxjvs_GetCommModemStatus 準拠）。
           sense=1(未割当/sense アサート)→0、sense=0(割当済み=チェーン終端)→MS_DSR_ON。
           これが無いとマスタは未割当機器が残ると誤認し SETADDR を無限に振り node 確定しない。 */
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

/* jvs_update_main PRE フック。
 * 注意: プレイヤ入力(sw/analog/coin)は **native JVS 経路(COM4)** で流れる — on_write_file が READ_SW 等の
 * 応答を mxjvs_set_input で組むので、ここでの node BSS 直書きは不要（旧 B 経路は撤去済み。詳細 facts/amjvs.md）。
 * 本フックは「毎フレーム必要な system 系上書き」だけを担う: 筐体 TEST/SERVICE(0x160194c) と free-play 保証。
 * （これらは JVS node とは別系統で、native JVS 化後も必要。） */
/* EEPROM(amBackup の area0,1=STATIC/CREDIT/NETWORK/HISTORY) 強制 provisioning。
 * 根本原因: amEepromCreateDeviceFile(0x984910) は SetupDi*(PnP GUID 列挙)+CreateFileA でデバイスを開くが、
 * standalone には mxsmbus の PnP デバイスが無く SetupDiEnumDeviceInterfaces 失敗 → デバイス未オープン →
 * amEepromInit(0x985160) 失敗（後始末 0x984bd0 が initFlag を 0 に戻す）→ EEPROM write fn(0x984E20) が
 * initFlag(0xccf4e0)==0 を見て -3 を返し続け、amBackupRecordWriteDup が洪水化（boot を塞ぐ）。
 * 名前ベースの mxsmbus エミュ(mxdev_create L"mxsmbus")はこの SetupDi 経路では一度もヒットしない。
 *
 * 対策: 実 amEepromInit が設定する eeprom ctx(base 0xccf4e0)を再現する。device handle を H_MXSMBUS にすると
 * read/write fn の DeviceIoControl(0x9c40200c, i2c@0x57)が既存 mxsmbus エミュ(mxdev_ioctl→eeprom.bin)へ流れる。
 * ctx レイアウト（amEepromInit 逆コンパイルで確定）:
 *   +0x00 initFlag / +0x04,+0x08 サイズ=6 / +0x0c mutex / +0x10 device handle / +0x14 i2c addr=0x57
 * on_jvs_tick は main loop（storage init 後）で回るので amEepromInit は既に試行済み＝initFlag==0 を見て安全に
 * 上書きできる（実 init 成功時は initFlag==1 で skip）。*/
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

/* dipsw ctx 強制 provisioning（board index 0xa/0xb の patches.c 0x45A0F5/F9 を置換）。
 * amDipswInit(0x9842a0) も amDipswCreateDeviceFile(0x983430) で SetupDi(PnP GUID 列挙)+CreateFileA を使うが、
 * standalone に mxsmbus PnP デバイスが無く列挙失敗 → handle(0xccf490)=-1。EEPROM と違い initFlag(0xccf488)は失敗時も 1。
 * すると amDipswReadByte(0x983bb0)が handle==-1 で即 return → dipsw byte 未読 → board index ゴミ → errCode 0xa/0xb。
 * ctx を再現すれば read fn の DeviceIoControl(0x9c402004,cmd=5)が既存 mxsmbus エミュ(mxdev_ioctl)へ流れ、index0=0x20
 * → board index=(0x20>>4)&7=2 を自然に得る（patch 不要）。ctx レイアウト（amDipswInit 逆コンパイルで確定, base 0xccf488）:
 *   +0x04 mutex / +0x08 handle / +0x0c smbus addr=0x20 / +0x38 busy=0 / +0x50 event / +0x00 initFlag */
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

/* ALL.Net / alAbEx keychip auth を「成功」詐称（network/matching 層が未実装のため）。
 * 根本原因: BBS は boot network SM `hlsm_boot_network_sm`(0x457FE0) で alAbEx auth 完了を要求し、
 * 未完だと attract から credit/card-auth scene へ進めない（"全国対戦の受付を終了しました" 既定状態）。
 * auth 完了の PROVEN gating reads（RE: facts/amnetwork 参照）を毎フレーム立てる:
 *   0x210AED0 session / 0x210AED2 auth_ok（→FUN_006ff650 auth ready）/ 0x210AED4 dlinstr /
 *   0x210B508 auth_complete / 0x16019A5 net_link_up / 0x16019A6 net_ip_match。
 * region errCode=4 は既存 NOP patch(0x459109/0x45A846, patches.c)で抑止済み。
 * ※経験的検証中: これで attract→entry/card-auth が開通するか live で確認（不可なら scene 側 guard を追う）。*/
static void network_auth_force_ready(LogicState *st) {
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    /* (1) alAbEx boot auth（subsys network:ok の前提。scene gate ではないが boot SM 充足）*/
    *(uint8_t *)(b + (0x210AED0u - 0x400000u)) = 1;   /* g_alabex_started */
    *(uint8_t *)(b + (0x210AED2u - 0x400000u)) = 1;   /* g_alabex_auth_ok */
    *(uint8_t *)(b + (0x210AED4u - 0x400000u)) = 1;   /* g_alabex_dlinstr_ok */
    *(uint8_t *)(b + (0x210B508u - 0x400000u)) = 1;   /* g_alabex_complete */
    *(uint8_t *)(b + (0x16019A5u - 0x400000u)) = 1;   /* g_net_link_up */
    *(uint8_t *)(b + (0x16019A6u - 0x400000u)) = 1;   /* g_net_ip_match */
    /* 注: MMGP input/service gate(DAT_0227fe6c|0x400 等)の強制は 2026-06-30 に試行→ gate は開いたが
       MMGP は state0 のまま不変（mmgp_diag で確認: credit scene が非 active で mmgp_request_start 未呼出）＝無効、
       かつ JVS 入力語を触り「メンテ countdown」副作用を誘発したため撤去。真の停止点は credit scene 活性化（上流の
       scene manager）。facts/gameflow.md 参照。*/
    if (!st->netauth_logged && st->host && st->host->log) {
        st->host->log("info", "{\"ev\":\"netauth.force_ready\",\"flags\":\"alabex(aed0/aed2/aed4/b508/19a5/19a6)\"}");
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

/* scene_va_name — task node の update slot(+0x24) VA → **nrs.exe 埋め込みの実 C++ クラス名**（RTTI 由来、
 * 推測ではない）。update VA はその scene クラスの vtable slot#2（仮想メソッド）の生アドレスなので、
 * vtable[-4]=COL → +0x0c=TypeDescriptor → +0x08=mangled name で実名を確定できる（裏取り: nrs.exe 直読、
 * EntryModeGamePoint/CheckCard を facts のライブ観測 VA と一致確認）。
 *   表は EntryMode* 系（attract→credit→card-auth entry flow の scene 群）。VA は static_VA。
 * ・継承で slot#2 を共有する組（Regist/UpdateBase/UpdateCard/VersionUp = 0x5ea0a0）は update VA だけでは
 *   一意化できないため意図的に未掲載（生 VA で出す。disambiguate は実行時 obj の RTTI 読みが要る）。
 * ・attract(0x7274d0)/net-session(0x6f42c0) は C++ scene クラスではない素の task callback で RTTI が無い
 *   → 実名が存在しないので名付けない（生 VA のまま）。捏造しない。 */
static const char *scene_va_name(unsigned va) {
    switch (va) {
        case 0x5e6200: return "EntryModeCheckCard";    /* COL 0xca9538 / vtbl 0xbb34bc（旧ラベル card-auth）*/
        case 0x5eaae0: return "EntryModeGamePoint";    /* COL 0xca9318 / vtbl 0xbb3584（旧ラベル credit, GP 入金）*/
        case 0x5e90b0: return "EntryModeNameEntry";    /* COL 0xca94a0 / vtbl 0xbb34ec */
        case 0x5e8710: return "EntryModeSelectChara";  /* COL 0xca94ec / vtbl 0xbb34d4 */
        case 0x5eb000: return "EntryModeDotNetRegist"; /* COL 0xca92cc / vtbl 0xbb359c */
        case 0x5ec340: return "EntryModePassword";     /* COL 0xca9234 / vtbl 0xbb35cc */
        case 0x5eb6b0: return "EntryModeReIssue";      /* COL 0xca9280 / vtbl 0xbb35b4 */
        case 0x62fb50: return "EntryModeBase";         /* COL 0xca9584 / vtbl 0xbb34a4（基底）*/
        default:       return 0;                        /* RTTI 未解決/非クラス → 生 VA で出す */
    }
}

/* scene_tag_fourcc — uid(tag) を ASCII FourCC へ。ゲーム自身が amTaskOpen の重複警告で
 * `uid=%08x(%s)` と出すのと同じ**低位バイト順**（DAT_02283014 = uid&0xff から）。
 * 非表示文字は '.'（JSON 安全のため " と \ も '.' に潰す）。例: 0x50474d4d→"MMGP", 0x45→"E...". */
static void scene_tag_fourcc(char out[5], unsigned tag) {
    for (int i = 0; i < 4; i++) {
        unsigned c = (tag >> (i * 8)) & 0xffu;
        out[i] = (c >= 0x20 && c < 0x7f && c != '"' && c != '\\') ? (char)c : '.';
    }
    out[4] = 0;
}

/* scene_node_json — delta の 1 エントリ。cls = 実 RTTI クラス名（無ければ null＝次の解析対象＝生 VA）、
 * tag = uid 生 hex、tag4 = uid を FourCC 文字列化（ゲーム公認のタグ表記。amTaskOpen 0x89dcb0 で裏取り）。 */
static int scene_node_json(char *dst, int cap, unsigned va, unsigned tag) {
    char fc[5]; scene_tag_fourcc(fc, tag);
    const char *cls = scene_va_name(va);
    (void)cap;
    if (cls) return wsprintfA(dst, "{\"va\":\"%x\",\"tag\":\"%x\",\"tag4\":\"%s\",\"cls\":\"%s\"}",
                              va, tag, fc, cls);
    return wsprintfA(dst, "{\"va\":\"%x\",\"tag\":\"%x\",\"tag4\":\"%s\",\"cls\":null}", va, tag, fc);
}

/* scene_diag — task/scene list(DAT_016db564) を walk し、各ノードの update vtable slot(+0x24) の VA を集める。
 * 目的: attract→credit→card-auth の scene 活性化を観測する。Phase B2 の停止点は「credit scene が非 active」
 * （gameflow.md 経験的検証）なので、touch 時に credit(0x5eaae0)/card-auth(0x5e6200) update fn を持つノードが
 * 生成・active 化されるかを直接見る。ノード: +4=uid tag / +8=flags(&1 active,&2 init,&4 remove) / +0x24=update / +0x3c=next。
 * 既知 scene update VA: attract=0x7274d0 / credit=0x5eaae0 / card-auth=0x5e6200。変化時＋約2秒毎にログ。 */
#define SCENE_CAP 64   /* active set ~35。診断 static の上限（超過分は切詰めて trunc を出す）*/
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
    /* scene.delta — active(va,tag) 多重集合を前フレームと diff。add/del を出し、未知 VA は生 hex で温存
     * （＝生成主を辿る次の Ghidra リード）。RE は「フレーム N で何が現れ／消えたか」で進むのでこれが主軸。
     * 35 ノードを目視 diff する摩擦を排し、各行を static_VA としてそのまま Ghidra に貼れる形にする。 */
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

/* 実マウス→消費側へ直接注入（SEGA の replay/debug 経路と同じ report_push 機構を自前で駆動）。
 * serial COM1 経路は game 内部の TX ワーカースレッド(FUN_0067c1a0)が touch ポートで動かず handshake 不全。
 * 一方、消費側 report バッファ +0x2b8 → report_promote(+0x30c dirty)→ +0x210/+0x234 は poll_update で毎フレーム
 * 処理される（mode 非依存）。よって +0x2b8 に「現マウス位置＋押下」を書き +0x30c=1 で消費側へ届ける。
 * ctx レイアウト（report_promote 0x8B37F0 逆コンパイルで確定）:
 *   +0x2b8[0]=press / +0x2b9,+0x2ba=down/move flags / +0x2dc(float)=X / +0x2e0(float)=Y → promote で +0x210/+0x234/+0x238
 * 座標空間は native(想定 1024x600)。窓 client(0..w/h)を native へスケール。要調整なら係数を変える。 */
static void touch_inject(LogicState *st) {
    /* 以前の実験で立てた amDebug_flag_hi(demo 自動入力)が残ると +0x2b8 を奪い合うので毎フレーム clear。 */
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

/* DirectInput / 951 診断: 起動時 dinput_create_device(0x67CBE0)が usbio_board_count を立てたか、
 * どの段で失敗して count=0(=Error 951)になるかを観測する。目的 = 951 を byte patch(0x6F0B80)ではなく
 * 実 SysMouse 供給で解消する前提調査（OS 境界仮想化・鉄則）。読み取り globals:
 *   usbio_board_count(0x16b88dc): dinput_create_device 成功数。<1 で usbio_io_status=-0x70→errCode 0xf→951。
 *   dinput_ctx(0x16f3a4c): IDirectInput8*（0 = DirectInput8Create 失敗）
 *   dev0/dev1(0x16f3a50/54): EnumDevices(DI8DEVCLASS_GAMECTRL)で埋まる joystick（不在なら 0）
 *   dinput_device2/mouse(0x16f3a58): CreateDevice(GUID_SysMouse)+SetDataFormat+SetCooperativeLevel 成功で非0
 *   hwnd(0x1696e0c): SetCooperativeLevel に渡すゲームウィンドウ HWND（0 = 未作成→SetCoopLevel が E_HANDLE で失敗）
 * 切り分け: ctx!=0 && mouse==0 && hwnd==0 → ウィンドウ未生成が原因。ctx!=0 && mouse==0 && hwnd!=0 → CreateDevice/環境。
 *          ctx==0 → DirectInput8Create 自体が失敗。 */
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

static void on_jvs_tick(LogicState *st) {
    const NrsConfig *cfg = st->host ? st->host->cfg : 0;
    NrsInput in; nrs_poll_input(&in, cfg ? cfg->bind : 0);

    dinput_diag(st);          /* DirectInput/951 状態観測（実 SysMouse 供給で 951 純正解消する前提調査）*/
    eeprom_force_ready(st);   /* EEPROM 未 provisioning なら provisioning（amBackup -3 洪水の解消）*/
    dipsw_force_ready(st);    /* dipsw ctx 未 provisioning なら provisioning（board index errCode 0xa/0xb の解消）*/
    network_auth_force_ready(st); /* ALL.Net alAbEx auth 成功詐称（attract→card-auth 開通の試験）*/
    mmgp_diag(st);            /* MMGP play-session 連鎖の診断（gate/state/txn のどこで止まるか確定）*/
    touch_diag(st);           /* touch device 内部状態の診断（serial→consumer 到達確認）*/
    scene_diag(st);           /* attract→credit→card-auth の scene 活性化を観測（Phase B2 停止点の切分け）*/

    /* touch_inject(st); — handshake 完了で device が mode1 動作するため bypass 注入は不要。
       実 serial 経路（on_read_file の 'T' フレーム→rx_parse→decode_T_coord）でタッチが流れる。 */

    /* 筐体 TEST/SERVICE を毎フレーム上書き（dipsw byte2=3 の常時 ON を入力で打ち消す。on_sys_override 相当だが
       on_sys_override(dipsw/sysinput hook)は attract 中に発火しない場合があるため、
       毎フレーム呼ばれる jvs_update_main でも DAT_0160194c bit0/1 を F1/F2 から書く。 */
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

    /* テストメニュー入口（実機 RE で確定・実測検証済み）:
       入口は 0x160194c(TEST スイッチ)ではなく scene システム。scene マネージャ scene_request_consume(0x6F0750)
       が毎フレーム要求 scene id DAT_016B8B54 を読み、≠-1 ならその scene を生成→ id を -1 へ戻す（ワンショット）。
       id=13 = テストモード容器 scene（enter cb open_test_menu 0x89DF80 → testmenu_tick 0x89E240 を生成）。
       通常は scene-init 0x6F06F0 が「DAT_016F5A9C!=0 のとき id=13 を要求」する。standalone はそのフラグが立たない
       ため入らない。ここで main ループ安定後（boot 完了後）に id=13 を一度だけ書いて入場させる。
       注: TEST は保持しない。メニュー内ナビはエッジ駆動で、保持するとホールドカウンタ誤発火で即退出するため
       （入場後の操作は実機同様 F1=TEST / F2=SERVICE のエッジ）。 */
    if (cfg && cfg->test_mode && !st->test_entered && st->sys_tick > 20) {
        *(uint32_t *)((uintptr_t)GetModuleHandleW(NULL) + (0x16B8B54u - 0x400000u)) = 13;  /* requested scene id */
        st->test_entered = 1;
        if (st->host && st->host->log) st->host->log("info", "{\"ev\":\"testmenu.enter\",\"scene\":13}");
    }

    /* 診断: この override(=sysinput 0x89B230 / dipsw 0x45A0E0 hook)が発火しているか（先頭3回のみ）*/
    if (st->sys_tick <= 3) {
        char m[120];
        wsprintfA(m, "{\"ev\":\"sys.ovr\",\"n\":%u,\"T\":%d,\"S\":%d,\"194c\":%u}", st->sys_tick, in.test, in.service, *p);
        if (st->host && st->host->log) st->host->log("info", m);
    }

}

/* keychip present flag hold（旧 mxkeychip/setup.js）: ctx(0xCCF000)+4 && +8 が非ゼロ＝真正 present の
 * とき keychip_present_flag(0x16014A2)=1 を保持（一方向ラッチの誤クリアを毎回打ち消す）。
 * 注: 真正 present 化には PCP サーバ(pcpa_server.py)移植が前提（未移植時は ctx 未認証で発火せず）。 */
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

/* amRtcGetServerTime POST（旧 amrtc/rtc.js 移植）。方針 = only-on-failure:
 * 実 RTC が応答(orig != -1)すればその値を温存、失敗(-1)のときだけ PC ローカル時刻で
 * amRtcTime 構造体を埋め成功(0)を返す。caller(amRtcGetServerTime 0x974040)は ret != -1 で成功判定。
 * 構造体レイアウトは converter amRtcConvertTimetToStruct(0x973F20)で確証:
 *   +0 WORD year / +2 BYTE month / +3 day / +4 hour / +5 minute / +6 second(60→59 クランプ) */
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

/* amEepromInit(0x985160) detour 本体: EEPROM ctx を storage-init の最中に provisioning する。
 * eeprom_force_ready を再利用（initFlag==0 の今だけ書く・冪等）。host 側 detour は本関数の後 0 を返し、
 * amlib_storage_init_all が amlib_eeprom_ok=1 で STATIC(area0) を読む → seed 済み region_game_pcb=01。
 * per-frame force（on_jvs_tick 経由）は init 後で遅すぎるため、ここで早期化する（force 側は冪等で no-op 化）。*/
static void on_eeprom_init(LogicState *st) {
    eeprom_force_ready(st);
}

/* dipsw read(0x45A0E0=amDipswRead) PRE detour 本体: dipsw ctx を読取の直前に provisioning する。
 * dipsw_force_ready を再利用（dipsw_fixed の冪等 one-shot）。board check(amlib_storage_board_check)が使う
 * board_index は amDipswRead が書くので、その読取前に ctx を H_MXSMBUS にしておけば IOCTL(cmd5,vcode0)→0x20
 * → index 2 → table[2]=8 で errCode 0xa(→errNo 910)を断つ。per-frame force(on_jvs_tick)は board check 後で遅い。*/
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
