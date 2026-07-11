/* abi.h — host(安定) ↔ logic(差し替え) の唯一の契約。
 * host→logic は logic_get_api() テーブル、logic→host は HostServices vtable のみ。
 * 状態は host 所有 arena（logic は永続 global 禁止）。この abi.h 変更時は host+logic 再ビルド+restart。 */
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN   /* winsock.h の bind 等と衝突回避 */
#endif
#include <windows.h>
#include <stdint.h>

#define NRSEDGE_ABI_VERSION 6u

/* host が hook している原関数(トランプリン)の識別子。logic は services->orig(id) で呼び戻す。 */
enum { ORIG_CREATE_FILE_W = 1, ORIG_CREATE_FILE_A, ORIG_READ_FILE, ORIG_WRITE_FILE,
       ORIG_DEVICE_IOCONTROL, ORIG_CLOSE_HANDLE, ORIG_SET_FILE_POINTER };

/* COM 制御 op。amJvstThreadInit は GetCommState/SetCommState/SetCommTimeouts/SetupComm/PurgeComm が
 * 全成功しないと init 中断するため、仮想ポートで TRUE 化する。 */
enum { COMCTL_GET_STATE = 1, COMCTL_SET_STATE, COMCTL_GET_TIMEOUTS, COMCTL_SET_TIMEOUTS,
       COMCTL_SETUP, COMCTL_PURGE, COMCTL_GET_MODEM_STATUS, COMCTL_CLEAR_ERROR };

/* 入力アクション。config.bind[] の index。 */
enum { ACT_TEST, ACT_SERVICE, ACT_COIN, ACT_START, ACT_UP, ACT_DOWN, ACT_LEFT, ACT_RIGHT,
       ACT_JUMP, ACT_DASH, ACT_ACTION, ACT_COUNT };

/* GUI が nrsedge.cfg に書き host が読む実行時設定。 */
typedef struct NrsConfig {
    int freeplay;
    int test_mode;                   /* TEST スイッチ常時 ON */
    int windowed;
    int jvs_com;                     /* JVS が開く COM 番号（既定 4）。0xAE11F0 文字列パッチと連動 */
    unsigned short bind[ACT_COUNT];  /* Win32 VK コード */
} NrsConfig;

/* logic→host の唯一経路。 */
typedef struct HostServices {
    uint32_t abi_version;
    void  (*log)(const char *level, const char *json_line);
    void *(*arena_alloc)(size_t n);   /* reload を跨いで生存 */
    void *(*orig)(int orig_id);       /* 原 Win32 関数ポインタ */
    const NrsConfig *cfg;
} HostServices;

/* logic 永続状態。host からは不透明（arena）。型変更=restart。 */
typedef struct LogicState LogicState;

/* on_* は handled=1 を立てたら host は原関数を呼ばない。 */
typedef struct LogicApi {
    uint32_t abi_version;

    /* 初回ロード／reload 後。*state==NULL なら新規確保、既存なら再バインド。 */
    void (*bind)(HostServices *host, LogicState **state);

    /* ---- driver 層: シリアル/COM + DeviceIoControl 境界 ---- */
    /* name が仮想デバイス(COM1/2/4 等)なら擬似 HANDLE を返し *handled=1。 */
    HANDLE (*on_create_file)(LogicState *st, const wchar_t *name, DWORD access, DWORD share,
                             DWORD disp, DWORD flags, int *handled);
    BOOL (*on_read_file)(LogicState *st, HANDLE h, void *buf, DWORD n, DWORD *got, int *handled);
    BOOL (*on_write_file)(LogicState *st, HANDLE h, const void *buf, DWORD n, DWORD *put, int *handled);
    BOOL (*on_device_iocontrol)(LogicState *st, HANDLE h, DWORD code, void *in, DWORD inlen,
                                void *out, DWORD outlen, DWORD *ret, int *handled);
    BOOL (*on_close_handle)(LogicState *st, HANDLE h, int *handled);
    /* op=COMCTL_*。p1/p2/p3 は操作別引数（GetCommState→p1=LPDCB, SetupComm→p2=in/p3=out）。 */
    BOOL (*on_comm_control)(LogicState *st, HANDLE h, int op, void *p1, DWORD p2, void *p3, int *handled);
    /* mxsram ハンドルなら *handled=1 とし新ポインタ(low DWORD)を返す。amSram が SetFilePointer→ReadFile/WriteFile
       で記録を読み書き。dist_high は 32bit デバイスにつき未使用。 */
    DWORD (*on_set_file_pointer)(LogicState *st, HANDLE h, long dist, long *dist_high, DWORD method, int *handled);

    /* ---- game-function hooks（host が VA で hook。detour は host 側、reload-safe に g_api 経由） ---- */
    void (*on_jvs_tick)(LogicState *st);      /* jvs_update_main(0x67B150) PRE: node BSS を入力で書く */
    void (*on_sys_override)(LogicState *st);  /* input_process_to_gamestate(0x89B230) 前: DAT_0160194c TEST/SERVICE 上書き */
    void (*on_keychip_hold)(LogicState *st);  /* keychip_errCode1_latcher(0x6F0A80) PRE: 真正present時に keychip_present_flag=1 保持 */
    /* amRtcGetServerTime(0x974040, __stdcall) POST: 実 RTC 失敗(orig==-1)時のみ PC ローカル時刻で amRtcTime 構造体
       (year@0 WORD/month@2/day@3/hour@4/min@5/sec@6)を埋め成功(≠-1)を返す。戻り値が detour の返り値。詳細 facts/amrtc.md。 */
    long long (*on_rtc_get)(LogicState *st, void *time_out, unsigned *flag_out, long long orig_ret);
    /* amEepromInit(0x985160) 内で EEPROM ctx を早期 provisioning（standalone では SetupDi 列挙失敗→Error 0903 になる）。
       成功後 genuine な amBackupRead(STATIC) が seed 済み region を読む。詳細 facts/mxdrivers.md。 */
    void (*on_eeprom_init)(LogicState *st);
    /* amDipswRead(0x45A0E0) PRE: 読取直前に dipsw ctx を H_MXSMBUS へ provisioning。standalone では board_index が
       ゴミ→table 誤判定→errCode 0xa→errNo 910。provisioning で IOCTL(cmd5,vcode0)→0x20, index=2, table[2]=8。詳細 facts/devices.md。 */
    void (*on_dipsw_provision)(LogicState *st);

    /* ---- system 層(PCP/TCP): host 側実装。TODO: on_socket / on_pcp_exchange ---- */
} LogicApi;

/* logic.dll の唯一の export */
__declspec(dllexport) const LogicApi *logic_get_api(void);
