/* abi.h — host(安定) ↔ logic(差し替え) の唯一の契約。
 *
 * 依存規律（CLAUDE.md）:
 *   - host は logic を `logic_get_api()` の関数テーブル経由でのみ呼ぶ。
 *   - logic は host を HostServices vtable 経由でのみ呼ぶ（名前で直接呼ばない）。
 *   - 状態は host 所有の arena に置く。logic は永続 global を持たない。
 *   - この abi.h を変えたら host+logic 両方を再ビルドし restart（hot-reload 不可）。それ以外は reload 可。
 */
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN   /* winsock.h を排除（bind 等の名前衝突回避。PCP は後で winsock2 を明示 include） */
#endif
#include <windows.h>
#include <stdint.h>

#define NRSEDGE_ABI_VERSION 4u   /* v4: on_set_file_pointer 追加（mxsram データ面: SetFilePointer 位置決め）*/

/* host が hook している原関数(トランプリン)の識別子。logic は services->orig(id) で呼び戻す。 */
enum { ORIG_CREATE_FILE_W = 1, ORIG_CREATE_FILE_A, ORIG_READ_FILE, ORIG_WRITE_FILE,
       ORIG_DEVICE_IOCONTROL, ORIG_CLOSE_HANDLE, ORIG_SET_FILE_POINTER };

/* COM 制御 API（host が傍受。仮想 COM ハンドルなら logic の on_comm_control へ委譲し成功を返す）。
 * native JVS 経路(amJvstThreadInit)は GetCommState→SetCommState→SetCommTimeouts→SetupComm→PurgeComm が
 * 全て成功しないと init を中断するため、仮想ポートでこれらを TRUE 化する必要がある（micetools comdevice 準拠）。*/
enum { COMCTL_GET_STATE = 1, COMCTL_SET_STATE, COMCTL_GET_TIMEOUTS, COMCTL_SET_TIMEOUTS,
       COMCTL_SETUP, COMCTL_PURGE, COMCTL_GET_MODEM_STATUS, COMCTL_CLEAR_ERROR };

/* 入力アクション（GUI 入力設定/テストと config.bind[] の index）。NrsInput と対応。 */
enum { ACT_TEST, ACT_SERVICE, ACT_COIN, ACT_START, ACT_UP, ACT_DOWN, ACT_LEFT, ACT_RIGHT,
       ACT_JUMP, ACT_DASH, ACT_ACTION, ACT_COUNT };

/* 統合 GUI(loader.exe)が nrsedge.cfg に書き host が読む実行時設定。 */
typedef struct NrsConfig {
    int freeplay;                    /* free-play flag 強制 */
    int test_mode;                   /* TEST スイッチ常時 ON（テストメニュー起動）*/
    int windowed;                    /* ウィンドウモード化 */
    int jvs_com;                     /* JVS が開く COM 番号（既定 4）。0xAE11F0 文字列パッチ + is_com マッチに連動 */
    unsigned short bind[ACT_COUNT];  /* 各アクションの Win32 VK コード */
} NrsConfig;

/* host が logic に提供するサービス（logic→host の唯一経路） */
typedef struct HostServices {
    uint32_t abi_version;
    void  (*log)(const char *level, const char *json_line); /* 構造化ログ(JSONL) */
    void *(*arena_alloc)(size_t n);                          /* host 所有・reload を跨いで生存 */
    void *(*orig)(int orig_id);                              /* 原 Win32 関数ポインタ取得 */
    const NrsConfig *cfg;                                    /* 実行時設定（host 所有・GUI が nrsedge.cfg で指定）*/
} HostServices;

/* logic 永続状態。host からは不透明（arena に置く）。型変更=restart。 */
typedef struct LogicState LogicState;

/* host→logic 呼び出しテーブル。各 on_* は handled=1 を立てたら host は原関数を呼ばない。 */
typedef struct LogicApi {
    uint32_t abi_version;

    /* 初回ロード／reload 後に呼ぶ。state==NULL なら新規確保し *state に格納、既存なら再バインド。 */
    void (*bind)(HostServices *host, LogicState **state);

    /* ---- driver 層: シリアル/COM + DeviceIoControl 境界 ---- */
    /* CreateFileW 傍受。name が仮想デバイス(COM1/2/4 等)なら擬似 HANDLE を返し *handled=1。 */
    HANDLE (*on_create_file)(LogicState *st, const wchar_t *name, DWORD access, DWORD share,
                             DWORD disp, DWORD flags, int *handled);
    BOOL (*on_read_file)(LogicState *st, HANDLE h, void *buf, DWORD n, DWORD *got, int *handled);
    BOOL (*on_write_file)(LogicState *st, HANDLE h, const void *buf, DWORD n, DWORD *put, int *handled);
    BOOL (*on_device_iocontrol)(LogicState *st, HANDLE h, DWORD code, void *in, DWORD inlen,
                                void *out, DWORD outlen, DWORD *ret, int *handled);
    BOOL (*on_close_handle)(LogicState *st, HANDLE h, int *handled);
    /* COM 制御傍受。op=COMCTL_*。p1/p2/p3 は操作別引数（GetCommState→p1=LPDCB, SetupComm→p2=in/p3=out 等）。
       仮想 COM ハンドルなら *handled=1 と戻り値(BOOL)を確定。overlapped は read/write 同様 host が処理。 */
    BOOL (*on_comm_control)(LogicState *st, HANDLE h, int op, void *p1, DWORD p2, void *p3, int *handled);
    /* SetFilePointer 傍受。仮想ブロックデバイス(mxsram)ハンドルなら *handled=1 とし新ポインタ(low DWORD)を返す。
       実 RingEdge では amSram が SetFilePointer(handle, recordAddr, FILE_BEGIN)→ReadFile/WriteFile で記録を
       読み書きする（mxsram.sys IRP_MJ_READ が ByteOffset で memcard0 を読む実装と一致）。method=FILE_BEGIN/CURRENT/END。
       dist_high は 32bit デバイスにつき未使用（あれば 0 を書く）。 */
    DWORD (*on_set_file_pointer)(LogicState *st, HANDLE h, long dist, long *dist_high, DWORD method, int *handled);

    /* ---- game-function hooks（host が VA で hook。detour は安定 host 側、reload-safe に g_api 経由） ---- */
    void (*on_jvs_tick)(LogicState *st);      /* jvs_update_main(0x67B150) PRE: node BSS を入力で書く（旧 input.js）*/
    void (*on_sys_override)(LogicState *st);  /* dipsw read(0x45A0E0) 後 / sysinput(0x89B230) 前: DAT_0160194c TEST/SERVICE 上書き */
    void (*on_keychip_hold)(LogicState *st);  /* keychip_errCode1_latcher(0x6F0A80) PRE: 真正present時に keychip_present_flag=1 保持（旧 setup.js）*/
    /* amRtcGetServerTime(0x974040, __stdcall, longlong 戻り) POST: 実 RTC 失敗(orig==-1)時のみ PC ローカル時刻で
       amRtcTime 構造体(year@0 WORD/month@2/day@3/hour@4/min@5/sec@6, converter 0x973F20 で確証)を埋め成功(≠-1)を返す。
       戻り値が detour の返り値になる。実 RTC が応答すれば温存（旧 amrtc/rtc.js, only-on-failure）。 */
    long long (*on_rtc_get)(LogicState *st, void *time_out, unsigned *flag_out, long long orig_ret);

    /* ---- system 層(PCP/TCP): フックは段階的に追加（P5） ---- */
    /* TODO: on_socket / on_pcp_exchange 等 */
} LogicApi;

/* logic.dll の唯一の export */
__declspec(dllexport) const LogicApi *logic_get_api(void);
