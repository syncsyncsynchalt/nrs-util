#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdint.h>

#define NRSEDGE_ABI_VERSION 6u

enum { ORIG_CREATE_FILE_W = 1, ORIG_CREATE_FILE_A, ORIG_READ_FILE, ORIG_WRITE_FILE,
       ORIG_DEVICE_IOCONTROL, ORIG_CLOSE_HANDLE, ORIG_SET_FILE_POINTER };

enum { COMCTL_GET_STATE = 1, COMCTL_SET_STATE, COMCTL_GET_TIMEOUTS, COMCTL_SET_TIMEOUTS,
       COMCTL_SETUP, COMCTL_PURGE, COMCTL_GET_MODEM_STATUS, COMCTL_CLEAR_ERROR };

enum { ACT_TEST, ACT_SERVICE, ACT_COIN, ACT_START, ACT_UP, ACT_DOWN, ACT_LEFT, ACT_RIGHT,
       ACT_JUMP, ACT_DASH, ACT_ACTION, ACT_COUNT };

typedef struct NrsConfig {
    int freeplay;
    int test_mode;
    int windowed;
    int jvs_com;
    unsigned short bind[ACT_COUNT];
} NrsConfig;

typedef struct HostServices {
    uint32_t abi_version;
    void  (*log)(const char *level, const char *json_line);
    void *(*arena_alloc)(size_t n);
    void *(*orig)(int orig_id);
    const NrsConfig *cfg;
} HostServices;

typedef struct LogicState LogicState;

typedef struct LogicApi {
    uint32_t abi_version;

    void (*bind)(HostServices *host, LogicState **state);

    HANDLE (*on_create_file)(LogicState *st, const wchar_t *name, DWORD access, DWORD share,
                             DWORD disp, DWORD flags, int *handled);
    BOOL (*on_read_file)(LogicState *st, HANDLE h, void *buf, DWORD n, DWORD *got, int *handled);
    BOOL (*on_write_file)(LogicState *st, HANDLE h, const void *buf, DWORD n, DWORD *put, int *handled);
    BOOL (*on_device_iocontrol)(LogicState *st, HANDLE h, DWORD code, void *in, DWORD inlen,
                                void *out, DWORD outlen, DWORD *ret, int *handled);
    BOOL (*on_close_handle)(LogicState *st, HANDLE h, int *handled);
    BOOL (*on_comm_control)(LogicState *st, HANDLE h, int op, void *p1, DWORD p2, void *p3, int *handled);
    DWORD (*on_set_file_pointer)(LogicState *st, HANDLE h, long dist, long *dist_high, DWORD method, int *handled);

    void (*on_jvs_tick)(LogicState *st);
    void (*on_sys_override)(LogicState *st);
    void (*on_keychip_hold)(LogicState *st);
    long long (*on_rtc_get)(LogicState *st, void *time_out, unsigned *flag_out, long long orig_ret);
    void (*on_eeprom_init)(LogicState *st);
    void (*on_dipsw_provision)(LogicState *st);

} LogicApi;

__declspec(dllexport) const LogicApi *logic_get_api(void);
