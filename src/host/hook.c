#include "host.h"
#include "MinHook.h"

static HANDLE (WINAPI *o_CreateFileW)(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
static HANDLE (WINAPI *o_CreateFileA)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
static BOOL   (WINAPI *o_ReadFile)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
static BOOL   (WINAPI *o_WriteFile)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
static BOOL   (WINAPI *o_DeviceIoControl)(HANDLE,DWORD,LPVOID,DWORD,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
static BOOL   (WINAPI *o_CloseHandle)(HANDLE);
static DWORD  (WINAPI *o_SetFilePointer)(HANDLE,LONG,PLONG,DWORD);
static BOOL   (WINAPI *o_GetCommState)(HANDLE,LPDCB);
static BOOL   (WINAPI *o_SetCommState)(HANDLE,LPDCB);
static BOOL   (WINAPI *o_GetCommTimeouts)(HANDLE,LPCOMMTIMEOUTS);
static BOOL   (WINAPI *o_SetCommTimeouts)(HANDLE,LPCOMMTIMEOUTS);
static BOOL   (WINAPI *o_SetupComm)(HANDLE,DWORD,DWORD);
static BOOL   (WINAPI *o_PurgeComm)(HANDLE,DWORD);
static BOOL   (WINAPI *o_GetCommModemStatus)(HANDLE,LPDWORD);
static BOOL   (WINAPI *o_ClearCommError)(HANDLE,LPDWORD,LPCOMSTAT);

void *host_orig(int id) {
    switch (id) {
        case ORIG_CREATE_FILE_W:     return (void *)o_CreateFileW;
        case ORIG_CREATE_FILE_A:     return (void *)o_CreateFileA;
        case ORIG_READ_FILE:         return (void *)o_ReadFile;
        case ORIG_WRITE_FILE:        return (void *)o_WriteFile;
        case ORIG_DEVICE_IOCONTROL:  return (void *)o_DeviceIoControl;
        case ORIG_CLOSE_HANDLE:      return (void *)o_CloseHandle;
        case ORIG_SET_FILE_POINTER:  return (void *)o_SetFilePointer;
        default: return 0;
    }
}

#define ENTER() AcquireSRWLockShared(&g_logic_lock)
#define LEAVE() ReleaseSRWLockShared(&g_logic_lock)

static HANDLE WINAPI h_CreateFileW(LPCWSTR name, DWORD a, DWORD s, LPSECURITY_ATTRIBUTES sa,
                                   DWORD d, DWORD f, HANDLE t) {
    int handled = 0; HANDLE r = INVALID_HANDLE_VALUE;
    ENTER();
    if (g_api && g_api->on_create_file) r = g_api->on_create_file(g_state, name, a, s, d, f, &handled);
    LEAVE();
    return handled ? r : o_CreateFileW(name, a, s, sa, d, f, t);
}
static HANDLE WINAPI h_CreateFileA(LPCSTR name, DWORD a, DWORD s, LPSECURITY_ATTRIBUTES sa,
                                   DWORD d, DWORD f, HANDLE t) {
    wchar_t w[260]; w[0] = 0;
    if (name) MultiByteToWideChar(CP_ACP, 0, name, -1, w, 260);
    int handled = 0; HANDLE r = INVALID_HANDLE_VALUE;
    ENTER();
    if (g_api && g_api->on_create_file) r = g_api->on_create_file(g_state, name ? w : 0, a, s, d, f, &handled);
    LEAVE();
    return handled ? r : o_CreateFileA(name, a, s, sa, d, f, t);
}
static BOOL WINAPI h_ReadFile(HANDLE h, LPVOID b, DWORD n, LPDWORD got, LPOVERLAPPED ov) {
    int handled = 0; BOOL r = FALSE; DWORD local = 0;
    ENTER();
    if (g_api && g_api->on_read_file) r = g_api->on_read_file(g_state, h, b, n, got ? got : &local, &handled);
    LEAVE();
    if (!handled) return o_ReadFile(h, b, n, got, ov);
    if (ov) { ov->Internal = 0; ov->InternalHigh = got ? *got : local; SetEvent(ov->hEvent); }
    return r;
}
static BOOL WINAPI h_WriteFile(HANDLE h, LPCVOID b, DWORD n, LPDWORD put, LPOVERLAPPED ov) {
    int handled = 0; BOOL r = FALSE; DWORD local = 0;
    ENTER();
    if (g_api && g_api->on_write_file) r = g_api->on_write_file(g_state, h, b, n, put ? put : &local, &handled);
    LEAVE();
    if (!handled) return o_WriteFile(h, b, n, put, ov);
    if (ov) { ov->Internal = 0; ov->InternalHigh = put ? *put : local; SetEvent(ov->hEvent); }
    return r;
}
static BOOL WINAPI h_DeviceIoControl(HANDLE h, DWORD c, LPVOID i, DWORD il, LPVOID o, DWORD ol,
                                     LPDWORD ret, LPOVERLAPPED ov) {
    int handled = 0; BOOL r = FALSE;
    ENTER();
    if (g_api && g_api->on_device_iocontrol) r = g_api->on_device_iocontrol(g_state, h, c, i, il, o, ol, ret, &handled);
    LEAVE();
    return handled ? r : o_DeviceIoControl(h, c, i, il, o, ol, ret, ov);
}
static BOOL WINAPI h_CloseHandle(HANDLE h) {
    int handled = 0; BOOL r = FALSE;
    ENTER();
    if (g_api && g_api->on_close_handle) r = g_api->on_close_handle(g_state, h, &handled);
    LEAVE();
    return handled ? r : o_CloseHandle(h);
}
static DWORD WINAPI h_SetFilePointer(HANDLE h, LONG dist, PLONG distHigh, DWORD method) {
    int handled = 0; DWORD r = INVALID_SET_FILE_POINTER;
    ENTER();
    if (g_api && g_api->on_set_file_pointer)
        r = g_api->on_set_file_pointer(g_state, h, dist, distHigh, method, &handled);
    LEAVE();
    return handled ? r : o_SetFilePointer(h, dist, distHigh, method);
}

#define COMCTL(call) \
    int hd = 0; BOOL r = FALSE; \
    ENTER(); if (g_api && g_api->on_comm_control) r = (call); LEAVE();
static BOOL WINAPI h_GetCommState(HANDLE h, LPDCB d) {
    COMCTL(g_api->on_comm_control(g_state, h, COMCTL_GET_STATE, d, 0, 0, &hd));
    return hd ? r : o_GetCommState(h, d);
}
static BOOL WINAPI h_SetCommState(HANDLE h, LPDCB d) {
    COMCTL(g_api->on_comm_control(g_state, h, COMCTL_SET_STATE, d, 0, 0, &hd));
    return hd ? r : o_SetCommState(h, d);
}
static BOOL WINAPI h_GetCommTimeouts(HANDLE h, LPCOMMTIMEOUTS t) {
    COMCTL(g_api->on_comm_control(g_state, h, COMCTL_GET_TIMEOUTS, t, 0, 0, &hd));
    return hd ? r : o_GetCommTimeouts(h, t);
}
static BOOL WINAPI h_SetCommTimeouts(HANDLE h, LPCOMMTIMEOUTS t) {
    COMCTL(g_api->on_comm_control(g_state, h, COMCTL_SET_TIMEOUTS, t, 0, 0, &hd));
    return hd ? r : o_SetCommTimeouts(h, t);
}
static BOOL WINAPI h_SetupComm(HANDLE h, DWORD in, DWORD out) {
    COMCTL(g_api->on_comm_control(g_state, h, COMCTL_SETUP, 0, in, (void *)(uintptr_t)out, &hd));
    return hd ? r : o_SetupComm(h, in, out);
}
static BOOL WINAPI h_PurgeComm(HANDLE h, DWORD flags) {
    COMCTL(g_api->on_comm_control(g_state, h, COMCTL_PURGE, 0, flags, 0, &hd));
    return hd ? r : o_PurgeComm(h, flags);
}
static BOOL WINAPI h_GetCommModemStatus(HANDLE h, LPDWORD st) {
    COMCTL(g_api->on_comm_control(g_state, h, COMCTL_GET_MODEM_STATUS, st, 0, 0, &hd));
    return hd ? r : o_GetCommModemStatus(h, st);
}
static BOOL WINAPI h_ClearCommError(HANDLE h, LPDWORD err, LPCOMSTAT stat) {
    COMCTL(g_api->on_comm_control(g_state, h, COMCTL_CLEAR_ERROR, err, 0, stat, &hd));
    return hd ? r : o_ClearCommError(h, err, stat);
}
#undef COMCTL

static int hook(LPCWSTR mod, LPCSTR fn, void *det, void **orig) {
    void *tgt = (void *)GetProcAddress(GetModuleHandleW(mod), fn);
    return tgt && MH_CreateHook(tgt, det, orig) == MH_OK && MH_EnableHook(tgt) == MH_OK ? 0 : -1;
}

int hooks_install(void) {
    if (MH_Initialize() != MH_OK) return -1;
    int e = 0;
    e |= hook(L"kernel32", "CreateFileW",     h_CreateFileW,     (void **)&o_CreateFileW);
    e |= hook(L"kernel32", "CreateFileA",     h_CreateFileA,     (void **)&o_CreateFileA);
    e |= hook(L"kernel32", "ReadFile",        h_ReadFile,        (void **)&o_ReadFile);
    e |= hook(L"kernel32", "WriteFile",       h_WriteFile,       (void **)&o_WriteFile);
    e |= hook(L"kernel32", "DeviceIoControl", h_DeviceIoControl, (void **)&o_DeviceIoControl);
    e |= hook(L"kernel32", "CloseHandle",     h_CloseHandle,     (void **)&o_CloseHandle);
    e |= hook(L"kernel32", "SetFilePointer",  h_SetFilePointer,  (void **)&o_SetFilePointer);
    e |= hook(L"kernel32", "GetCommState",      h_GetCommState,      (void **)&o_GetCommState);
    e |= hook(L"kernel32", "SetCommState",      h_SetCommState,      (void **)&o_SetCommState);
    e |= hook(L"kernel32", "GetCommTimeouts",   h_GetCommTimeouts,   (void **)&o_GetCommTimeouts);
    e |= hook(L"kernel32", "SetCommTimeouts",   h_SetCommTimeouts,   (void **)&o_SetCommTimeouts);
    e |= hook(L"kernel32", "SetupComm",         h_SetupComm,         (void **)&o_SetupComm);
    e |= hook(L"kernel32", "PurgeComm",         h_PurgeComm,         (void **)&o_PurgeComm);
    e |= hook(L"kernel32", "GetCommModemStatus",h_GetCommModemStatus,(void **)&o_GetCommModemStatus);
    e |= hook(L"kernel32", "ClearCommError",    h_ClearCommError,    (void **)&o_ClearCommError);
    return e;
}
