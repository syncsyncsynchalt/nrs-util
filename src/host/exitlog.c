/* exitlog.c — 旧 app/exit.js 相当。ExitProcess / TerminateProcess / NtTerminateProcess を
 * フックして終了 code と呼出元(nrs+offset)をログ。nrs が「なぜ落ちる/終わるか」を特定する診断。 */
#include "host.h"
#include "MinHook.h"

USHORT WINAPI RtlCaptureStackBackTrace(ULONG, ULONG, PVOID *, PULONG);

static void (WINAPI *o_ExitProcess)(UINT);
static BOOL (WINAPI *o_TerminateProcess)(HANDLE, UINT);
static LONG (NTAPI  *o_NtTerminateProcess)(HANDLE, LONG);

static void log_exit(const char *who, unsigned code) {
    void *bt[10];
    USHORT n = RtlCaptureStackBackTrace(1, 10, bt, 0);
    uintptr_t base = (uintptr_t)GetModuleHandleW(NULL);
    char m[480];
    int o = wsprintfA(m, "{\"ev\":\"%s\",\"code\":%u,\"bt\":\"", who, code);
    for (USHORT i = 0; i < n && o < 440; i++) {
        uintptr_t a = (uintptr_t)bt[i];
        if (a >= base && a < base + 0x2200000) o += wsprintfA(m + o, "nrs+%X ", (unsigned)(a - base));
        else o += wsprintfA(m + o, "%p ", bt[i]);
    }
    wsprintfA(m + o, "\"}");
    host_log("warn", m);
}

static void WINAPI h_ExitProcess(UINT c) { log_exit("ExitProcess", c); o_ExitProcess(c); }
static BOOL WINAPI h_TerminateProcess(HANDLE h, UINT c) { log_exit("TerminateProcess", c); return o_TerminateProcess(h, c); }
static LONG NTAPI  h_NtTerminateProcess(HANDLE h, LONG s) { log_exit("NtTerminateProcess", (unsigned)s); return o_NtTerminateProcess(h, s); }

static void eh(LPCWSTR mod, LPCSTR fn, void *det, void **orig) {
    void *t = (void *)GetProcAddress(GetModuleHandleW(mod), fn);
    if (t && MH_CreateHook(t, det, orig) == MH_OK) MH_EnableHook(t);
}

void exitlog_install(void) {   /* MH_Initialize 済 */
    eh(L"kernel32", "ExitProcess",       (void *)h_ExitProcess,       (void **)&o_ExitProcess);
    eh(L"kernel32", "TerminateProcess",  (void *)h_TerminateProcess,  (void **)&o_TerminateProcess);
    eh(L"ntdll",    "NtTerminateProcess",(void *)h_NtTerminateProcess,(void **)&o_NtTerminateProcess);
}
