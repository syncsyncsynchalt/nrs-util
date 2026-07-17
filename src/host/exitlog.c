#include "host.h"
#include "MinHook.h"

USHORT WINAPI RtlCaptureStackBackTrace(ULONG, ULONG, PVOID *, PULONG);

static void (WINAPI *o_ExitProcess)(UINT);
static BOOL (WINAPI *o_TerminateProcess)(HANDLE, UINT);
static LONG (NTAPI  *o_NtTerminateProcess)(HANDLE, LONG);

static int resolve_mod(uintptr_t a, char *buf) {
    HMODULE mod = NULL;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)a, &mod) && mod) {
        wchar_t path[MAX_PATH];
        if (GetModuleFileNameW(mod, path, MAX_PATH)) {
            const wchar_t *bn = path;
            for (const wchar_t *p = path; *p; p++) if (*p == L'\\' || *p == L'/') bn = p + 1;
            char nm[64]; int j = 0;
            for (; bn[j] && j < 63; j++) nm[j] = (char)bn[j];
            nm[j] = 0;
            return wsprintfA(buf, "%s+%X", nm, (unsigned)(a - (uintptr_t)mod));
        }
    }
    return wsprintfA(buf, "%p", (void *)a);
}

static void log_exit(const char *who, unsigned code) {
    void *bt[10];
    USHORT n = RtlCaptureStackBackTrace(1, 10, bt, 0);
    char m[640];
    int o = wsprintfA(m, "{\"ev\":\"%s\",\"code\":%u,\"bt\":\"", who, code);
    for (USHORT i = 0; i < n && o < 560; i++) {
        char f[80]; resolve_mod((uintptr_t)bt[i], f);
        o += wsprintfA(m + o, "%s ", f);
    }
    wsprintfA(m + o, "\"}");
    host_log("warn", m);
}

static LONG NTAPI veh_handler(EXCEPTION_POINTERS *ep) {
    static volatile LONG count = 0;
    if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_STACK_OVERFLOW ||
        code == EXCEPTION_ILLEGAL_INSTRUCTION || code == EXCEPTION_PRIV_INSTRUCTION ||
        code == EXCEPTION_INT_DIVIDE_BY_ZERO) {
        if (InterlockedIncrement(&count) <= 60) {
            char at[96]; resolve_mod((uintptr_t)ep->ExceptionRecord->ExceptionAddress, at);
            unsigned acc = 0, va = 0;
            if (code == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters >= 2) {
                acc = (unsigned)ep->ExceptionRecord->ExceptionInformation[0];
                va  = (unsigned)ep->ExceptionRecord->ExceptionInformation[1];
            }
            char chain[200]; int co = 0; chain[0] = 0;
            if (ep->ContextRecord) {
                HMODULE mainmod = GetModuleHandleW(NULL);
                uintptr_t *sp = (uintptr_t *)(uintptr_t)ep->ContextRecord->Esp;
                int found = 0;
                for (int i = 0; i < 512 && found < 6 && co < 170; i++) {
                    uintptr_t v = 0;
                    __try { v = sp[i]; } __except (EXCEPTION_EXECUTE_HANDLER) { break; }
                    HMODULE m = NULL;
                    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                           (LPCWSTR)v, &m) && m == mainmod) {
                        co += wsprintfA(chain + co, "%X,", (unsigned)(v - (uintptr_t)mainmod));
                        found++;
                    }
                }
            }
            char m[360];
            wsprintfA(m, "{\"ev\":\"veh\",\"code\":\"%X\",\"at\":\"%s\",\"acc\":%u,\"va\":\"%X\",\"nrs\":\"%s\"}",
                      (unsigned)code, at, acc, va, chain);
            host_log("error", m);
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void WINAPI h_ExitProcess(UINT c) { log_exit("ExitProcess", c); o_ExitProcess(c); }
static BOOL WINAPI h_TerminateProcess(HANDLE h, UINT c) { log_exit("TerminateProcess", c); return o_TerminateProcess(h, c); }
static LONG NTAPI  h_NtTerminateProcess(HANDLE h, LONG s) { log_exit("NtTerminateProcess", (unsigned)s); return o_NtTerminateProcess(h, s); }

static void eh(LPCWSTR mod, LPCSTR fn, void *det, void **orig) {
    void *t = (void *)GetProcAddress(GetModuleHandleW(mod), fn);
    if (t && MH_CreateHook(t, det, orig) == MH_OK) MH_EnableHook(t);
}

void exitlog_install(void) {
    AddVectoredExceptionHandler(1, veh_handler);
    eh(L"kernel32", "ExitProcess",       (void *)h_ExitProcess,       (void **)&o_ExitProcess);
    eh(L"kernel32", "TerminateProcess",  (void *)h_TerminateProcess,  (void **)&o_TerminateProcess);
    eh(L"ntdll",    "NtTerminateProcess",(void *)h_NtTerminateProcess,(void **)&o_NtTerminateProcess);
}
