#include "host.h"
#include "MinHook.h"
#include <stdio.h>
#include <stdarg.h>

#define IMAGE_BASE 0x400000u

static int (__fastcall *o_dbg_sink)(unsigned level, const char *msg);

static void (*o_dbg_init)(void);
static void __cdecl d_dbg_init(void) {
    o_dbg_init();
    uintptr_t base = (uintptr_t)GetModuleHandleW(NULL);
    *(volatile int *)     (base + (0x1696F38 - IMAGE_BASE)) = 0x7FFFFFFF;
    *(volatile unsigned *)(base + (0x1696F3C - IMAGE_BASE)) = 0xFFFFFFFF;
}

static void json_escape(const char *s, char *out, size_t cap) {
    size_t o = 0;
    for (; s && *s && o + 7 < cap; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '"':  out[o++] = '\\'; out[o++] = '"';  break;
            case '\\': out[o++] = '\\'; out[o++] = '\\'; break;
            case '\n': out[o++] = '\\'; out[o++] = 'n';  break;
            case '\r': out[o++] = '\\'; out[o++] = 'r';  break;
            case '\t': out[o++] = '\\'; out[o++] = 't';  break;
            default:
                if (c < 0x20) o += (size_t)_snprintf(out + o, cap - o, "\\u%04x", c);
                else          out[o++] = (char)c;
        }
    }
    out[o] = 0;
}

static const char *lvl_of(unsigned sev, const char *msg) {
    if (sev <= 1) return "error";
    if (sev <= 3) return "warn";
    return "info";
}

static void emit_game(unsigned level, int raw, const char *msg) {
    if (!msg) return;
    char buf[1100], esc[2200], line[2400];
    size_t n = 0;
    while (msg[n] && n < sizeof buf - 1) n++;
    while (n && (msg[n - 1] == '\n' || msg[n - 1] == '\r')) n--;
    memcpy(buf, msg, n); buf[n] = 0;
    if (!buf[0]) return;

    json_escape(buf, esc, sizeof esc);
    unsigned sev = level & 7;
    _snprintf(line, sizeof line,
              "{\"ev\":\"game\",\"sys\":\"%s\",\"lv\":%u,\"msg\":\"%s\"}",
              raw ? "raw" : "lvl", sev, esc);
    line[sizeof line - 1] = 0;
    host_log(raw ? "info" : lvl_of(sev, buf), line);
}

static int __fastcall d_dbg_sink(unsigned level, const char *msg) {
    emit_game(level, 0, msg);
    (void)o_dbg_sink;
    return 1;
}

static int (__cdecl *o_write)(int fd, const void *buf, unsigned cnt);
static int __cdecl d_write(int fd, const void *buf, unsigned cnt) {
    if ((fd == 1 || fd == 2) && buf && cnt) {
        char raw[1100], esc[2200], line[2500];
        unsigned n = cnt < sizeof raw - 1 ? cnt : (unsigned)(sizeof raw - 1);
        memcpy(raw, buf, n);
        while (n && (raw[n - 1] == '\n' || raw[n - 1] == '\r')) n--;
        raw[n] = 0;
        if (raw[0]) {
            json_escape(raw, esc, sizeof esc);
            _snprintf(line, sizeof line, "{\"ev\":\"stdio\",\"fd\":%d,\"msg\":\"%s\"}", fd, esc);
            line[sizeof line - 1] = 0;
            host_log("info", line);
        }
    }
    return o_write(fd, buf, cnt);
}

static void __cdecl d_dbg_out(const char *fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    _vsnprintf(buf, sizeof buf, fmt ? fmt : "", ap);
    va_end(ap);
    buf[sizeof buf - 1] = 0;
    emit_game(0, 1, buf);
}

#define SEH_CTX_VA   0x1600B90u
#define SEH_LEN_OFF  0xA4
#define SEH_TXT_OFF  0xAC
static void (__cdecl *o_seh_frame)(void *frame);
static void __cdecl d_seh_frame(void *frame) {
    o_seh_frame(frame);
    uintptr_t ctx = (uintptr_t)GetModuleHandleW(NULL) + (SEH_CTX_VA - IMAGE_BASE);
    int len = *(volatile int *)(ctx + SEH_LEN_OFF);
    if (len > 0 && len < 0x400) {
        char raw[0x404], esc[0x810], line[0x880];
        memcpy(raw, (const char *)(ctx + SEH_TXT_OFF), (unsigned)len);
        raw[len] = 0;
        while (len && (raw[len - 1] == ' ' || raw[len - 1] == '\n' || raw[len - 1] == '\r'))
            raw[--len] = 0;
        if (raw[0]) {
            json_escape(raw, esc, sizeof esc);
            _snprintf(line, sizeof line, "{\"ev\":\"crash\",\"msg\":\"%s\"}", esc);
            line[sizeof line - 1] = 0;
            host_log("error", line);
        }
    }
}

static int hk(unsigned va, void *det, void **orig) {
    void *a = (void *)((uintptr_t)GetModuleHandleW(NULL) + (va - IMAGE_BASE));
    return (MH_CreateHook(a, det, orig) == MH_OK && MH_EnableHook(a) == MH_OK) ? 0 : -1;
}

void dbglog_install(void) {
    int e = 0;
    e |= hk(0x55C500, (void *)d_dbg_init, (void **)&o_dbg_init);
    e |= hk(0x55C800, (void *)d_dbg_sink, (void **)&o_dbg_sink);
    e |= hk(0x55C7E0, (void *)d_dbg_out,  0);
    e |= hk(0xA823A3, (void *)d_write,    (void **)&o_write);
    e |= hk(0x456900, (void *)d_seh_frame, (void **)&o_seh_frame);
    host_log(e ? "warn" : "info",
             e ? "{\"ev\":\"dbglog.partial\"}" : "{\"ev\":\"dbglog.hooks\"}");
}
