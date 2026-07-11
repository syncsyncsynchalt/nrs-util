/* netobs.c — winsock connect/resolve の passive 観測（log→原関数、挙動は変えない）。詳細 facts/ambilling.md。
 *   billing(alpbEx)は "ib.naominet.jp" DNS 失敗で :8443 connect に至らず、実トラフィックは keychip_server の
 *   localhost PCPA 群 40100–40113。接続先を可視化する診断用。
 * 前提: MinHook は hooks_install()→MH_Initialize() 済み。host.c は hooks.ok の後で netobs_install を呼ぶ。 */
#include "host.h"
#include <winsock2.h>   /* WIN32_LEAN_AND_MEAN(abi.h)で winsock.h は排除済み→衝突なし */
#include <ws2tcpip.h>
#include <stdio.h>      /* _snprintf */
#include "MinHook.h"

static int             (WINAPI *o_connect)(SOCKET, const struct sockaddr *, int);
static int             (WINAPI *o_getaddrinfo)(PCSTR, PCSTR, const ADDRINFOA *, PADDRINFOA *);
static struct hostent *(WINAPI *o_gethostbyname)(const char *);

/* JSON 文字列値を最小エスケープ（"..."付き）。 */
static void json_str(char *dst, size_t cap, const char *s) {
    size_t j = 0;
    if (cap < 3) { if (cap) dst[0] = 0; return; }
    dst[j++] = '"';
    for (size_t i = 0; s && s[i] && j + 2 < cap; i++) {
        char c = s[i];
        if (c == '"' || c == '\\') { dst[j++] = '\\'; dst[j++] = c; }
        else if ((unsigned char)c >= 0x20) dst[j++] = c;
    }
    dst[j++] = '"';
    dst[j] = 0;
}

static int WINAPI h_connect(SOCKET s, const struct sockaddr *addr, int len) {
    char msg[160];
    if (addr && addr->sa_family == AF_INET) {
        const struct sockaddr_in *si = (const struct sockaddr_in *)addr;
        const unsigned char *ip = (const unsigned char *)&si->sin_addr;
        _snprintf(msg, sizeof msg,
                  "{\"ev\":\"net.connect\",\"ip\":\"%u.%u.%u.%u\",\"port\":%u}",
                  ip[0], ip[1], ip[2], ip[3], (unsigned)ntohs(si->sin_port));
    } else {
        _snprintf(msg, sizeof msg, "{\"ev\":\"net.connect\",\"af\":%d}", addr ? addr->sa_family : -1);
    }
    msg[sizeof msg - 1] = 0;
    host_log("info", msg);
    return o_connect(s, addr, len);
}

static int WINAPI h_getaddrinfo(PCSTR node, PCSTR svc, const ADDRINFOA *hints, PADDRINFOA *res) {
    char nb[128], sb[48], msg[224];
    json_str(nb, sizeof nb, node ? node : "");
    json_str(sb, sizeof sb, svc ? svc : "");
    _snprintf(msg, sizeof msg, "{\"ev\":\"net.resolve\",\"node\":%s,\"svc\":%s}", nb, sb);
    msg[sizeof msg - 1] = 0;
    host_log("info", msg);
    return o_getaddrinfo(node, svc, hints, res);
}

static struct hostent *WINAPI h_gethostbyname(const char *name) {
    char nb[128], msg[176];
    json_str(nb, sizeof nb, name ? name : "");
    _snprintf(msg, sizeof msg, "{\"ev\":\"net.gethostbyname\",\"node\":%s}", nb);
    msg[sizeof msg - 1] = 0;
    host_log("info", msg);
    return o_gethostbyname(name);
}

static int nhook(LPCSTR fn, void *det, void **orig) {
    void *tgt = (void *)GetProcAddress(GetModuleHandleW(L"ws2_32"), fn);
    return tgt && MH_CreateHook(tgt, det, orig) == MH_OK && MH_EnableHook(tgt) == MH_OK ? 0 : -1;
}

void netobs_install(void) {
    LoadLibraryW(L"ws2_32.dll");
    int e = 0;
    e |= nhook("connect",       h_connect,       (void **)&o_connect);
    e |= nhook("getaddrinfo",   h_getaddrinfo,   (void **)&o_getaddrinfo);
    e |= nhook("gethostbyname", h_gethostbyname, (void **)&o_gethostbyname);
    host_log(e ? "warn" : "info", e ? "{\"ev\":\"netobs.partial\"}" : "{\"ev\":\"netobs.ok\"}");
}
