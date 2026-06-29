/* keychip_server.c — 旧 boot/mxkeychip/server/pcpa_server.py の native 移植（winsock サーバ部）。
 * 応答ロジックは keychip_proto.c（純粋・test 可）に分離。127.0.0.1 各ポートで listen。
 * ワイヤ: S->C ">"、C->S "k=v&k=v\r\n"、S->C "resp\r\n>"。reload-safe のため安定 host 側に常駐。 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include "host.h"
#include "keychip_proto.h"
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

static const int PORTS[] = { 40100, 40102, 40104, 40106, 40110, 40111, 40113 };

static DWORD WINAPI client_thread(LPVOID arg) {
    SOCKET c = (SOCKET)(uintptr_t)arg;
    char in[1024], rbuf[512], pkt[600];
    int inlen = 0;
    send(c, ">", 1, 0);
    for (;;) {
        char chunk[512];
        int n = recv(c, chunk, sizeof chunk, 0);
        if (n <= 0) break;
        if (inlen + n > (int)sizeof in - 1) inlen = 0;     /* オーバフロー保護 */
        memcpy(in + inlen, chunk, n); inlen += n; in[inlen] = 0;
        char *nl;
        while ((nl = strchr(in, '\n')) != 0) {
            *nl = 0;
            char line[600]; int ll = (int)(nl - in);
            if (ll > 0 && in[ll - 1] == '\r') ll--;
            if (ll > (int)sizeof line - 1) ll = sizeof line - 1;
            memcpy(line, in, ll); line[ll] = 0;
            int rest = inlen - (int)(nl - in) - 1;
            memmove(in, nl + 1, rest > 0 ? rest : 0); inlen = rest > 0 ? rest : 0; in[inlen] = 0;
            if (line[0]) {
                const char *body = kc_respond(line, rbuf, sizeof rbuf);
                int pn = snprintf(pkt, sizeof pkt, "%s\r\n>", body);
                if (pn > 0) send(c, pkt, pn, 0);
            }
        }
    }
    closesocket(c);
    return 0;
}

static DWORD WINAPI listen_thread(LPVOID arg) {
    int port = (int)(intptr_t)arg;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 1;
    int yes = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof yes);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons((u_short)port);
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) { closesocket(s); return 1; }  /* 二重起動なら skip */
    listen(s, 10);
    for (;;) {
        SOCKET c = accept(s, 0, 0);
        if (c == INVALID_SOCKET) break;
        CreateThread(0, 0, client_thread, (LPVOID)(uintptr_t)c, 0, 0);
    }
    closesocket(s);
    return 0;
}

void keychip_server_start(void) {
    WSADATA w;
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) { host_log("error", "{\"ev\":\"kc.wsa.fail\"}"); return; }
    for (size_t i = 0; i < sizeof PORTS / sizeof PORTS[0]; i++)
        CreateThread(0, 0, listen_thread, (LPVOID)(intptr_t)PORTS[i], 0, 0);
    host_log("info", "{\"ev\":\"keychip.server.up\",\"ports\":\"40100..40113\"}");
}
