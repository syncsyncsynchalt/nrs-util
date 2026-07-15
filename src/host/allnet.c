/* allnet.c — ALL.Net HTTP バックエンドのエミュ（standalone 用・平文 HTTP・生 winsock）。詳細 facts/mxnetwork.md。
 * 目的: card-auth scene(0x5e6200) が UID を NUPL 経由で POST→NetDataCardinfoResponse で有効判定する経路を成立させる。
 *
 * 二段構え:
 *   1. boot: http://naominet.jp/sys/servlet/PowerOn へ POST。応答パーサ FUN_006fe670 が stat=1 を要求し uri= から
 *      バックエンド URL を抽出→DAT_0210b530(=NUPL obj+8)。PowerOn 成功なしでは URL 空でカード POST が飛ばない。
 *   2. card-info はその uri へ POST。エンベロープ `command_common=..&response_header=..&command=<b64>&`
 *      （recv FUN_00712710 が id/status を抽出、command= の base64 を Binary2Class で 5611B 構造体にパース）。
 *
 * トランスポート傍受（card 経路は平文 HTTP。billing の OpenSSL ib.naominet は別系統・非対象）:
 *   getaddrinfo/gethostbyname: naominet.jp(ib. 除く)→ LAN IP / connect: <LAN IP>:80 → 127.0.0.1:ALLNET_PORT。
 * winsock フックを所有（netobs の connect/resolve ログを内包）。reload-safe のため host 側常駐。 */
#include "host.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "MinHook.h"

#pragma comment(lib, "ws2_32.lib")

#define ALLNET_PORT 40080   /* 平文 HTTP リスナー（loopback）。connect <LAN IP>:80 を here へ書換える */
#define LFS_TCP_PORT 40130  /* LFS(LOCAL GAME SERVER) loopback TCP responder。client の :30000 connect を here へ振替える */
/* ALL.Net ホストの解決先＝非 loopback の擬似 LAN IP。loopback(127.x)は IP バリデータ FUN_00a02bb0 が INVALID とし
 * auth init を失敗させる。全 ALL.Net ホストを同一 IP に解決すれば LAN 判定 FUN_006ff140 が network_type_LAN_flag=1。
 * 到達性は connect hook が :80→127.0.0.1:ALLNET_PORT へ振替えるので不要。 */
#define FAKE_LAN_IP "192.168.11.1"

/* 実行時にマシンの実 LAN IP へ設定（auth の AuthHops FUN_006ff230 が traceroute で hop 数を測るため、実在 IP なら
 * 即完了し ~46s 停滞を避ける）。取得失敗時は FAKE_LAN_IP へフォールバック。 */
static char          g_lan_ip[16] = FAKE_LAN_IP;
static unsigned char g_lan_b[4]   = { 192, 168, 11, 1 };

/* マシンの primary 非 loopback IPv4 を取得して g_lan_ip/g_lan_b に設定（hook 設置前に生 API で呼ぶ）。 */
static void resolve_local_ip(void) {
    char h[256];
    if (gethostname(h, sizeof h) != 0) return;
    struct addrinfo hints, *res = 0;
    memset(&hints, 0, sizeof hints); hints.ai_family = AF_INET;
    if (getaddrinfo(h, 0, &hints, &res) != 0 || !res) return;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        const struct sockaddr_in *si = (const struct sockaddr_in *)p->ai_addr;
        const unsigned char *ip = (const unsigned char *)&si->sin_addr;
        if (ip[0] != 127 && !(ip[0] == 169 && ip[1] == 254)) {   /* 非 loopback・非 APIPA */
            memcpy(g_lan_b, ip, 4);
            _snprintf(g_lan_ip, sizeof g_lan_ip, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
            break;
        }
    }
    freeaddrinfo(res);
}

/* ---- winsock redirect hooks（naominet.jp→loopback / :80→ALLNET_PORT） ---- */
static int             (WINAPI *o_connect)(SOCKET, const struct sockaddr *, int);
static int             (WINAPI *o_getaddrinfo)(PCSTR, PCSTR, const ADDRINFOA *, PADDRINFOA *);
static struct hostent *(WINAPI *o_gethostbyname)(const char *);

/* JSON 文字列値を最小エスケープ（"..."付き, 制御文字/非ASCIIは落とす）。 */
static void json_str(char *dst, size_t cap, const char *s, int maxlen) {
    size_t j = 0;
    if (cap < 3) { if (cap) dst[0] = 0; return; }
    dst[j++] = '"';
    for (int i = 0; s && s[i] && i < maxlen && j + 2 < cap; i++) {
        char c = s[i];
        if (c == '"' || c == '\\') { dst[j++] = '\\'; dst[j++] = c; }
        else if ((unsigned char)c >= 0x20 && (unsigned char)c < 0x7f) dst[j++] = c;
        else dst[j++] = '.';
    }
    dst[j++] = '"';
    dst[j] = 0;
}

/* ALL.Net ゲームサーバ系ホストか（billing の ib.naominet は TLS 別系統ゆえ除外）。 */
static int host_is_allnet(const char *name) {
    if (!name) return 0;
    if (strstr(name, "ib.naominet")) return 0;          /* billing（OpenSSL）は横取りしない */
    return strstr(name, "naominet.jp") != 0             /* PowerOn/DownloadOrder */
        || strstr(name, "bbrouter")   != 0              /* ALL.Net ルータ名 */
        || strstr(name, "tenporouter")!= 0
        || strstr(name, "allnet")     != 0;
}

static int WINAPI h_getaddrinfo(PCSTR node, PCSTR svc, const ADDRINFOA *hints, PADDRINFOA *res) {
    char nb[128], msg[224];
    int redir = host_is_allnet(node);
    json_str(nb, sizeof nb, node ? node : "", 100);
    _snprintf(msg, sizeof msg, "{\"ev\":\"allnet.resolve\",\"node\":%s,\"redir\":%d}", nb, redir);
    msg[sizeof msg - 1] = 0;
    host_log("info", msg);
    if (redir) return o_getaddrinfo(g_lan_ip, svc, hints, res);  /* ALL.Net→LAN IP（loopback は IP 検証で弾かれる）*/
    return o_getaddrinfo(node, svc, hints, res);
}

static struct hostent *WINAPI h_gethostbyname(const char *name) {
    char nb[128], msg[176];
    int redir = host_is_allnet(name);
    json_str(nb, sizeof nb, name ? name : "", 100);
    _snprintf(msg, sizeof msg, "{\"ev\":\"allnet.gethostbyname\",\"node\":%s,\"redir\":%d}", nb, redir);
    msg[sizeof msg - 1] = 0;
    host_log("info", msg);
    if (redir) return o_gethostbyname(g_lan_ip);
    return o_gethostbyname(name);
}

static int WINAPI h_connect(SOCKET s, const struct sockaddr *addr, int len) {
    if (addr && addr->sa_family == AF_INET) {
        const struct sockaddr_in *si = (const struct sockaddr_in *)addr;
        const unsigned char *ip = (const unsigned char *)&si->sin_addr;
        unsigned port = ntohs(si->sin_port);
        /* 擬似 LAN IP:80 = 我々が ALL.Net ホストを redirect した宛先 → loopback の実リスナーへ振替え。
           他ポート(keychip 40100+, billing 等)や他 IP は素通し。 */
        if (memcmp(ip, g_lan_b, 4) == 0 && port == 80) {
            struct sockaddr_in a = *si;
            a.sin_addr.s_addr = inet_addr("127.0.0.1");
            a.sin_port = htons(ALLNET_PORT);
            char msg[128];
            _snprintf(msg, sizeof msg,
                      "{\"ev\":\"allnet.connect\",\"redir\":\"%s:80->127.0.0.1:%d\"}", g_lan_ip, ALLNET_PORT);
            msg[sizeof msg - 1] = 0;
            host_log("info", msg);
            return o_connect(s, (const struct sockaddr *)&a, sizeof a);
        }
        /* LFS TCP: client は探索応答で得た server IP:30000 へ connect し accept を待つ。in-process サーバは
           standalone で accept 直後に close し send 失敗(connres=5)。∴ :30000 connect を自前の完全な
           LFS responder(127.0.0.1:LFS_TCP_PORT)へ振替え、正しい "LFSS" accept を push させる（OS 境界・メモリ無改変）。 */
        if (port == 30000) {
            struct sockaddr_in a = *si;
            a.sin_addr.s_addr = inet_addr("127.0.0.1");
            a.sin_port = htons(LFS_TCP_PORT);
            char msg[128];
            _snprintf(msg, sizeof msg,
                      "{\"ev\":\"lfs.connect\",\"redir\":\"%u.%u.%u.%u:30000->127.0.0.1:%d\"}", ip[0],ip[1],ip[2],ip[3], LFS_TCP_PORT);
            msg[sizeof msg - 1] = 0;
            host_log("info", msg);
            return o_connect(s, (const struct sockaddr *)&a, sizeof a);
        }
        char msg[160];
        _snprintf(msg, sizeof msg, "{\"ev\":\"allnet.connect\",\"ip\":\"%u.%u.%u.%u\",\"port\":%u}",
                  ip[0], ip[1], ip[2], ip[3], port);
        msg[sizeof msg - 1] = 0;
        host_log("info", msg);
    }
    return o_connect(s, addr, len);
}

/* ---- LFS(LOCAL GAME SERVER) UDP 探索の診断フック ----
 * ゲームの LfsClient は UDP :30002 bind→ broadcast "LFSS"(0x5353464c) hello を宛先 :30001 へ送り、
 * 応答で TCP server IP:port を得て TCP :30000 に connect する（in-process サーバ 0.0.0.0:30001/30000 稼働中）。
 * standalone では探索応答が返らず linkresult=3→connres=2→idx4 が status1 のまま boot hang。
 * まず sendto/recvfrom を素通し観測して、探索ブロードキャストの実宛先とサーバ応答有無を確定する。 */
static int (WINAPI *o_sendto)(SOCKET, const char *, int, int, const struct sockaddr *, int);
static int (WINAPI *o_recvfrom)(SOCKET, char *, int, int, struct sockaddr *, int *);

static int WINAPI h_sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen) {
    if (to && to->sa_family == AF_INET) {
        const struct sockaddr_in *si = (const struct sockaddr_in *)to;
        const unsigned char *ip = (const unsigned char *)&si->sin_addr;
        unsigned port = ntohs(si->sin_port);
        /* LFS 探索 broadcast(:30001) の宛先が 0.0.0.0/broadcast の場合、in-process サーバへ届くよう
           127.0.0.1:30001 に振替える（OS 境界 redirect・ゲームメモリ無改変）。 */
        if (port == 30001) {
            unsigned dst = si->sin_addr.s_addr;
            int is_bcast = (dst == 0 || dst == 0xFFFFFFFFu ||
                            (ip[0]==g_lan_b[0] && ip[3]==255));      /* 0.0.0.0 / 255.255.255.255 / LAN bcast */
            char m[220];
            _snprintf(m, sizeof m,
                "{\"ev\":\"lfs.sendto\",\"ip\":\"%u.%u.%u.%u\",\"port\":%u,\"len\":%d,\"magic\":\"%02x%02x%02x%02x\",\"redir\":%d}",
                ip[0], ip[1], ip[2], ip[3], port, len,
                len>0?(unsigned char)buf[0]:0, len>1?(unsigned char)buf[1]:0,
                len>2?(unsigned char)buf[2]:0, len>3?(unsigned char)buf[3]:0, is_bcast);
            m[sizeof m-1]=0; host_log("info", m);
            if (is_bcast) {
                struct sockaddr_in a = *si;
                a.sin_addr.s_addr = inet_addr("127.0.0.1");
                return o_sendto(s, buf, len, flags, (const struct sockaddr *)&a, sizeof a);
            }
        }
    }
    return o_sendto(s, buf, len, flags, to, tolen);
}

static int WINAPI h_recvfrom(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen) {
    int n = o_recvfrom(s, buf, len, flags, from, fromlen);
    if (n > 0 && from && from->sa_family == AF_INET) {
        const struct sockaddr_in *si = (const struct sockaddr_in *)from;
        unsigned port = ntohs(si->sin_port);
        const unsigned char *ip = (const unsigned char *)&si->sin_addr;
        if (port >= 30000 && port <= 30002) {
            char m[200];
            _snprintf(m, sizeof m, "{\"ev\":\"lfs.recvfrom\",\"ip\":\"%u.%u.%u.%u\",\"port\":%u,\"len\":%d}",
                      ip[0], ip[1], ip[2], ip[3], port, n);
            m[sizeof m-1]=0; host_log("info", m);
        }
    }
    return n;
}

/* ---- base64 encode（標準 alphabet +/、pad =。ゲームの decoder FUN_004919f0 と対） ---- */
static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int b64_encode(const unsigned char *in, int n, char *out, int cap) {
    int o = 0;
    for (int i = 0; i < n; i += 3) {
        int r = n - i;
        unsigned b0 = in[i];
        unsigned b1 = r > 1 ? in[i + 1] : 0;
        unsigned b2 = r > 2 ? in[i + 2] : 0;
        unsigned v = (b0 << 16) | (b1 << 8) | b2;
        if (o + 4 >= cap) break;
        out[o++] = B64[(v >> 18) & 0x3f];
        out[o++] = B64[(v >> 12) & 0x3f];
        out[o++] = r > 1 ? B64[(v >> 6) & 0x3f] : '=';
        out[o++] = r > 2 ? B64[v & 0x3f] : '=';
    }
    out[o] = 0;
    return o;
}

/* ---- NetDataCardinfoResponse（5611B）を組む ----
 * Binary2Class(0x913590) は input>=5611 && consumed==5611 を要求。全 zero-fill で空 string/0 count は valid。
 * u32 は big-endian。先頭 version/cmd と card-status のみ設定:
 *   [0..3]   protocol_version = 0x92B2D258（Binary2Class が照合）
 *   [4..7]   command enum     = 0x00000023（応答 cmd）
 *   [143..146] card status    = 0x00000001（=有効カード → scene card-data+0x3c==1 → 前進）
 * 残りは 0（空プロフィール＝新規/有効の最小形）。 */
#define CARDINFO_RESP_LEN 5611
static void put_be32(unsigned char *p, unsigned v) {
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);  p[3] = (unsigned char)v;
}
static void build_cardinfo_binary(unsigned char *buf /* CARDINFO_RESP_LEN */) {
    memset(buf, 0, CARDINFO_RESP_LEN);
    put_be32(buf + 0,   0x92B2D258u);   /* protocol_version */
    put_be32(buf + 4,   0x00000023u);   /* command enum 0x23 */
    put_be32(buf + 143, 0x00000001u);   /* card status = valid */
}

/* ---- zlib transport codec（NUPL コマンドは base64(zlib_deflate(平文))）----
 * 復号: base64-decode → inflate。符号化: zlib STORED ブロック（無圧縮でも game の zlib 1.2.3 が受理）。
 * 応答 HTTP に "Pragma: DFI" を付けると受信側が復号する。 */
static int b64_val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62; if (c == '/') return 63; return -1;
}
static int b64_decode(const char *in, int n, unsigned char *out, int cap) {
    int o = 0, bits = 0, acc = 0;
    for (int i = 0; i < n; i++) {
        int v = b64_val((unsigned char)in[i]); if (v < 0) continue;
        acc = (acc << 6) | v; bits += 6;
        if (bits >= 8) { bits -= 8; if (o < cap) out[o++] = (unsigned char)((acc >> bits) & 0xff); }
    }
    return o;
}
static unsigned adler32_of(const unsigned char *d, int n) {
    unsigned a = 1, b = 0; for (int i = 0; i < n; i++) { a = (a + d[i]) % 65521; b = (b + a) % 65521; } return (b << 16) | a;
}
typedef struct { const unsigned char *src; int srclen, pos; int bitbuf, bitcnt; } BitS;
static int gb1(BitS *b) {
    if (b->bitcnt == 0) { if (b->pos >= b->srclen) return -1; b->bitbuf = b->src[b->pos++]; b->bitcnt = 8; }
    int r = b->bitbuf & 1; b->bitbuf >>= 1; b->bitcnt--; return r;
}
static int gbn(BitS *b, int n) { int v = 0; for (int i = 0; i < n; i++) { int x = gb1(b); if (x < 0) return -1; v |= x << i; } return v; }
typedef struct { short count[16]; short symbol[288]; } Huf;
static void huf_build(Huf *h, const unsigned char *lens, int n) {
    int i; for (i = 0; i < 16; i++) h->count[i] = 0;
    for (i = 0; i < n; i++) h->count[lens[i]]++;
    h->count[0] = 0; short offs[16]; offs[1] = 0;
    for (i = 1; i < 15; i++) offs[i + 1] = offs[i] + h->count[i];
    for (i = 0; i < n; i++) if (lens[i]) h->symbol[offs[lens[i]]++] = (short)i;
}
static int huf_decode(BitS *b, Huf *h) {
    int code = 0, first = 0, idx = 0;
    for (int len = 1; len <= 15; len++) {
        int bit = gb1(b); if (bit < 0) return -1;
        code |= bit; int cnt = h->count[len];
        if (code - first < cnt) return h->symbol[idx + (code - first)];
        idx += cnt; first += cnt; first <<= 1; code <<= 1;
    }
    return -1;
}
static const short LBASE[] = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
static const short LEXT[]  = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
static const short DBASE[] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
static const short DEXT[]  = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
static int inflate_block(BitS *b, Huf *lh, Huf *dh, unsigned char *out, int *op, int cap) {
    for (;;) {
        int sym = huf_decode(b, lh); if (sym < 0) return -1;
        if (sym == 256) return 0;
        if (sym < 256) { if (*op < cap) out[(*op)++] = (unsigned char)sym; }
        else {
            sym -= 257; if (sym >= 29) return -1;
            int len = LBASE[sym] + gbn(b, LEXT[sym]);
            int ds = huf_decode(b, dh); if (ds < 0 || ds >= 30) return -1;
            int dist = DBASE[ds] + gbn(b, DEXT[ds]);
            for (int i = 0; i < len; i++) { if (*op < cap && *op - dist >= 0) { out[*op] = out[*op - dist]; (*op)++; } }
        }
    }
}
static int inflate_raw(const unsigned char *src, int srclen, unsigned char *out, int cap) {
    BitS b = { src, srclen, 0, 0, 0 }; int op = 0;
    static Huf flh, fdh; static int fixed_init = 0;
    for (;;) {
        int final = gb1(&b); if (final < 0) return -1;
        int type = gbn(&b, 2); if (type < 0) return -1;
        if (type == 0) {
            b.bitcnt = 0; if (b.pos + 4 > srclen) return -1;
            int len = src[b.pos] | (src[b.pos + 1] << 8); b.pos += 4;
            for (int i = 0; i < len; i++) { if (b.pos >= srclen) return -1; if (op < cap) out[op++] = src[b.pos++]; }
        } else if (type == 1) {
            if (!fixed_init) {
                unsigned char l[288]; int i;
                for (i = 0; i < 144; i++) l[i] = 8; for (; i < 256; i++) l[i] = 9; for (; i < 280; i++) l[i] = 7; for (; i < 288; i++) l[i] = 8;
                huf_build(&flh, l, 288);
                unsigned char d[30]; for (i = 0; i < 30; i++) d[i] = 5; huf_build(&fdh, d, 30); fixed_init = 1;
            }
            if (inflate_block(&b, &flh, &fdh, out, &op, cap) < 0) return -1;
        } else if (type == 2) {
            int hlit = gbn(&b, 5) + 257, hdist = gbn(&b, 5) + 1, hclen = gbn(&b, 4) + 4;
            static const unsigned char ord[19] = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};
            unsigned char cl[19]; memset(cl, 0, 19);
            for (int i = 0; i < hclen; i++) cl[ord[i]] = (unsigned char)gbn(&b, 3);
            Huf clh; huf_build(&clh, cl, 19);
            unsigned char lens[320]; int nn = 0, total = hlit + hdist;
            while (nn < total) {
                int sym = huf_decode(&b, &clh); if (sym < 0) return -1;
                if (sym < 16) lens[nn++] = (unsigned char)sym;
                else if (sym == 16) { int r = gbn(&b, 2) + 3; unsigned char pv = lens[nn - 1]; while (r-- && nn < total) lens[nn++] = pv; }
                else if (sym == 17) { int r = gbn(&b, 3) + 3; while (r-- && nn < total) lens[nn++] = 0; }
                else { int r = gbn(&b, 7) + 11; while (r-- && nn < total) lens[nn++] = 0; }
            }
            Huf lh, dh; huf_build(&lh, lens, hlit); huf_build(&dh, lens + hlit, hdist);
            if (inflate_block(&b, &lh, &dh, out, &op, cap) < 0) return -1;
        } else return -1;
        if (final) break;
    }
    return op;
}
/* zlib(2バイトヘッダ)を剥がして inflate。戻り=平文長, 失敗=-1。 */
static int zlib_decode(const unsigned char *src, int srclen, unsigned char *out, int cap) {
    if (srclen < 2) return -1;
    return inflate_raw(src + 2, srclen - 2, out, cap);
}
/* 平文を zlib STORED ストリームへ（無圧縮）。戻り=長。 */
static int zlib_encode(const unsigned char *d, int n, unsigned char *out, int cap) {
    int o = 0; if (cap < n + 11) return -1;
    out[o++] = 0x78; out[o++] = 0x01;
    int i = 0;
    do {
        int blk = n - i; if (blk > 65535) blk = 65535; int final = (i + blk >= n) ? 1 : 0;
        out[o++] = (unsigned char)final;
        out[o++] = blk & 0xff; out[o++] = (blk >> 8) & 0xff;
        out[o++] = ~blk & 0xff; out[o++] = (~blk >> 8) & 0xff;
        memcpy(out + o, d + i, blk); o += blk; i += blk;
    } while (i < n);
    unsigned ad = adler32_of(d, n);
    out[o++] = (ad >> 24) & 0xff; out[o++] = (ad >> 16) & 0xff; out[o++] = (ad >> 8) & 0xff; out[o++] = ad & 0xff;
    return o;
}

/* ---- HTTP リクエスト解析ヘルパ ---- */

/* 大小無視の部分一致検索（Content-Length ヘッダ等）。 */
static const char *ci_find(const char *hay, const char *needle) {
    size_t nl = strlen(needle);
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nl && p[i] && (char)tolower((unsigned char)p[i]) == (char)tolower((unsigned char)needle[i])) i++;
        if (i == nl) return p;
    }
    return 0;
}

/* body から `key=value` の value を dst へ（'&' か末尾まで）。見つからなければ 0。 */
static int field_value(const char *body, int blen, const char *key, char *dst, int cap) {
    size_t kl = strlen(key);
    for (int i = 0; i + (int)kl < blen; i++) {
        if (memcmp(body + i, key, kl) == 0) {
            int j = i + (int)kl, o = 0;
            while (j < blen && body[j] != '&' && o < cap - 1) dst[o++] = body[j++];
            dst[o] = 0;
            return 1;
        }
    }
    if (cap > 0) dst[0] = 0;
    return 0;
}

/* バイナリ領域にトークン(NUL終端文字列)が含まれるか。 */
static int mem_contains(const unsigned char *hay, int n, const char *tok) {
    int tl = (int)strlen(tok);
    for (int i = 0; i + tl <= n; i++) if (memcmp(hay + i, tok, tl) == 0) return 1;
    return 0;
}

/* --- 複合配列フィールド生成ヘルパ（区切り = リテラル "del"、cdb 実測: DAT_01266f60）--- */
/* n 個の "0" トークンを "del" 連結で書く（全ゼロの配列値）。tokenizer FUN_008e57d0 が "del" を find し +3 前進。 */
static char *put_zarr(char *p, char *end, int n) {
    for (int i = 0; i < n; i++) {
        if (i) { if (end - p < 5) break; *p++ = 'd'; *p++ = 'e'; *p++ = 'l'; }
        if (end - p < 2) break;
        *p++ = '0';
    }
    return p;
}
static char *put_str(char *p, char *end, const char *s) {
    while (*s && p < end - 1) *p++ = *s++;
    return p;
}

/* attend/start/netentry/matchingstat 共通の session-config 応答（RE: FUN_00902040 attend_response_parse・68 field）。
 * 複合配列 field は固定数の "del" 区切りレコードが必須（欠落・数不足で NUPL obj+0xd8=-1）。
 * flat "del" トークン総数（record数×record内 token数, cdb/decompile で確定）:
 *   map_id=40 / rules=16×161=2576 / ranking_coefficient=1×9=9 / event_attr=3×3=9 /
 *   event_param=3×119=357 / event_result=3×7=21 / ranking=4×24=96。全 leaf は int/float/破棄string ゆえ "0" で可。 */
static int build_session_config(const char *cmd_response, const char *cc, char *out, int cap) {
    char *p = out, *end = out + cap;
    p = put_str(p, end, "command="); p = put_str(p, end, cmd_response);
    p = put_str(p, end, "&protocol_version=92b2d258&command_common="); p = put_str(p, end, cc);
    /* パーサ先頭の pre-split 検証（各フィールドは "=" 分割で厳密に 2 要素＝key=value 必須, 空値=count1 で throw）
     * のため、全フィールドに非空値を与える（空文字 "" 不可。cdb 実証: ms_url= で count1→例外→-1）。
     * さらに state handler FUN_00714230 が ms_close/ms_open/ms_maintenance_time 等を datetime 再パース(FUN_007230f0
     * →__mkgmtime64)するため、これらは "0" 不可・妥当な datetime "YYYY-MM-DD HH:MM:SS.0" 必須。DT=init と同形式。 */
    #define DT "2000-01-01 00:00:00.0"
    p = put_str(p, end, "&response_header=0del&"
        "ms_url=0&ms_port=0&ms_ping=0&ms_close=" DT "&ms_open=" DT "&ms_maintenance_time=" DT "&ms_maintenance_week=0&ms_match_flag=0&"
        "ul_start=0&dl_start=0&ul_interval=0&dl_interval=0&ul_max_size=0&dl_count=0&map_id=");
    p = put_zarr(p, end, 40);
    /* record 系フィールドは各 record が sub-parser 込みで N token 消費（rules=175/record cdb 実測, 各値に後続 "del" 必須）。
     * caller は N record 読んで停止＝余剰 token は無視されるため、安全側に多めに供給（最終値の後続 del も保証）。
     * map_id のみ count==40 厳密検査ゆえ 40 固定。 */
    p = put_str(p, end, "&rules=");
    p = put_zarr(p, end, 4000);   /* caller の record 境界 stride ≈188-198 del/record（cdb: 2576→14rec, 3000→16目失敗）。16×198≈3168 に余裕 */
    p = put_str(p, end,
        "&illegal_delay=0&illegal_recovery=0&exchange_rate=0&max_exchange_rearity=0&"
        "material_daily_bonus_table=0&material_daily_bonus_num=0&material_bonus_probability=0&material_multi_ratio=0&bonus_adder_open=0&"
        "gp_by_1credit=260&gp_by_2credit=520&gp_by_3credit=780&gp_by_5credit=1300&gp_continue_bonus=0&gp_bonus_count=0&"
        "gp_tutorial1=0&gp_tutorial2=0&gp_color_change=0&gp_character_change=0&gp_rate_tempmap=0&"
        "cp_rate_on_time=0&cp_rate_by_gp=0&cp_max=0&chip_max_battle_time=0&chip_max_point=0&"
        "new_material_probability=0&sv_setting_version=0&rank_battle_count_max=0&max_scrm_rank=0&max_team_scrm_rank=0&"
        "ngword_update=" DT "&ranking_update=" DT "&event_update=" DT "&replay_update=" DT "&seal_update=" DT "&cap_update=" DT "&paramadjust_update=" DT "&"
        "placelist_update=" DT "&nickname_update=" DT "&attend_update=" DT "&book_keep_flg=AAAAAAAAAAAAAAAA&"
        "ms_stop_flag=0&pushed_flag=0&extra_flag=0&ranking_coefficient=");
    p = put_zarr(p, end, 15);          /* 単一 record 9 値 + 余裕 */
    p = put_str(p, end, "&event_attr=");
    p = put_zarr(p, end, 24);          /* 3 record × 3 + 余裕 */
    p = put_str(p, end, "&event_param=");
    p = put_zarr(p, end, 600);         /* 3 record ×(119+sub-parser) 多め */
    p = put_str(p, end, "&event_result=");
    p = put_zarr(p, end, 36);          /* 3 record × 7 + 余裕 */
    p = put_str(p, end, "&ranking=");
    p = put_zarr(p, end, 240);         /* 4 record ×(24+境界 overhead)。caller stride 高めゆえ多め */
    p = put_str(p, end, "&");
    if (p >= end) return -1;   /* 溢れ */
    *p = 0;
    return (int)(p - out);
}

/* command= 値の 0x30 挿入を除去し "_request" を剥がしてコマンド名を得る（"atte0nd0_re0que0st"→"attend"）。
 * ALL.Net コマンド名は数字を含まないので '0' 全除去は安全。out は小さくてよい（最長 ~20）。 */
static void nupl_cmd_name(const unsigned char *req, int reqlen, char *out, int cap) {
    char raw[80]; field_value((const char *)req, reqlen, "command=", raw, sizeof raw);
    int j = 0;
    for (int i = 0; raw[i] && j < cap - 1; i++) if (raw[i] != '0') out[j++] = raw[i];
    out[j] = 0;
    char *p = strstr(out, "_request"); if (p) *p = 0;
}

/* ALL.Net text 応答テーブル（各 command の strict parser を RE して抽出。round1 workflow allnet-cmd-re）。
 * fields = envelope(command/protocol_version/command_common/response_header) を除く全必須 field を最小有効値で。
 * 各 parser は全 field present を要求（欠落で NUPL obj+0xd8=-1）。日付= "2000-01-01 00:00:00.0"。 */
typedef struct { const char *name; const char *fields; } NuplTextResp;
static const NuplTextResp NUPL_TEXT[] = {
    { "init",
      "local_uid=0000000000000000&db_start_time=2000-01-01 00:00:00.0&db_stop_time=2030-01-01 23:59:00.0&" },
    /* db_stop_time の time-of-day 23:59＝session の time-schedule gate(FUN_0076de00)を <0 化し state2→3 前進（cdb 実証）*/
    { "end",          "ms_stop_flag=0&card_id=0&dotnet_flag=0&" },
    { "rank",         "ranking_flag=&ranking_data_version=0&ranking_start=&ranking_end=&ranking_is_compleat=0&ranking_month=0&ranking_param=&" },
    { "ngword",       "ng_word=&" },
    { "cap",          "update_timestamp=&cap_update=0&have_item=&have_avater=&cap_open_rank=0&" },
    { "image",        "image_file_binary=&image_file_size=0&image_crc=0&" },
    { "selecterinfo", "clan_id=0&playing_member_clan=0&" },
};

/* NUPL コマンドの内部平文応答を組む（decode 済リクエスト req から）。エンベロープ = command=<cmd>_response&
 * protocol_version=92b2d258&command_common=<echo>&response_header=0del& + 各 field。recv(FUN_00712710)が id 一致
 * ＋status0 で envelope 通過、その後 command 別 strict parser が全 field を検証。戻り=平文長。 */
static int build_nupl_inner(const unsigned char *req, int reqlen, char *out, int cap) {
    char cc[512]; field_value((const char *)req, reqlen, "command_common=", cc, sizeof cc);  /* echo */
    char name[32]; nupl_cmd_name(req, reqlen, name, sizeof name);
    (void)mem_contains;

    /* cardinfo: card-auth の 5611B binary 応答（command=base64(binary), Binary2Class 0x913590）。末尾配置。 */
    if (strcmp(name, "cardinfo") == 0) {
        unsigned char bin[CARDINFO_RESP_LEN]; build_cardinfo_binary(bin);
        static char pb64[CARDINFO_RESP_LEN * 2]; b64_encode(bin, CARDINFO_RESP_LEN, pb64, sizeof pb64);
        return _snprintf(out, cap, "response_header=0del&command_common=%s&protocol_version=92b2d258&command=%s&", cc, pb64);
    }
    /* delivinst(配信インストール): parser delivinst_response_parse(0x916150) が全 instruction_* field を要求。
       instruction_interval=int-list 厳密4個 / instruction_cloud=int-list 厳密48個（区切り DAT_01266f5c）。全 0 = 配信指示なし。
       未応答だと boot 通過後 MMNW シーンで ~60s 毎に retry し attract 手前で停止。 */
    if (strcmp(name, "delivinst") == 0) {
        char cloud[160]; int cp = 0;
        for (int i = 0; i < 48; i++) cp += _snprintf(cloud + cp, (int)sizeof cloud - cp, i ? ",0" : "0");
        return _snprintf(out, cap,
            "command=delivinst_response&protocol_version=92b2d258&command_common=%s&response_header=0del&"
            "instruction_id=0&instruction_order_time=2000-01-01 00:00:00.0&"
            "instruction_release_time=2000-01-01 00:00:00.0&instruction_interval=0,0,0,0&instruction_cloud=%s&"
            "instruction_part_size=0&instruction_report_interval=0&instruction_flag=0&instruction_partition=0&",
            cc, cloud);
    }
    /* text テーブル一致で envelope + fields を組む。 */
    for (size_t i = 0; i < sizeof NUPL_TEXT / sizeof NUPL_TEXT[0]; i++) {
        if (strcmp(name, NUPL_TEXT[i].name) == 0)
            return _snprintf(out, cap,
                "command=%s_response&protocol_version=92b2d258&command_common=%s&response_header=0del&%s",
                NUPL_TEXT[i].name, cc, NUPL_TEXT[i].fields);
    }
    /* attend/start/netentry/matchingstat = session config（68 field・複合配列は "del" 区切りゼロ配列）。同一パーサ FUN_00902040。 */
    if (strcmp(name, "attend") == 0)       return build_session_config("attend_response", cc, out, cap);
    if (strcmp(name, "start") == 0)        return build_session_config("start_response", cc, out, cap);
    if (strcmp(name, "netentry") == 0)     return build_session_config("netentry_response", cc, out, cap);
    if (strcmp(name, "matchingstat") == 0) return build_session_config("matchingstat_response", cc, out, cap);

    return _snprintf(out, cap, "response_header=0del&command_common=%s&protocol_version=92b2d258&command=&", cc);
}

/* ---- ルーティング: path/body から応答 body を組む。戻り=body 長。*want_pragma=1 なら zlib+Pragma:DFI。 ---- */
static int build_response_body(const char *path, const char *body, int blen, char *out, int cap, int *want_pragma) {
    *want_pragma = 0;
    /* --- PowerOn: alAbEx auth を genuine 成立（stat=1 + uri=。平文・非エンコード）。uri=ゲームバックエンド URL。 --- */
    if (ci_find(path, "PowerOn")) {
        /* year..second = 実機 ALL.Net サーバが返す「現在時刻」。ゲームはこれを NUPL セッション時計の基準にする。
         * これが db_start_time(00:00) より後でないと NUPL の time-window gate(nupl_session_time_window_gate 0x76de00)が
         * (db_start - current)分 >= 0 で session を待機させ、attend が最大 60s 遅延する（init→attend gap の真因）。
         * 実時刻を返せば current > db_start(00:00) で gate は即 proceed → attend 即送信 → phase3 到達で UPLOAD ready。 */
        SYSTEMTIME st; GetLocalTime(&st);
        /* time-window gate は分単位で (db_start{00:00} - current) を見る。current==00:00 ちょうど（真夜中の
         * 最初の1分）だと差=0 で待機に落ちるため、その 1 分だけ 00:01 に丸める（他時刻は実時刻のまま）。 */
        if (st.wHour == 0 && st.wMinute == 0) st.wMinute = 1;
        int n = _snprintf(out, cap,
            "stat=1&uri=http://%s/sys/servlet/&host=%s&"
            "region0=1&region_name0=JAPAN&region_name1=&region_name2=&region_name3=&"
            "place_id=1234&name=NRSEDGE&nickname=NRSEDGE&country=JPN&"
            "year=%d&month=%d&day=%d&hour=%d&minute=%d&second=%d&setting=&res_class=PowerOnResponseVer2&",
            g_lan_ip, g_lan_ip, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        return n > 0 ? n : 0;
    }
    /* --- DownloadOrder: stat=1 + uri=（平文・非エンコード）。 --- */
    if (ci_find(path, "DownloadOrder")) {
        int n = _snprintf(out, cap, "stat=1&uri=http://%s/sys/servlet/&", g_lan_ip);
        return n > 0 ? n : 0;
    }

    /* --- NUPL ゲームバックエンド（bare /sys/servlet/）: リクエストは base64(zlib(平文))。復号→command 判定→応答→再エンコード。 --- */
    unsigned char reqraw[4096]; int rawlen = b64_decode(body, blen, reqraw, sizeof reqraw);
    unsigned char reqdec[8192]; int declen = zlib_decode(reqraw, rawlen, reqdec, sizeof reqdec);
    if (declen <= 0) { declen = blen < (int)sizeof reqdec ? blen : (int)sizeof reqdec; memcpy(reqdec, body, declen); }
    { char snip[420]; json_str(snip, sizeof snip, (const char *)reqdec, 300);
      char m[520]; _snprintf(m, sizeof m, "{\"ev\":\"allnet.nupl_req\",\"declen\":%d,\"dec\":%s}", declen, snip);
      m[sizeof m - 1] = 0; host_log("info", m); }

    static char inner[32768];   /* session-config 応答は rules 2576 token 等で ~13KB に達する */
    int innerlen = build_nupl_inner(reqdec, declen, inner, sizeof inner);
    if (innerlen <= 0) { host_log("error", "{\"ev\":\"allnet.inner_overflow\"}"); return 0; }
    { char snip[300]; json_str(snip, sizeof snip, inner, 200);
      char m[400]; _snprintf(m, sizeof m, "{\"ev\":\"allnet.nupl_resp\",\"innerlen\":%d,\"inner\":%s}", innerlen, snip);
      m[sizeof m - 1] = 0; host_log("info", m); }
    static unsigned char enc[32768];
    int enclen = zlib_encode((unsigned char *)inner, innerlen, enc, sizeof enc);
    if (enclen <= 0) return 0;
    int n = b64_encode(enc, enclen, out, cap);
    *want_pragma = 1;                          /* zlib エンコード応答＝Pragma:DFI マーカー必須 */
    return n;
}

/* ---- HTTP サーバ ---- */
static DWORD WINAPI allnet_client(LPVOID arg) {
    SOCKET c = (SOCKET)(uintptr_t)arg;
    static const int REQCAP = 32768;
    char *req = (char *)HeapAlloc(GetProcessHeap(), 0, REQCAP);
    char *resp = (char *)HeapAlloc(GetProcessHeap(), 0, 65536);
    if (!req || !resp) { if (req) HeapFree(GetProcessHeap(), 0, req);
                         if (resp) HeapFree(GetProcessHeap(), 0, resp); closesocket(c); return 0; }
    int rl = 0, hdrlen = -1, clen = 0;
    /* ヘッダ完了まで読み、Content-Length 分の body を追加受信 */
    for (;;) {
        if (rl >= REQCAP - 1) break;
        int n = recv(c, req + rl, REQCAP - 1 - rl, 0);
        if (n <= 0) break;
        rl += n; req[rl] = 0;
        if (hdrlen < 0) {
            char *he = strstr(req, "\r\n\r\n");
            if (he) {
                hdrlen = (int)(he + 4 - req);
                const char *cl = ci_find(req, "content-length:");
                if (cl) clen = atoi(cl + 15);
            }
        }
        if (hdrlen >= 0 && rl - hdrlen >= clen) break;    /* body 揃った */
    }
    if (hdrlen < 0) { closesocket(c); HeapFree(GetProcessHeap(),0,req); HeapFree(GetProcessHeap(),0,resp); return 0; }

    /* method/path 抽出（"POST /path HTTP/1.1"） */
    char path[512] = {0};
    { const char *sp = strchr(req, ' ');
      if (sp) { sp++; const char *sp2 = strchr(sp, ' '); int pl = sp2 ? (int)(sp2 - sp) : 0;
                if (pl > 0 && pl < (int)sizeof path) { memcpy(path, sp, pl); path[pl] = 0; } } }
    const char *body = req + hdrlen;
    int blen = rl - hdrlen; if (blen < 0) blen = 0;
    if (blen > clen && clen > 0) blen = clen;

    /* リクエストログ（command_common / launch_code / card_id を可視化して収束を助ける） */
    { char pb[256], cb[256], lb[64], idb[32];
      json_str(pb, sizeof pb, path, 200);
      char cc2[256]; field_value(body, blen, "command_common=", cc2, sizeof cc2); json_str(cb, sizeof cb, cc2, 120);
      char lc2[48]; field_value(body, blen, "launch_code=", lc2, sizeof lc2); json_str(lb, sizeof lb, lc2, 40);
      char id2[24]; field_value(body, blen, "card_id=", id2, sizeof id2); json_str(idb, sizeof idb, id2, 20);
      char bodyb[420]; json_str(bodyb, sizeof bodyb, body, 300);   /* 実フォーマット確認用に本文先頭を記録 */
      char m[1100];
      _snprintf(m, sizeof m,
                "{\"ev\":\"allnet.req\",\"path\":%s,\"clen\":%d,\"cc\":%s,\"launch\":%s,\"card_id\":%s,\"body\":%s}",
                pb, blen, cb, lb, idb, bodyb);
      m[sizeof m - 1] = 0; host_log("info", m); }

    /* 応答生成 */
    static char rbody[32768];
    int want_pragma = 0;
    int rblen = build_response_body(path, body, blen, rbody, sizeof rbody, &want_pragma);
    /* Content-Type: alAbEx HTTP ゲート FUN_00a020e0 が application/octet-stream 完全一致を要求。
     * Pragma: DFI: NUPL 応答は base64(zlib) エンコードゆえマーカー必須（受信 FUN_0066dff0/0066c0a0 が検出→復号）。
     *   PowerOn/DownloadOrder は平文ゆえ付けない。 */
    int hn = _snprintf(resp, 65536,
                       "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n%s"
                       "Content-Length: %d\r\nConnection: close\r\n\r\n",
                       want_pragma ? "Pragma: DFI\r\n" : "", rblen);
    if (hn > 0) {
        send(c, resp, hn, 0);
        if (rblen > 0) send(c, rbody, rblen, 0);
    }
    { char m[128]; _snprintf(m, sizeof m, "{\"ev\":\"allnet.resp\",\"blen\":%d}", rblen);
      m[sizeof m-1]=0; host_log("info", m); }

    closesocket(c);
    HeapFree(GetProcessHeap(), 0, req);
    HeapFree(GetProcessHeap(), 0, resp);
    return 0;
}

static DWORD WINAPI allnet_listen(LPVOID arg) {
    (void)arg;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { host_log("warn", "{\"ev\":\"allnet.listen.fail\"}"); return 1; }
    int yes = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof yes);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(ALLNET_PORT);
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) { closesocket(s); host_log("warn","{\"ev\":\"allnet.bind.fail\"}"); return 1; }
    listen(s, 16);
    host_log("info", "{\"ev\":\"allnet.server.up\",\"port\":40080}");
    for (;;) {
        SOCKET c = accept(s, 0, 0);
        if (c == INVALID_SOCKET) break;
        CreateThread(0, 0, allnet_client, (LPVOID)(uintptr_t)c, 0, 0);
    }
    closesocket(s);
    return 0;
}

/* ---- LFS(LOCAL GAME SERVER) loopback TCP responder ----
 * client は探索後 :30000 に connect し passive で待機（何も送らない）。in-process サーバは standalone で
 * accept 直後に close し client の send が失敗(linkresult=6→connres=5)。我々の responder は accept 直後に
 * 正しい "LFSS" accept を push → parser(lfs_link_tcp_recv_parse 0x6b12b0)が state8/linkresult=0 →
 * connres=0 → exec SM が manager+0x204=2 → idx4(LOCAL) done → boot CHECKING CONNECTION 通過。
 * client の :30000 connect は h_connect が 127.0.0.1:LFS_TCP_PORT へ振替える（OS 境界・ゲームメモリ無改変）。
 * accept 28B: BE length prefix 0x18 + body{magic"LFSS", msgtype=4, ver=0x0405, self_len=0x18, id, flags=1, aux}。 */
static const unsigned char LFS_ACCEPT[28] = {
    0x00,0x00,0x00,0x18,             /* BE length prefix = 0x18 (body 24B) */
    0x4C,0x46,0x53,0x53,             /* [0x00] magic "LFSS" */
    0x04,0x00,                       /* [0x04] msgtype = 4 (ACCEPT) */
    0x05,0x04,                       /* [0x06] version = 0x0405 */
    0x18,0x00,0x00,0x00,             /* [0x08] self-length = 0x18 (== prefix) */
    0x00,0x00,0x00,0x00,             /* [0x0C] id (any) */
    0x01,0x00,0x00,0x00,             /* [0x10] flags = 1 (bit0 accept, bit1 clear) */
    0x00,0x00,0x00,0x00              /* [0x14] aux (any) */
};

static DWORD WINAPI lfs_client(LPVOID arg) {
    SOCKET c = (SOCKET)(uintptr_t)arg;
    send(c, (const char *)LFS_ACCEPT, sizeof LFS_ACCEPT, 0);   /* accept を即 push（state7 の ~3s timeout 内） */
    host_log("info", "{\"ev\":\"lfs.accept.sent\"}");
    char tmp[64];
    for (;;) { int n = recv(c, tmp, sizeof tmp, 0); if (n <= 0) break; }  /* parse 完了まで接続維持（早期 RST 回避） */
    closesocket(c);
    return 0;
}

static DWORD WINAPI lfs_listen(LPVOID arg) {
    (void)arg;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { host_log("warn", "{\"ev\":\"lfs.listen.fail\"}"); return 1; }
    int yes = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof yes);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(LFS_TCP_PORT);
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) { closesocket(s); host_log("warn","{\"ev\":\"lfs.bind.fail\"}"); return 1; }
    listen(s, 8);
    host_log("info", "{\"ev\":\"lfs.server.up\",\"port\":40130}");
    for (;;) {
        SOCKET c = accept(s, 0, 0);
        if (c == INVALID_SOCKET) break;
        CreateThread(0, 0, lfs_client, (LPVOID)(uintptr_t)c, 0, 0);
    }
    closesocket(s);
    return 0;
}

static int nhook(LPCSTR fn, void *det, void **orig) {
    void *tgt = (void *)GetProcAddress(GetModuleHandleW(L"ws2_32"), fn);
    return tgt && MH_CreateHook(tgt, det, orig) == MH_OK && MH_EnableHook(tgt) == MH_OK ? 0 : -1;
}

void allnet_install(void) {
    LoadLibraryW(L"ws2_32.dll");
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);   /* keychip_server も呼ぶが冪等 */
    resolve_local_ip();                          /* hook 設置前に生 getaddrinfo で実 LAN IP を取得 */
    { char m[96]; _snprintf(m, sizeof m, "{\"ev\":\"allnet.lan_ip\",\"ip\":\"%s\"}", g_lan_ip);
      m[sizeof m-1]=0; host_log("info", m); }
    int e = 0;
    e |= nhook("connect",       h_connect,       (void **)&o_connect);
    e |= nhook("getaddrinfo",   h_getaddrinfo,   (void **)&o_getaddrinfo);
    e |= nhook("gethostbyname", h_gethostbyname, (void **)&o_gethostbyname);
    e |= nhook("sendto",        h_sendto,        (void **)&o_sendto);     /* LFS 探索 UDP 観測 */
    e |= nhook("recvfrom",      h_recvfrom,      (void **)&o_recvfrom);   /* LFS 探索応答 観測 */
    host_log(e ? "warn" : "info", e ? "{\"ev\":\"allnet.hooks.partial\"}" : "{\"ev\":\"allnet.hooks.ok\"}");
    CreateThread(0, 0, allnet_listen, 0, 0, 0);
    CreateThread(0, 0, lfs_listen, 0, 0, 0);     /* LFS(LOCAL GAME SERVER) loopback TCP responder */
}
