#include "host.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "MinHook.h"

#pragma comment(lib, "ws2_32.lib")

#define ALLNET_PORT 40080
#define LFS_TCP_PORT 40130
#define FAKE_LAN_IP "192.168.11.1"

static char          g_lan_ip[16] = FAKE_LAN_IP;
static unsigned char g_lan_b[4]   = { 192, 168, 11, 1 };

static void resolve_local_ip(void) {
    char h[256];
    if (gethostname(h, sizeof h) != 0) return;
    struct addrinfo hints, *res = 0;
    memset(&hints, 0, sizeof hints); hints.ai_family = AF_INET;
    if (getaddrinfo(h, 0, &hints, &res) != 0 || !res) return;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        const struct sockaddr_in *si = (const struct sockaddr_in *)p->ai_addr;
        const unsigned char *ip = (const unsigned char *)&si->sin_addr;
        if (ip[0] != 127 && !(ip[0] == 169 && ip[1] == 254)) {
            memcpy(g_lan_b, ip, 4);
            _snprintf(g_lan_ip, sizeof g_lan_ip, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
            break;
        }
    }
    freeaddrinfo(res);
}

static int             (WINAPI *o_connect)(SOCKET, const struct sockaddr *, int);
static int             (WINAPI *o_getaddrinfo)(PCSTR, PCSTR, const ADDRINFOA *, PADDRINFOA *);
static struct hostent *(WINAPI *o_gethostbyname)(const char *);

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

static int host_is_allnet(const char *name) {
    if (!name) return 0;
    if (strstr(name, "ib.naominet")) return 0;
    return strstr(name, "naominet.jp") != 0
        || strstr(name, "bbrouter")   != 0
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
    if (redir) return o_getaddrinfo(g_lan_ip, svc, hints, res);
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

static int (WINAPI *o_sendto)(SOCKET, const char *, int, int, const struct sockaddr *, int);
static int (WINAPI *o_recvfrom)(SOCKET, char *, int, int, struct sockaddr *, int *);

static int WINAPI h_sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen) {
    if (to && to->sa_family == AF_INET) {
        const struct sockaddr_in *si = (const struct sockaddr_in *)to;
        const unsigned char *ip = (const unsigned char *)&si->sin_addr;
        unsigned port = ntohs(si->sin_port);
        if (port == 30001) {
            unsigned dst = si->sin_addr.s_addr;
            int is_bcast = (dst == 0 || dst == 0xFFFFFFFFu ||
                            (ip[0]==g_lan_b[0] && ip[3]==255));
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

#define CARDINFO_RESP_LEN 5611
static void put_be32(unsigned char *p, unsigned v) {
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);  p[3] = (unsigned char)v;
}
static void build_cardinfo_binary(unsigned char *buf) {
    memset(buf, 0, CARDINFO_RESP_LEN);
    put_be32(buf + 0,   0x92B2D258u);
    put_be32(buf + 4,   0x00000023u);
    put_be32(buf + 143, 0x00000001u);
}

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
static int zlib_decode(const unsigned char *src, int srclen, unsigned char *out, int cap) {
    if (srclen < 2) return -1;
    return inflate_raw(src + 2, srclen - 2, out, cap);
}
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

static const char *ci_find(const char *hay, const char *needle) {
    size_t nl = strlen(needle);
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nl && p[i] && (char)tolower((unsigned char)p[i]) == (char)tolower((unsigned char)needle[i])) i++;
        if (i == nl) return p;
    }
    return 0;
}

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

static int mem_contains(const unsigned char *hay, int n, const char *tok) {
    int tl = (int)strlen(tok);
    for (int i = 0; i + tl <= n; i++) if (memcmp(hay + i, tok, tl) == 0) return 1;
    return 0;
}

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

static int build_session_config(const char *cmd_response, const char *cc, char *out, int cap) {
    char *p = out, *end = out + cap;
    p = put_str(p, end, "command="); p = put_str(p, end, cmd_response);
    p = put_str(p, end, "&protocol_version=92b2d258&command_common="); p = put_str(p, end, cc);
    #define DT "2000-01-01 00:00:00.0"
    p = put_str(p, end, "&response_header=0del&"
        "ms_url=0&ms_port=0&ms_ping=0&ms_close=" DT "&ms_open=" DT "&ms_maintenance_time=" DT "&ms_maintenance_week=0&ms_match_flag=0&"
        "ul_start=0&dl_start=0&ul_interval=0&dl_interval=0&ul_max_size=0&dl_count=0&map_id=");
    p = put_zarr(p, end, 40);
    p = put_str(p, end, "&rules=");
    p = put_zarr(p, end, 4000);
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
    p = put_zarr(p, end, 15);
    p = put_str(p, end, "&event_attr=");
    p = put_zarr(p, end, 24);
    p = put_str(p, end, "&event_param=");
    p = put_zarr(p, end, 600);
    p = put_str(p, end, "&event_result=");
    p = put_zarr(p, end, 36);
    p = put_str(p, end, "&ranking=");
    p = put_zarr(p, end, 240);
    p = put_str(p, end, "&");
    if (p >= end) return -1;
    *p = 0;
    return (int)(p - out);
}

static void nupl_cmd_name(const unsigned char *req, int reqlen, char *out, int cap) {
    char raw[80]; field_value((const char *)req, reqlen, "command=", raw, sizeof raw);
    int j = 0;
    for (int i = 0; raw[i] && j < cap - 1; i++) if (raw[i] != '0') out[j++] = raw[i];
    out[j] = 0;
    char *p = strstr(out, "_request"); if (p) *p = 0;
}

typedef struct { const char *name; const char *fields; } NuplTextResp;
static const NuplTextResp NUPL_TEXT[] = {
    { "init",
      "local_uid=0000000000000000&db_start_time=2000-01-01 00:00:00.0&db_stop_time=2030-01-01 23:59:00.0&" },
    { "end",          "ms_stop_flag=0&card_id=0&dotnet_flag=0&" },
    { "rank",         "ranking_flag=&ranking_data_version=0&ranking_start=&ranking_end=&ranking_is_compleat=0&ranking_month=0&ranking_param=&" },
    { "ngword",       "ng_word=&" },
    { "cap",          "update_timestamp=&cap_update=0&have_item=&have_avater=&cap_open_rank=0&" },
    { "image",        "image_file_binary=&image_file_size=0&image_crc=0&" },
    { "selecterinfo", "clan_id=0&playing_member_clan=0&" },
};

static int build_nupl_inner(const unsigned char *req, int reqlen, char *out, int cap) {
    char cc[512]; field_value((const char *)req, reqlen, "command_common=", cc, sizeof cc);
    char name[32]; nupl_cmd_name(req, reqlen, name, sizeof name);
    (void)mem_contains;

    if (strcmp(name, "cardinfo") == 0) {
        unsigned char bin[CARDINFO_RESP_LEN]; build_cardinfo_binary(bin);
        static char pb64[CARDINFO_RESP_LEN * 2]; b64_encode(bin, CARDINFO_RESP_LEN, pb64, sizeof pb64);
        return _snprintf(out, cap, "response_header=0del&command_common=%s&protocol_version=92b2d258&command=%s&", cc, pb64);
    }
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
    for (size_t i = 0; i < sizeof NUPL_TEXT / sizeof NUPL_TEXT[0]; i++) {
        if (strcmp(name, NUPL_TEXT[i].name) == 0)
            return _snprintf(out, cap,
                "command=%s_response&protocol_version=92b2d258&command_common=%s&response_header=0del&%s",
                NUPL_TEXT[i].name, cc, NUPL_TEXT[i].fields);
    }
    if (strcmp(name, "attend") == 0)       return build_session_config("attend_response", cc, out, cap);
    if (strcmp(name, "start") == 0)        return build_session_config("start_response", cc, out, cap);
    if (strcmp(name, "netentry") == 0)     return build_session_config("netentry_response", cc, out, cap);
    if (strcmp(name, "matchingstat") == 0) return build_session_config("matchingstat_response", cc, out, cap);

    return _snprintf(out, cap, "response_header=0del&command_common=%s&protocol_version=92b2d258&command=&", cc);
}

static int build_response_body(const char *path, const char *body, int blen, char *out, int cap, int *want_pragma) {
    *want_pragma = 0;
    if (ci_find(path, "PowerOn")) {
        SYSTEMTIME st; GetLocalTime(&st);
        if (st.wHour == 0 && st.wMinute == 0) st.wMinute = 1;
        int n = _snprintf(out, cap,
            "stat=1&uri=http://%s/sys/servlet/&host=%s&"
            "region0=1&region_name0=JAPAN&region_name1=&region_name2=&region_name3=&"
            "place_id=1234&name=NRSEDGE&nickname=NRSEDGE&country=JPN&"
            "year=%d&month=%d&day=%d&hour=%d&minute=%d&second=%d&setting=&res_class=PowerOnResponseVer2&",
            g_lan_ip, g_lan_ip, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        return n > 0 ? n : 0;
    }
    if (ci_find(path, "DownloadOrder")) {
        int n = _snprintf(out, cap, "stat=1&uri=http://%s/sys/servlet/&", g_lan_ip);
        return n > 0 ? n : 0;
    }

    unsigned char reqraw[4096]; int rawlen = b64_decode(body, blen, reqraw, sizeof reqraw);
    unsigned char reqdec[8192]; int declen = zlib_decode(reqraw, rawlen, reqdec, sizeof reqdec);
    if (declen <= 0) { declen = blen < (int)sizeof reqdec ? blen : (int)sizeof reqdec; memcpy(reqdec, body, declen); }
    { char snip[420]; json_str(snip, sizeof snip, (const char *)reqdec, 300);
      char m[520]; _snprintf(m, sizeof m, "{\"ev\":\"allnet.nupl_req\",\"declen\":%d,\"dec\":%s}", declen, snip);
      m[sizeof m - 1] = 0; host_log("info", m); }

    static char inner[32768];
    int innerlen = build_nupl_inner(reqdec, declen, inner, sizeof inner);
    if (innerlen <= 0) { host_log("error", "{\"ev\":\"allnet.inner_overflow\"}"); return 0; }
    { char snip[300]; json_str(snip, sizeof snip, inner, 200);
      char m[400]; _snprintf(m, sizeof m, "{\"ev\":\"allnet.nupl_resp\",\"innerlen\":%d,\"inner\":%s}", innerlen, snip);
      m[sizeof m - 1] = 0; host_log("info", m); }
    static unsigned char enc[32768];
    int enclen = zlib_encode((unsigned char *)inner, innerlen, enc, sizeof enc);
    if (enclen <= 0) return 0;
    int n = b64_encode(enc, enclen, out, cap);
    *want_pragma = 1;
    return n;
}

static DWORD WINAPI allnet_client(LPVOID arg) {
    SOCKET c = (SOCKET)(uintptr_t)arg;
    static const int REQCAP = 32768;
    char *req = (char *)HeapAlloc(GetProcessHeap(), 0, REQCAP);
    char *resp = (char *)HeapAlloc(GetProcessHeap(), 0, 65536);
    if (!req || !resp) { if (req) HeapFree(GetProcessHeap(), 0, req);
                         if (resp) HeapFree(GetProcessHeap(), 0, resp); closesocket(c); return 0; }
    int rl = 0, hdrlen = -1, clen = 0;
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
        if (hdrlen >= 0 && rl - hdrlen >= clen) break;
    }
    if (hdrlen < 0) { closesocket(c); HeapFree(GetProcessHeap(),0,req); HeapFree(GetProcessHeap(),0,resp); return 0; }

    char path[512] = {0};
    { const char *sp = strchr(req, ' ');
      if (sp) { sp++; const char *sp2 = strchr(sp, ' '); int pl = sp2 ? (int)(sp2 - sp) : 0;
                if (pl > 0 && pl < (int)sizeof path) { memcpy(path, sp, pl); path[pl] = 0; } } }
    const char *body = req + hdrlen;
    int blen = rl - hdrlen; if (blen < 0) blen = 0;
    if (blen > clen && clen > 0) blen = clen;

    { char pb[256], cb[256], lb[64], idb[32];
      json_str(pb, sizeof pb, path, 200);
      char cc2[256]; field_value(body, blen, "command_common=", cc2, sizeof cc2); json_str(cb, sizeof cb, cc2, 120);
      char lc2[48]; field_value(body, blen, "launch_code=", lc2, sizeof lc2); json_str(lb, sizeof lb, lc2, 40);
      char id2[24]; field_value(body, blen, "card_id=", id2, sizeof id2); json_str(idb, sizeof idb, id2, 20);
      char bodyb[420]; json_str(bodyb, sizeof bodyb, body, 300);
      char m[1100];
      _snprintf(m, sizeof m,
                "{\"ev\":\"allnet.req\",\"path\":%s,\"clen\":%d,\"cc\":%s,\"launch\":%s,\"card_id\":%s,\"body\":%s}",
                pb, blen, cb, lb, idb, bodyb);
      m[sizeof m - 1] = 0; host_log("info", m); }

    static char rbody[32768];
    int want_pragma = 0;
    int rblen = build_response_body(path, body, blen, rbody, sizeof rbody, &want_pragma);
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

static const unsigned char LFS_ACCEPT[28] = {
    0x00,0x00,0x00,0x18,
    0x4C,0x46,0x53,0x53,
    0x04,0x00,
    0x05,0x04,
    0x18,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
    0x01,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00
};

static DWORD WINAPI lfs_client(LPVOID arg) {
    SOCKET c = (SOCKET)(uintptr_t)arg;
    send(c, (const char *)LFS_ACCEPT, sizeof LFS_ACCEPT, 0);
    host_log("info", "{\"ev\":\"lfs.accept.sent\"}");
    char tmp[64];
    for (;;) { int n = recv(c, tmp, sizeof tmp, 0); if (n <= 0) break; }
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
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
    resolve_local_ip();
    { char m[96]; _snprintf(m, sizeof m, "{\"ev\":\"allnet.lan_ip\",\"ip\":\"%s\"}", g_lan_ip);
      m[sizeof m-1]=0; host_log("info", m); }
    int e = 0;
    e |= nhook("connect",       h_connect,       (void **)&o_connect);
    e |= nhook("getaddrinfo",   h_getaddrinfo,   (void **)&o_getaddrinfo);
    e |= nhook("gethostbyname", h_gethostbyname, (void **)&o_gethostbyname);
    e |= nhook("sendto",        h_sendto,        (void **)&o_sendto);
    e |= nhook("recvfrom",      h_recvfrom,      (void **)&o_recvfrom);
    host_log(e ? "warn" : "info", e ? "{\"ev\":\"allnet.hooks.partial\"}" : "{\"ev\":\"allnet.hooks.ok\"}");
    CreateThread(0, 0, allnet_listen, 0, 0, 0);
    CreateThread(0, 0, lfs_listen, 0, 0, 0);
}
