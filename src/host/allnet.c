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
        char msg[160];
        _snprintf(msg, sizeof msg, "{\"ev\":\"allnet.connect\",\"ip\":\"%u.%u.%u.%u\",\"port\":%u}",
                  ip[0], ip[1], ip[2], ip[3], port);
        msg[sizeof msg - 1] = 0;
        host_log("info", msg);
    }
    return o_connect(s, addr, len);
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

/* NUPL コマンドの内部平文応答を組む（decode 済リクエスト req から）。エンベロープ = command_common(id echo)/
 * protocol_version=92b2d258/response_header=0 + command=base64(payload)。recv(FUN_00712710)が id 一致
 * (obj+0x20130) ＋ status0 で obj+0xd8=0 前進。payload はコマンド別: card-info=5611B / init=key=value。戻り=平文長。 */
static int build_nupl_inner(const unsigned char *req, int reqlen, char *out, int cap) {
    char cc[512]; field_value((const char *)req, reqlen, "command_common=", cc, sizeof cc);  /* echo */
    /* command= の値内に 0x30 挿入がある（"init_re0que0st"）ため prefix stem で判定。*/
    char cmd[64]; field_value((const char *)req, reqlen, "command=", cmd, sizeof cmd);
    (void)mem_contains;

    /* command=base64 は末尾に置く（decode 末端の影響回避）。区切り sub-field = literal "del"。 */
    if (strncmp(cmd, "cardinfo", 8) == 0) {
        unsigned char bin[CARDINFO_RESP_LEN]; build_cardinfo_binary(bin);
        static char pb64[CARDINFO_RESP_LEN * 2]; b64_encode(bin, CARDINFO_RESP_LEN, pb64, sizeof pb64);
        return _snprintf(out, cap, "response_header=0del&command_common=%s&protocol_version=92b2d258&command=%s&", cc, pb64);
    }
    if (strncmp(cmd, "init", 4) == 0) {
        /* init 応答は flat key=value レコード（serializer FUN_0092c3b0 と同型）。command は "init_response" 固定
         * （parser FUN_0092bb10 が strcmp 一致を要求）。local_uid/db_*_time は TOP-LEVEL フィールド。日付書式 "YYYY-MM-DD HH:MM:SS.f"。 */
        return _snprintf(out, cap,
            "command=init_response&protocol_version=92b2d258&command_common=%s&response_header=0del&"
            "local_uid=0000000000000000&db_start_time=2000-01-01 00:00:00.0&"
            "db_stop_time=2030-01-01 00:00:00.0&", cc);
    }
    return _snprintf(out, cap, "response_header=0del&command_common=%s&protocol_version=92b2d258&command=&", cc);
}

/* ---- ルーティング: path/body から応答 body を組む。戻り=body 長。*want_pragma=1 なら zlib+Pragma:DFI。 ---- */
static int build_response_body(const char *path, const char *body, int blen, char *out, int cap, int *want_pragma) {
    *want_pragma = 0;
    /* --- PowerOn: alAbEx auth を genuine 成立（stat=1 + uri=。平文・非エンコード）。uri=ゲームバックエンド URL。 --- */
    if (ci_find(path, "PowerOn")) {
        int n = _snprintf(out, cap,
            "stat=1&uri=http://%s/sys/servlet/&host=%s&"
            "region0=1&region_name0=JAPAN&region_name1=&region_name2=&region_name3=&"
            "place_id=1234&name=NRSEDGE&nickname=NRSEDGE&country=JPN&"
            "year=2026&month=7&day=2&hour=0&minute=0&second=0&setting=&res_class=PowerOnResponseVer2&",
            g_lan_ip, g_lan_ip);
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

    static char inner[CARDINFO_RESP_LEN * 2 + 1024];
    int innerlen = build_nupl_inner(reqdec, declen, inner, sizeof inner);
    { char snip[300]; json_str(snip, sizeof snip, inner, 200);
      char m[400]; _snprintf(m, sizeof m, "{\"ev\":\"allnet.nupl_resp\",\"innerlen\":%d,\"inner\":%s}", innerlen, snip);
      m[sizeof m - 1] = 0; host_log("info", m); }
    static unsigned char enc[CARDINFO_RESP_LEN * 2 + 1024];
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
    host_log(e ? "warn" : "info", e ? "{\"ev\":\"allnet.hooks.partial\"}" : "{\"ev\":\"allnet.hooks.ok\"}");
    CreateThread(0, 0, allnet_listen, 0, 0, 0);
}
