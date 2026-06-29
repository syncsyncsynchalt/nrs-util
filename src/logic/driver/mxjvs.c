/* mxjvs — COM4 JVS ボード（115200 8N1）。micetools jvs_base.c + jvs_837_14572.c を lift。
 * フレーム: [E0][dst][len][payload...][sum]。len=payload+1(sum込)。0xE0/0xD0 は 0xD0,(b-1) でエスケープ。
 * 1 フレームに複数コマンド可（host は payload を順に消費）。応答: [E0][00][len][STATUS][report+data...][sum]。 */
#include "mxjvs.h"
#include <string.h>

/* READ_ID(0x10) 応答文字列。実機 RingEdge/RINGWIDE の JVS I/O ボードは FTDI USB の 837-15067 系
 * （ftdibus.inf: VID_0CA3 PID_0010..0015=837-15067(-00..-05), PID_000F=837-15121）。micetools は別世代の
 * 837-13551 を名乗るが本プロジェクトは実機型番に合わせる。Ver/日付サブフィールドは基板 ROM 内の値で未捕捉
 * （nrs.exe は ID 文字列を一切参照しない＝"837-"/"I/O BD" 文字列が binary に無く、spec-check も feature 数のみ）
 * ため SEGA 標準フォーマットでの最良推定。mxjvs.sys Build=Oct 2011 から日付帯のみ整合させた。 */
static const char BOARD_ID[] =
    "SEGA ENTERPRISES,LTD.;I/O BD JVS;837-15067 ;Ver1.00;11/05";
/* 版応答。nrs.exe spec-check(FUN_0067afa0)が gate するのは cmd_ver≥0x13 のみ（node_info +0x134）。
 * JVS_VER(0x12)/COMM_VER(0x13)は nrs では比較されない（実走でも 0x20/0x10 で init clean）。 */
#define CMD_VER 0x13   /* GET_CMD_VERSION: nrs 要求 ≥0x13、最小値ちょうど（実機 837-145xx も 0x13）*/
#define JVS_VER 0x20   /* GET_JVS_VERSION: nrs 非検査。JVS 規格 2.0 = 0x20（実機値は不問）*/
#define COMM_VER 0x10  /* GET_COMM_VERSION: nrs 非検査 */

void mxjvs_init(JvsBoard *b) {
    memset(b, 0, sizeof *b);
    b->address = 0xFF;
    b->sense = 1;
    for (int i = 0; i < JVS_ANALOG_CH; i++) b->analog[i] = 0x8000;  /* 中心 */
}

/* 論理入力 → JVS ボード。sw[0] 13bit 配置(facts/devices.md): bit12=START bit11=SERVICE bit10=UP
 * bit9=DOWN bit8=LEFT bit7=RIGHT bit6=PUSH1(jump) bit5=PUSH2(dash) bit4=PUSH3(action)。
 * READ_SW で v=sw<<3 され byte0 bit7=START… になる。analog: ch1=X ch0=Y（実機計測）。 */
void mxjvs_set_input(JvsBoard *b, const NrsInput *in) {
    uint16_t v = 0;
    if (in->start)  v |= 1u << 12;
    if (in->service)v |= 1u << 11;
    if (in->up)     v |= 1u << 10;
    if (in->down)   v |= 1u << 9;
    if (in->left)   v |= 1u << 8;
    if (in->right)  v |= 1u << 7;
    if (in->jump)   v |= 1u << 6;
    if (in->dash)   v |= 1u << 5;
    if (in->action) v |= 1u << 4;
    b->sw[0] = v;
    b->test = in->test ? 1 : 0;
    b->analog[1] = in->analog_x;   /* MOVE X */
    b->analog[0] = in->analog_y;   /* MOVE Y */
    if (in->coin && !b->coin_prev) b->coin[0]++;   /* 立ち上がりで加算 */
    b->coin_prev = in->coin ? 1 : 0;
}

/* masked → raw（SYNC は literal、以降の 0xD0 は次バイト+1）。戻り=raw 長, -1=異常。 */
static int unmask(const uint8_t *in, int n, uint8_t *raw, int cap) {
    if (n < 1 || cap < 1) return -1;
    raw[0] = in[0];
    int j = 1;
    for (int i = 1; i < n; i++) {
        if (j >= cap) return -1;
        if (in[i] == JVS_MARK) { if (++i >= n) return -1; raw[j++] = (uint8_t)(in[i] + 1); }
        else raw[j++] = in[i];
    }
    return j;
}

/* raw 応答(out[1..]) を masked 配線形式へ。raw[0]=SYNC は literal。戻り=wire 長。 */
static int mask(const uint8_t *raw, int n, uint8_t *wire, int cap) {
    if (cap < 1) return -1;
    wire[0] = raw[0];
    int j = 1;
    for (int i = 1; i < n; i++) {
        uint8_t b = raw[i];
        if (b == JVS_SYNC || b == JVS_MARK) {
            if (j + 2 > cap) return -1;
            wire[j++] = JVS_MARK; wire[j++] = (uint8_t)(b - 1);
        } else {
            if (j >= cap) return -1;
            wire[j++] = b;
        }
    }
    return j;
}

static uint8_t sum8(const uint8_t *p, int n) {
    unsigned s = 0; for (int i = 0; i < n; i++) s += p[i]; return (uint8_t)(s & 0xFF);
}

int mxjvs_handle_frame(JvsBoard *b, const uint8_t *in, int in_len, uint8_t *out, int out_cap) {
    uint8_t raw[512], resp[512];
    int rn = unmask(in, in_len, raw, sizeof raw);
    if (rn < 5 || raw[0] != JVS_SYNC) return 0;             /* 非 JVS / 短すぎ */
    uint8_t len = raw[2];
    if (3 + len > rn) return 0;                             /* 長さ不整合 */
    if (sum8(raw + 1, 1 + len) != raw[2 + len]) return 0;   /* checksum: dst..payload */

    int ri = 3;                  /* payload 先頭 */
    int end = 2 + len;           /* checksum の index（手前まで処理） */
    int wp = 0;                  /* resp の payload 書込み位置（STATUS の次から）*/
    uint8_t status = JVS_STATUS_OK;
    int silence = 0;

    #define RD() (ri < end ? raw[ri++] : 0)
    #define WR(x) do { if (4 + wp < (int)sizeof resp) resp[4 + wp++] = (uint8_t)(x); } while (0)

    while (ri < end) {
        uint8_t cmd = raw[ri++];
        switch (cmd) {
        case JVS_CMD_RESET:
            RD();                       /* arg = 0xD9 */
            b->address = 0xFF; b->sense = 1;
            silence = 1;                /* RESET は無応答 */
            break;
        case JVS_CMD_CHANGE_COMMS:
            silence = 1; break;
        case JVS_CMD_ASSIGN_ADDR:
            b->address = RD(); b->sense = 0;
            WR(JVS_REPORT_OK);
            break;
        case JVS_CMD_READ_ID:
            WR(JVS_REPORT_OK);
            for (size_t i = 0; i < sizeof BOARD_ID - 1; i++) WR(BOARD_ID[i]);
            WR(0x00);
            break;
        case JVS_CMD_GET_CMD_VERSION:  WR(JVS_REPORT_OK); WR(CMD_VER); break;
        case JVS_CMD_GET_JVS_VERSION:  WR(JVS_REPORT_OK); WR(JVS_VER); break;
        case JVS_CMD_GET_COMM_VERSION: WR(JVS_REPORT_OK); WR(COMM_VER); break;
        case JVS_CMD_GET_FEATURES:
            WR(JVS_REPORT_OK);
            WR(JVS_FEAT_PLAYERS); WR(JVS_PLAYERS); WR(JVS_FEAT_BTNS); WR(0);
            WR(JVS_FEAT_COINS);   WR(JVS_COINS);   WR(0);            WR(0);
            WR(JVS_FEAT_ANALOG);  WR(JVS_ANALOG_CH); WR(0);          WR(0);
            WR(JVS_FEAT_GPIO);    WR(JVS_FEAT_GPO); WR(0);           WR(0);
            WR(JVS_FEAT_EOF);
            break;
        case JVS_CMD_RECEIVE_MAIN_ID:
            while (ri < end && raw[ri] != 0) ri++;  /* 文字列を読み飛ばす */
            if (ri < end) ri++;                     /* 終端 null */
            WR(JVS_REPORT_OK);
            break;
        case JVS_CMD_READ_SW: {
            uint8_t players = RD(), swbytes = RD();
            if (players > JVS_PLAYERS || swbytes != JVS_SWBYTES) { WR(JVS_REPORT_PARAM_INVALID); break; }
            WR(JVS_REPORT_OK);
            WR(b->test ? 0x80 : 0x00);              /* system byte: bit7=TEST */
            for (int p = 0; p < players; p++) {
                uint16_t v = (uint16_t)(b->sw[p] << (16 - JVS_BTNS));  /* 13bit を左詰め */
                for (int i = swbytes - 1; i >= 0; i--) WR((v >> (i * 8)) & 0xFF);
            }
            break;
        }
        case JVS_CMD_READ_COIN: {
            uint8_t slots = RD();
            WR(JVS_REPORT_OK);
            for (int s = 0; s < slots && s < JVS_COINS; s++) {
                WR((b->coin[s] >> 8) & 0x3F);       /* 上位2bit=coin condition(0=normal) */
                WR(b->coin[s] & 0xFF);
            }
            break;
        }
        case JVS_CMD_READ_ANALOG: {
            uint8_t n = RD();
            WR(JVS_REPORT_OK);
            for (int i = 0; i < n; i++) {
                uint16_t a = (i < JVS_ANALOG_CH) ? b->analog[i] : 0x8000;
                WR((a >> 8) & 0xFF); WR(a & 0xFF);
            }
            break;
        }
        case JVS_CMD_COIN_DECREASE: {
            uint8_t slot = RD(); uint16_t amt = (uint16_t)(RD() << 8); amt |= RD();
            if (slot < JVS_COINS && b->coin[slot] >= amt) b->coin[slot] -= amt;
            WR(JVS_REPORT_OK);
            break;
        }
        case JVS_CMD_WRITE_GPIO1: {
            uint8_t nb = RD();
            for (int i = 0; i < nb; i++) RD();      /* solenoid 等。今は破棄 */
            WR(JVS_REPORT_OK);
            break;
        }
        case JVS_CMD_WRITE_GPIO2:                    /* 0x37/0x38 = (byteIndex, byteData)。破棄して OK */
        case JVS_CMD_WRITE_GPIO3:
            RD(); RD();
            WR(JVS_REPORT_OK);
            break;
        default:
            status = JVS_STATUS_UKCOM;
            ri = end;                               /* 不明コマンド: 以降中断 */
            break;
        }
    }
    #undef RD
    #undef WR

    if (silence) return 0;

    resp[0] = JVS_SYNC;
    resp[1] = JVS_NODE_MASTER;
    resp[2] = (uint8_t)(wp + 2);     /* len = STATUS + payload + sum */
    resp[3] = status;
    int raw_resp_len = 4 + wp;
    resp[raw_resp_len] = sum8(resp + 1, raw_resp_len - 1);  /* sum over [1..3+wp] */
    raw_resp_len += 1;

    return mask(resp, raw_resp_len, out, out_cap);
}
