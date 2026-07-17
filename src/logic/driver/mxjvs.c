#include "mxjvs.h"
#include <string.h>

static const char BOARD_ID[] =
    "SEGA ENTERPRISES,LTD.;I/O BD JVS;837-15067 ;Ver1.00;11/05";
#define CMD_VER 0x13
#define JVS_VER 0x20
#define COMM_VER 0x10

void mxjvs_init(JvsBoard *b) {
    memset(b, 0, sizeof *b);
    b->address = 0xFF;
    b->sense = 1;
    for (int i = 0; i < JVS_ANALOG_CH; i++) b->analog[i] = 0x8000;
}

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
    b->analog[1] = in->analog_x;
    b->analog[0] = in->analog_y;
    if (in->coin && !b->coin_prev) b->coin[0]++;
    b->coin_prev = in->coin ? 1 : 0;
}

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
    if (rn < 5 || raw[0] != JVS_SYNC) return 0;
    uint8_t len = raw[2];
    if (3 + len > rn) return 0;
    if (sum8(raw + 1, 1 + len) != raw[2 + len]) return 0;

    int ri = 3;
    int end = 2 + len;
    int wp = 0;
    uint8_t status = JVS_STATUS_OK;
    int silence = 0;

    #define RD() (ri < end ? raw[ri++] : 0)
    #define WR(x) do { if (4 + wp < (int)sizeof resp) resp[4 + wp++] = (uint8_t)(x); } while (0)

    while (ri < end) {
        uint8_t cmd = raw[ri++];
        switch (cmd) {
        case JVS_CMD_RESET:
            RD();
            b->address = 0xFF; b->sense = 1;
            silence = 1;
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
            while (ri < end && raw[ri] != 0) ri++;
            if (ri < end) ri++;
            WR(JVS_REPORT_OK);
            break;
        case JVS_CMD_READ_SW: {
            uint8_t players = RD(), swbytes = RD();
            if (players > JVS_PLAYERS || swbytes != JVS_SWBYTES) { WR(JVS_REPORT_PARAM_INVALID); break; }
            WR(JVS_REPORT_OK);
            WR(b->test ? 0x80 : 0x00);
            for (int p = 0; p < players; p++) {
                uint16_t v = (uint16_t)(b->sw[p] << (16 - JVS_BTNS));
                for (int i = swbytes - 1; i >= 0; i--) WR((v >> (i * 8)) & 0xFF);
            }
            break;
        }
        case JVS_CMD_READ_COIN: {
            uint8_t slots = RD();
            WR(JVS_REPORT_OK);
            for (int s = 0; s < slots && s < JVS_COINS; s++) {
                WR((b->coin[s] >> 8) & 0x3F);
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
            for (int i = 0; i < nb; i++) RD();
            WR(JVS_REPORT_OK);
            break;
        }
        case JVS_CMD_WRITE_GPIO2:
        case JVS_CMD_WRITE_GPIO3:
            RD(); RD();
            WR(JVS_REPORT_OK);
            break;
        default:
            status = JVS_STATUS_UKCOM;
            ri = end;
            break;
        }
    }
    #undef RD
    #undef WR

    if (silence) return 0;

    resp[0] = JVS_SYNC;
    resp[1] = JVS_NODE_MASTER;
    resp[2] = (uint8_t)(wp + 2);
    resp[3] = status;
    int raw_resp_len = 4 + wp;
    resp[raw_resp_len] = sum8(resp + 1, raw_resp_len - 1);
    raw_resp_len += 1;

    return mask(resp, raw_resp_len, out, out_cap);
}
