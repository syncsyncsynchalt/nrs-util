#include "driver/card.h"
#include <string.h>

void card_init(CardReader *c) {
    memset(c, 0, sizeof *c);
    c->card_type = CARD_TYPE_4032;
}

static int card_cmd_len(uint8_t op) {
    switch (op) {
    case CARD_CMD_READ_DATA:  return 9;
    case CARD_CMD_WRITE:      return 5;
    case CARD_CMD_SLOT_ADDR:  return 3;
    case CARD_CMD_SETSPEED:   return 2;
    case CARD_CMD_READ_ATTR:  return 3;
    default:                  return 1;
    }
}

static void emit(CardReader *c, uint8_t b) {
    if (c->tx_len < CARD_TX_CAP) c->tx[c->tx_len++] = b;
}
static void emit_n(CardReader *c, uint8_t b, int n) { for (int i = 0; i < n; i++) emit(c, b); }

static void card_build_response(CardReader *c) {
    uint8_t op = c->rx[0];
    c->tx_len = c->tx_off = 0;
    c->last_op = op;
    c->cmds++;

    switch (op) {
    case CARD_CMD_RESET:
    case CARD_CMD_INIT:
    case CARD_CMD_STATUS:
    case 0x48u:
    case CARD_CMD_SLOT_ADDR:
    case CARD_CMD_SETSPEED:
        emit(c, CARD_ACK_NL);
        break;
    case 0x58u:
        emit(c, CARD_ACK_NL); emit(c, CARD_STAT_OK);
        break;
    case 0x88u:
        emit(c, CARD_ACK_NL); emit_n(c, 0x00, 18);
        break;

    case CARD_CMD_POLL:
        if (c->present) {
            emit(c, CARD_ACK_VT);
            emit(c, CARD_STAT_OK);
            emit(c, c->card_type);
            emit(c, (uint8_t)(c->uid >> 24));
            emit(c, (uint8_t)(c->uid >> 16));
            emit(c, (uint8_t)(c->uid >> 8));
            emit(c, (uint8_t)(c->uid));
            emit(c, 0x00);
            emit(c, 0x00);
        } else {
            emit(c, CARD_STAT_NOCARD);
        }
        break;

    case CARD_CMD_READ_ATTR:
        emit(c, CARD_ACK_PLUS);
        if (c->present) {
            int off = c->read_cursor;
            for (int i = 0; i < 128; i++) {
                int p = off + i;
                emit(c, (p >= 0 && p < CARD_IMAGE_BYTES) ? c->image[p] : 0x00);
            }
            c->read_cursor = off + 128;
            if (c->read_len > 0) c->read_len -= (c->read_len < 128 ? c->read_len : 128);
        } else {
            emit_n(c, 0x00, 128);
        }
        break;

    case CARD_CMD_READ_DATA:
        c->read_cursor = 0;
        c->read_len = 0;
        emit(c, CARD_ACK_8B);
        break;

    case CARD_CMD_WRITE:
        if (c->rx_len >= 5)
            c->write_addr = (uint32_t)((c->rx[1] << 24) | (c->rx[2] << 16) | (c->rx[3] << 8) | c->rx[4]);
        emit(c, CARD_ACK_8B);
        break;

    case CARD_CMD_READ_DATA2:
    case 0xCDu:
    case 0xEDu: {
        uint8_t cap_hi = 0x00, cap_lo = 0x00;
        switch (c->card_type) {
        case CARD_TYPE_1984: cap_hi = (CARD_DATALEN_1984 >> 8) & 0xFF; cap_lo = CARD_DATALEN_1984 & 0xFF; break;
        case CARD_TYPE_960:  cap_hi = (CARD_DATALEN_960  >> 8) & 0xFF; cap_lo = CARD_DATALEN_960  & 0xFF; break;
        default:             cap_hi = (CARD_DATALEN_4032 >> 8) & 0xFF; cap_lo = CARD_DATALEN_4032 & 0xFF; break;
        }
        emit(c, CARD_ACK_8B); emit(c, cap_hi); emit(c, cap_lo);
        break;
    }

    case CARD_CMD_SLOT_SEL:
        emit(c, CARD_ACK_K); emit(c, 0x00); emit(c, 0x00);
        break;

    case 0x1Du:
        emit(c, CARD_ACK_RESET); emit_n(c, 0x00, 8);
        break;

    default:
        break;
    }
}

void card_on_write(CardReader *c, const uint8_t *buf, int n) {
    c->writes += (unsigned)(n < 0 ? 0 : n);
    for (int i = 0; i < n; i++) {
        uint8_t b = buf[i];
        if (c->rx_len >= CARD_RX_CAP) c->rx_len = 0;
        c->rx[c->rx_len++] = b;
        if (c->rx_len >= card_cmd_len(c->rx[0])) {
            card_build_response(c);
            c->rx_len = 0;
        }
    }
}

int card_on_read(CardReader *c, uint8_t *out, int cap) {
    int o = 0;
    c->reads++;
    while (c->tx_off < c->tx_len && o < cap) out[o++] = c->tx[c->tx_off++];
    if (c->tx_off >= c->tx_len) c->tx_len = c->tx_off = 0;
    return o;
}

int card_rx_pending(const CardReader *c) {
    int avail = c->tx_len - c->tx_off;
    return avail > 0 ? avail : 0;
}
