#pragma once
#include "abi.h"
#include <stdint.h>

#define CARD_CMD_RESET      0xF7u
#define CARD_CMD_INIT       0x28u
#define CARD_CMD_POLL       0x4Du
#define CARD_CMD_READ_ATTR  0x0Du
#define CARD_CMD_READ_DATA  0x2Du
#define CARD_CMD_READ_DATA2 0x8Du
#define CARD_CMD_WRITE      0xADu
#define CARD_CMD_STATUS     0x38u
#define CARD_CMD_SLOT_ADDR  0x68u
#define CARD_CMD_SLOT_SEL   0x6Du
#define CARD_CMD_SETSPEED   0xB8u
#define CARD_SPEED_ARG      0xCFu

#define CARD_ACK_RESET      0xABu
#define CARD_ACK_NL         0x0Au
#define CARD_ACK_PLUS       0x2Bu
#define CARD_ACK_8B         0x8Bu
#define CARD_ACK_VT         0x0Bu
#define CARD_ACK_K          0x4Bu

#define CARD_ST_OK_STAR     0x2Au
#define CARD_ST_COLON       0x3Au
#define CARD_ST_J           0x4Au
#define CARD_ST_Z           0x5Au
#define CARD_ST_CB          0xCBu
#define CARD_ST_BUSY        0x1Au

#define CARD_TYPE_1984      0x36u
#define CARD_TYPE_960       0xC9u
#define CARD_TYPE_4032      0xFFu
#define CARD_DATALEN_1984   0x7C0
#define CARD_DATALEN_960    0x3C0
#define CARD_DATALEN_4032   0xFC0

#define CARD_MAX_SLOTS      7
#define CARD_HDR_BYTES      64

#define CARD_STAT_OK        0x1Au
#define CARD_STAT_NOCARD    0x5Au

#define CARD_IMAGE_BYTES    0x1008
#define CARD_HDR_UID_OFF    0x04

#define CARD_RX_CAP         32
#define CARD_TX_CAP         256

typedef struct {
    uint8_t  rx[CARD_RX_CAP];
    int      rx_len;
    uint8_t  tx[CARD_TX_CAP];
    int      tx_len, tx_off;
    uint8_t  present;
    uint32_t uid;
    uint8_t  card_type;
    uint8_t  image[CARD_IMAGE_BYTES];
    int      read_cursor;
    int      read_len;
    uint32_t write_addr;
    uint8_t  dirty;
    unsigned reads;
    unsigned writes;
    unsigned cmds;
    uint8_t  last_op;
} CardReader;

void card_init(CardReader *c);

void card_on_write(CardReader *c, const uint8_t *buf, int n);

int  card_on_read(CardReader *c, uint8_t *out, int cap);

int  card_rx_pending(const CardReader *c);
