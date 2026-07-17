#pragma once
#include <stdint.h>

enum {
    JVS_SYNC = 0xE0, JVS_MARK = 0xD0, JVS_NODE_MASTER = 0x00, JVS_NODE_BROADCAST = 0xFF,
    JVS_CMD_RESET = 0xF0, JVS_CMD_RESET_ASSERT = 0xD9, JVS_CMD_ASSIGN_ADDR = 0xF1,
    JVS_CMD_CHANGE_COMMS = 0xF2, JVS_CMD_READ_ID = 0x10, JVS_CMD_GET_CMD_VERSION = 0x11,
    JVS_CMD_GET_JVS_VERSION = 0x12, JVS_CMD_GET_COMM_VERSION = 0x13, JVS_CMD_GET_FEATURES = 0x14,
    JVS_CMD_RECEIVE_MAIN_ID = 0x15, JVS_CMD_READ_SW = 0x20, JVS_CMD_READ_COIN = 0x21,
    JVS_CMD_READ_ANALOG = 0x22, JVS_CMD_COIN_DECREASE = 0x30, JVS_CMD_WRITE_GPIO1 = 0x32,
    JVS_CMD_WRITE_GPIO2 = 0x37, JVS_CMD_WRITE_GPIO3 = 0x38,
    JVS_REPORT_OK = 0x01, JVS_REPORT_PARAM_INVALID = 0x03,
    JVS_STATUS_OK = 0x01, JVS_STATUS_UKCOM = 0x02, JVS_STATUS_SUM = 0x03,
    JVS_FEAT_PLAYERS = 0x01, JVS_FEAT_COINS = 0x02, JVS_FEAT_ANALOG = 0x03,
    JVS_FEAT_GPIO = 0x12, JVS_FEAT_EOF = 0x00,
    JVS_PLAYERS = 2, JVS_BTNS = 13, JVS_COINS = 2, JVS_SWBYTES = 2, JVS_ANALOG_CH = 8,
    JVS_FEAT_BTNS = 14, JVS_FEAT_GPO = 13
};

typedef struct {
    uint8_t  address;
    uint8_t  sense;
    uint8_t  test;
    uint8_t  coin_prev;
    uint16_t sw[JVS_PLAYERS];
    uint16_t coin[JVS_COINS];
    uint16_t analog[JVS_ANALOG_CH];
} JvsBoard;

typedef struct {
    uint8_t test, service, start, up, down, left, right, jump, dash, action;
    uint8_t coin;
    uint16_t analog_x, analog_y;
} NrsInput;

void mxjvs_init(JvsBoard *b);
void mxjvs_set_input(JvsBoard *b, const NrsInput *in);

int mxjvs_handle_frame(JvsBoard *b, const uint8_t *in, int in_len, uint8_t *out, int out_cap);
