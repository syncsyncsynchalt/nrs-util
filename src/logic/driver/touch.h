#pragma once
#include "abi.h"
#include <stdint.h>

#define TOUCH_FRAME_LEN 10
#define TOUCH_SYNC      0x55u
#define TOUCH_MAX       0x0FFFu

typedef struct {
    uint16_t x, y;
    uint8_t  pressed;
    uint8_t  tx[64];
    int      tx_len, tx_off;
    uint8_t  rx[TOUCH_FRAME_LEN];
    int      rx_len;
    unsigned reads;
    unsigned cmds;
} TouchPanel;

void touch_init(TouchPanel *t);

void touch_sample_mouse(TouchPanel *t, HWND win);

void touch_on_write(TouchPanel *t, const uint8_t *buf, int n);

int  touch_on_read(TouchPanel *t, uint8_t *out, int cap);
