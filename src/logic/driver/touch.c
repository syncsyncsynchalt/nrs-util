#include "driver/touch.h"
#include <string.h>

#ifndef TOUCH_GAIN_X
#define TOUCH_GAIN_X 1.0
#endif
#ifndef TOUCH_GAIN_Y
#define TOUCH_GAIN_Y 1.0
#endif

static uint8_t touch_cksum(const uint8_t *f) {
    unsigned s = 0;
    for (int i = 0; i < 9; i++) s += f[i];
    return (uint8_t)((s - 0x56) & 0xff);
}

void touch_init(TouchPanel *t) {
    memset(t, 0, sizeof *t);
    t->x = TOUCH_MAX / 2;
    t->y = TOUCH_MAX / 2;
}

void touch_sample_mouse(TouchPanel *t, HWND win) {
    POINT p;
    if (!GetCursorPos(&p)) return;
    if (!win) win = GetForegroundWindow();
    int inside = 0;
    RECT rc;
    if (win && GetClientRect(win, &rc) && rc.right > rc.left && rc.bottom > rc.top) {
        long w = rc.right - rc.left, h = rc.bottom - rc.top;
        POINT cp = p;
        ScreenToClient(win, &cp);
        inside = (cp.x >= 0 && cp.x < w && cp.y >= 0 && cp.y < h);
        long cx = cp.x < 0 ? 0 : (cp.x >= w ? w - 1 : cp.x);
        long cy = cp.y < 0 ? 0 : (cp.y >= h ? h - 1 : cp.y);
        double fx = (w > 1) ? (double)cx / (double)(w - 1) : 0.0;
        double fy = (h > 1) ? (double)cy / (double)(h - 1) : 0.0;
        fx = (fx - 0.5) * (double)TOUCH_GAIN_X + 0.5;
        fy = (fy - 0.5) * (double)TOUCH_GAIN_Y + 0.5;
        if (fx < 0.0) fx = 0.0; else if (fx > 1.0) fx = 1.0;
        if (fy < 0.0) fy = 0.0; else if (fy > 1.0) fy = 1.0;
        t->x = (uint16_t)(fx * (double)TOUCH_MAX + 0.5);
        t->y = (uint16_t)(fy * (double)TOUCH_MAX + 0.5);
    }
    int focused = (win && win == GetForegroundWindow());
    int held = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) || (GetAsyncKeyState('T') & 0x8000);
    t->pressed = (held && focused && inside) ? 1 : 0;
}

static int build_T(const TouchPanel *t, uint8_t *out) {
    uint16_t z = t->pressed ? 0x00FFu : 0x0000u;
    uint16_t wx = (uint16_t)(TOUCH_MAX - t->x);
    uint16_t wy = (uint16_t)(TOUCH_MAX - t->y);
    out[0] = (uint8_t)TOUCH_SYNC;
    out[1] = 'T';
    out[2] = (uint8_t)(t->pressed ? 1 : 0);
    out[3] = (uint8_t)(wx & 0xff);
    out[4] = (uint8_t)((wx >> 8) & 0x0f);
    out[5] = (uint8_t)(wy & 0xff);
    out[6] = (uint8_t)((wy >> 8) & 0x0f);
    out[7] = (uint8_t)(z & 0xff);
    out[8] = (uint8_t)((z >> 8) & 0xff);
    out[9] = touch_cksum(out);
    return TOUCH_FRAME_LEN;
}

static int build_P(uint8_t *out) {
    memset(out, 0, TOUCH_FRAME_LEN);
    out[0] = (uint8_t)TOUCH_SYNC;
    out[1] = 'P';
    out[2] = '0';
    out[3] = 6;
    out[9] = touch_cksum(out);
    return TOUCH_FRAME_LEN;
}

static void tx_push(TouchPanel *t, const uint8_t *f, int n) {
    if (t->tx_off >= t->tx_len) t->tx_len = t->tx_off = 0;
    if (t->tx_len + n > (int)sizeof t->tx) return;
    memcpy(t->tx + t->tx_len, f, (size_t)n);
    t->tx_len += n;
}

void touch_on_write(TouchPanel *t, const uint8_t *buf, int n) {
    for (int i = 0; i < n; i++) {
        uint8_t byte = buf[i];
        if (t->rx_len == 0 && byte != (uint8_t)TOUCH_SYNC) continue;
        if (t->rx_len < TOUCH_FRAME_LEN) t->rx[t->rx_len++] = byte;
        if (t->rx_len < TOUCH_FRAME_LEN) continue;

        uint8_t cmd = t->rx[1];
        if (cmd == 'p' || cmd == 'P') {
            uint8_t f[TOUCH_FRAME_LEN];
            build_P(f);
            tx_push(t, f, TOUCH_FRAME_LEN);
        }
        t->cmds++;
        t->rx_len = 0;
    }
}

int touch_on_read(TouchPanel *t, uint8_t *out, int cap) {
    int o = 0;
    t->reads++;
    while (t->tx_off < t->tx_len && o < cap) out[o++] = t->tx[t->tx_off++];
    if (t->tx_off >= t->tx_len) t->tx_len = t->tx_off = 0;
    if (o + TOUCH_FRAME_LEN <= cap) o += build_T(t, out + o);
    return o;
}
