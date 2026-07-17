#include "input.h"
#include <windows.h>
#include <string.h>

static int kd(int vk) { return vk && (GetAsyncKeyState(vk) & 0x8000) != 0; }

void nrs_poll_input(NrsInput *o, const unsigned short *b) {
    static const unsigned short defb[ACT_COUNT] =
        { 0x70, 0x71, 0x35, 0x31, 0x26, 0x28, 0x25, 0x27, 0x5A, 0x58, 0x43 };
    if (!b) b = defb;
    memset(o, 0, sizeof *o);
    o->test    = (uint8_t)kd(b[ACT_TEST]);
    o->service = (uint8_t)kd(b[ACT_SERVICE]);
    o->coin    = (uint8_t)kd(b[ACT_COIN]);
    o->start   = (uint8_t)kd(b[ACT_START]);
    o->up      = (uint8_t)kd(b[ACT_UP]);
    o->down    = (uint8_t)kd(b[ACT_DOWN]);
    o->left    = (uint8_t)kd(b[ACT_LEFT]);
    o->right   = (uint8_t)kd(b[ACT_RIGHT]);
    o->jump    = (uint8_t)kd(b[ACT_JUMP]);
    o->dash    = (uint8_t)kd(b[ACT_DASH]);
    o->action  = (uint8_t)kd(b[ACT_ACTION]);
    o->analog_x = o->left ? 0x0000 : (o->right ? 0xFFFF : 0x8000);
    o->analog_y = o->up   ? 0x0000 : (o->down  ? 0xFFFF : 0x8000);
}
