/* touch — COM1 タッチパネルのワイヤプロトコル emulate（touch.h 参照）。
 * nrs.exe の native serial 経路にそのまま wire bytes を渡す＝OS 境界仮想化（CLAUDE.md 鉄則 #2）。
 * 内部 report バッファ(+0x2b8/+0x210)には触らず、game 自身のパーサ/state machine に解釈させる。 */
#include "driver/touch.h"
#include <string.h>

/* checksum = (Σ byte[0..8] − 0x56) & 0xff（touch_serial_rx_parse 0x8B2E40 / 送信側 FUN_008b38f0 と同式）*/
static uint8_t touch_cksum(const uint8_t *f) {
    unsigned s = 0;
    for (int i = 0; i < 9; i++) s += f[i];
    return (uint8_t)((s - 0x56) & 0xff);
}

void touch_init(TouchPanel *t) {
    memset(t, 0, sizeof *t);
    t->x = TOUCH_MAX / 2;   /* 中央 */
    t->y = TOUCH_MAX / 2;
}

void touch_sample_mouse(TouchPanel *t, HWND win) {
    POINT p;
    if (!GetCursorPos(&p)) return;
    if (!win) win = GetForegroundWindow();
    RECT rc;
    if (win && GetClientRect(win, &rc) && rc.right > rc.left && rc.bottom > rc.top) {
        long w = rc.right - rc.left, h = rc.bottom - rc.top;
        ScreenToClient(win, &p);
        long cx = p.x < 0 ? 0 : (p.x >= w ? w - 1 : p.x);
        long cy = p.y < 0 ? 0 : (p.y >= h ? h - 1 : p.y);
        t->x = (uint16_t)((long long)cx * TOUCH_MAX / (w > 1 ? w - 1 : 1));
        t->y = (uint16_t)((long long)cy * TOUCH_MAX / (h > 1 ? h - 1 : 1));
    }
    t->pressed = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) ? 1 : 0;
}

/* 現座標の 'T' 座標フレームを out[10] に構築。X/Y は LE12bit, Z=筆圧, byte2=status(押下フラグ)。*/
static int build_T(const TouchPanel *t, uint8_t *out) {
    uint16_t z = t->pressed ? 0x00FFu : 0x0000u;
    out[0] = (uint8_t)TOUCH_SYNC;            /* 'U' */
    out[1] = 'T';                            /* 0x54 = 座標レポート */
    out[2] = (uint8_t)(t->pressed ? 1 : 0);  /* status/id → ctx+0x166 */
    out[3] = (uint8_t)(t->x & 0xff);
    out[4] = (uint8_t)((t->x >> 8) & 0x0f);
    out[5] = (uint8_t)(t->y & 0xff);
    out[6] = (uint8_t)((t->y >> 8) & 0x0f);
    out[7] = (uint8_t)(z & 0xff);
    out[8] = (uint8_t)((z >> 8) & 0xff);
    out[9] = touch_cksum(out);
    return TOUCH_FRAME_LEN;
}

/* 'P' param 応答フレーム（'p'/'P' コマンドへの ack）。
   byte1='P'(=送信側 +0x3a) で +0x3b=1 ack、byte3=6 で +0x28=1 → handshake state 0x1f→0x3c→ok。 */
static int build_P(uint8_t *out) {
    memset(out, 0, TOUCH_FRAME_LEN);
    out[0] = (uint8_t)TOUCH_SYNC;
    out[1] = 'P';     /* 0x50 */
    out[2] = '0';     /* 0x30: 送信フレームと同じ filler（parser は byte2 不参照）*/
    out[3] = 6;       /* param=6 → ctx+0x28=1 */
    out[9] = touch_cksum(out);
    return TOUCH_FRAME_LEN;
}

/* 応答キューへ追加（完全排出済みなら巻き戻してから）。溢れは捨てる（handshake は低頻度）。 */
static void tx_push(TouchPanel *t, const uint8_t *f, int n) {
    if (t->tx_off >= t->tx_len) t->tx_len = t->tx_off = 0;
    if (t->tx_len + n > (int)sizeof t->tx) return;
    memcpy(t->tx + t->tx_len, f, (size_t)n);
    t->tx_len += n;
}

void touch_on_write(TouchPanel *t, const uint8_t *buf, int n) {
    /* game の TX は 'U'(0x55) 始まり 10B フレーム（複数連結あり）。byte1 で分岐。 */
    for (int i = 0; i + TOUCH_FRAME_LEN <= n; ) {
        if (buf[i] != (uint8_t)TOUCH_SYNC) { i++; continue; }   /* 同期再取得 */
        uint8_t cmd = buf[i + 1];
        if (cmd == 'p' || cmd == 'P') {                          /* status 照会 / param set → 'P' ack */
            uint8_t f[TOUCH_FRAME_LEN];
            build_P(f);
            tx_push(t, f, TOUCH_FRAME_LEN);
        }
        /* 'R'(reset 0x52) は応答不要（game は +0xc timer 駆動で前進）。其他も無応答＝timeout 前進。 */
        i += TOUCH_FRAME_LEN;
    }
}

int touch_on_read(TouchPanel *t, uint8_t *out, int cap) {
    int o = 0;
    t->reads++;
    /* queue済み ack を先に排出 */
    while (t->tx_off < t->tx_len && o < cap) out[o++] = t->tx[t->tx_off++];
    if (t->tx_off >= t->tx_len) t->tx_len = t->tx_off = 0;
    /* 続けて現座標の 'T' フレームを 1 つ（cap に収まれば）。常時ストリームで watchdog を養う。 */
    if (o + TOUCH_FRAME_LEN <= cap) o += build_T(t, out + o);
    return o;
}
