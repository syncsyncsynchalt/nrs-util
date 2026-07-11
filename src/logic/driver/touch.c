/* touch — COM1 タッチパネルのワイヤプロトコル emulate（touch.h 参照）。wire bytes を native serial 経路へ渡し、
 * game 自身のパーサ/SM に解釈させる（内部 report バッファ +0x2b8/+0x210 には触らない）。 */
#include "driver/touch.h"
#include <string.h>

/* 校正スケール相殺ゲイン（中心アンカー）。game は生レンジ(0..0xFFF)を画面より内側へ校正する
 * (touch_set_calib_window 0x8B3D60, k<1)ので送信前に 1/k 倍に拡大して相殺。1.0=無補正。 */
#ifndef TOUCH_GAIN_X
#define TOUCH_GAIN_X 1.0   /* TODO: 実測値に置換（1/(1−2p), p=左端カーソル時のタッチ表示位置/画面幅）*/
#endif
#ifndef TOUCH_GAIN_Y
#define TOUCH_GAIN_Y 1.0   /* TODO: 同上（縦比）*/
#endif

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
    int inside = 0;
    RECT rc;
    if (win && GetClientRect(win, &rc) && rc.right > rc.left && rc.bottom > rc.top) {
        long w = rc.right - rc.left, h = rc.bottom - rc.top;
        POINT cp = p;
        ScreenToClient(win, &cp);
        inside = (cp.x >= 0 && cp.x < w && cp.y >= 0 && cp.y < h);  /* client 矩形内か */
        long cx = cp.x < 0 ? 0 : (cp.x >= w ? w - 1 : cp.x);
        long cy = cp.y < 0 ? 0 : (cp.y >= h ? h - 1 : cp.y);
        /* client 0..1 正規化 → 中心基準でゲイン拡大（校正の中心引き込みを相殺）→ クランプ → 0..0xFFF。
           +0.5 で四捨五入（floor の左上偏りも解消）。t->x/y は反転前の生値（build_T で 0xFFF−x 反転）。 */
        double fx = (w > 1) ? (double)cx / (double)(w - 1) : 0.0;
        double fy = (h > 1) ? (double)cy / (double)(h - 1) : 0.0;
        fx = (fx - 0.5) * (double)TOUCH_GAIN_X + 0.5;
        fy = (fy - 0.5) * (double)TOUCH_GAIN_Y + 0.5;
        if (fx < 0.0) fx = 0.0; else if (fx > 1.0) fx = 1.0;
        if (fy < 0.0) fy = 0.0; else if (fy > 1.0) fy = 1.0;
        t->x = (uint16_t)(fx * (double)TOUCH_MAX + 0.5);
        t->y = (uint16_t)(fy * (double)TOUCH_MAX + 0.5);
    }
    /* 押下 = マウス左 or 'T' キー。ただし VK_LBUTTON はシステム全域で発火するため、
       「ゲーム窓が前面 かつ カーソルが client 矩形内」に限定する。これを外すと窓外クリックが
       端クランプ座標で誤タッチになる（窓外反応バグ）。座標は現カーソル位置。 */
    int focused = (win && win == GetForegroundWindow());
    int held = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) || (GetAsyncKeyState('T') & 0x8000);
    t->pressed = (held && focused && inside) ? 1 : 0;
}

/* 現座標の 'T' 座標フレームを out[10] に構築。X/Y は LE12bit, Z=筆圧, byte2=status(押下フラグ)。*/
static int build_T(const TouchPanel *t, uint8_t *out) {
    uint16_t z = t->pressed ? 0x00FFu : 0x0000u;
    /* パネル native 座標は両軸反転（game の decode_T_coord 0x8B31E0 が +0x21c=0xFFF−X / +0x220=0xFFF−Y で戻す）。
       ここで反転し game の反転と相殺する。片軸のみズレるなら該当軸の反転だけ外す。 */
    uint16_t wx = (uint16_t)(TOUCH_MAX - t->x);
    uint16_t wy = (uint16_t)(TOUCH_MAX - t->y);
    out[0] = (uint8_t)TOUCH_SYNC;            /* 'U' */
    out[1] = 'T';                            /* 0x54 = 座標レポート */
    out[2] = (uint8_t)(t->pressed ? 1 : 0);  /* status/id → ctx+0x166 */
    out[3] = (uint8_t)(wx & 0xff);
    out[4] = (uint8_t)((wx >> 8) & 0x0f);
    out[5] = (uint8_t)(wy & 0xff);
    out[6] = (uint8_t)((wy >> 8) & 0x0f);
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

/* game の TX フラッシュ(FUN_0067c070)は **1 バイトずつ WriteFile** する。よってバイトを蓄積し
   'U'(0x55) 始まりの 10B フレームを組み立ててから処理する（10B 一括前提だと n=1 で一生処理されない）。 */
void touch_on_write(TouchPanel *t, const uint8_t *buf, int n) {
    for (int i = 0; i < n; i++) {
        uint8_t byte = buf[i];
        if (t->rx_len == 0 && byte != (uint8_t)TOUCH_SYNC) continue;  /* 'U' まで同期待ち */
        if (t->rx_len < TOUCH_FRAME_LEN) t->rx[t->rx_len++] = byte;
        if (t->rx_len < TOUCH_FRAME_LEN) continue;                    /* まだ未完 */

        /* 10B フレーム完成。byte1=cmd で分岐。'p'(status照会)/'P'(param set)→ 'P'(byte3=6) ack。 */
        uint8_t cmd = t->rx[1];
        if (cmd == 'p' || cmd == 'P') {
            uint8_t f[TOUCH_FRAME_LEN];
            build_P(f);
            tx_push(t, f, TOUCH_FRAME_LEN);
        }
        /* 'R'(reset 0x52) は応答不要（game は timer 駆動で前進）。 */
        t->cmds++;
        t->rx_len = 0;                                                /* 次フレームへ */
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
