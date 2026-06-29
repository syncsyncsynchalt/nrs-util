/* touch — COM1 タッチパネル（class 0x22, 9600 8N1）。nrs.exe の touch_serial_rx_parse(0x8B2E40)/
 * touch_decode_T_coord(0x8B31E0)/touch_panel_init(0x8B2450) を実体逆コンパイルして確定した
 * ワイヤプロトコルを emulate する。正は facts/devices.md §タッチパネル。
 *
 * フレーム = 10 バイト固定長:  [0]='U'(0x55) [1]=cmd [2..8]=data(7B) [9]=checksum
 *   checksum = (Σ byte[0..8] − 0x56) & 0xff
 * cmd:  'T'=座標レポート(device→host) / 'p'=status 照会 / 'P'=param set/応答 / 'R'=reset (host→device)
 *
 * 'T' 座標ペイロード（LE16 枠, decode_T_coord 準拠）:
 *   byte[2]=status/id  byte[3:4]=X(12bit 0..0xFFF)  byte[5:6]=Y(12bit)  byte[7:8]=Z/筆圧(8bit)
 *
 * pure protocol（host 非依存・global 無し・reload 安全）。状態は host arena 上の TouchPanel。 */
#pragma once
#include "abi.h"
#include <stdint.h>

#define TOUCH_FRAME_LEN 10
#define TOUCH_SYNC      0x55u    /* 'U' 同期ヘッダ */
#define TOUCH_MAX       0x0FFFu  /* 12-bit 座標レンジ（decode_T_coord の clamp 値）*/

/* COM1 タッチパネルのプロトコル状態。host arena に置く（型変更=restart）。 */
typedef struct {
    uint16_t x, y;              /* 直近 panel 座標（0..0xFFF 生値。軸反転は game 側 0xFFF-X）*/
    uint8_t  pressed;           /* タッチ中（マウス左ボタン押下）*/
    uint8_t  tx[64];            /* device→host 応答キュー（handshake の 'P' ack）*/
    int      tx_len, tx_off;    /* 応答キューの書込/読出位置 */
    uint8_t  rx[TOUCH_FRAME_LEN]; /* host→device コマンド組立バッファ（game は 1 バイト/WriteFile で書く）*/
    int      rx_len;            /* 組立中バイト数 */
    unsigned reads;             /* ReadFile 回数（診断）*/
    unsigned cmds;              /* 受信した完全コマンドframe 数（診断）*/
} TouchPanel;

void touch_init(TouchPanel *t);

/* マウス位置 → panel 座標(0..0xFFF)＋押下状態を更新。win はゲーム窓（NULL なら foreground）。 */
void touch_sample_mouse(TouchPanel *t, HWND win);

/* game が書いた 10B コマンドフレーム列を処理し、必要な 'P' ack を応答キューへ積む。 */
void touch_on_write(TouchPanel *t, const uint8_t *buf, int n);

/* ReadFile 応答を out(cap) に詰める。queue済み ack を先に、続けて現座標の 'T' フレームを 1 つ流す。
   戻り = 書込バイト数。watchdog(+0x15c)を養いつつ座標を供給する。 */
int  touch_on_read(TouchPanel *t, uint8_t *out, int cap);
