/* mxjvs — COM4 JVS ボードエミュ。pure frame handler は host 非依存(test 可)・global 無し(reload 安全)。
 * 正準 = micetools jvs_boards/jvs_base.c + jvs_837_14572.c（lift 元）。 */
#pragma once
#include <stdint.h>

enum {
    JVS_SYNC = 0xE0, JVS_MARK = 0xD0, JVS_NODE_MASTER = 0x00, JVS_NODE_BROADCAST = 0xFF,
    JVS_CMD_RESET = 0xF0, JVS_CMD_RESET_ASSERT = 0xD9, JVS_CMD_ASSIGN_ADDR = 0xF1,
    JVS_CMD_CHANGE_COMMS = 0xF2, JVS_CMD_READ_ID = 0x10, JVS_CMD_GET_CMD_VERSION = 0x11,
    JVS_CMD_GET_JVS_VERSION = 0x12, JVS_CMD_GET_COMM_VERSION = 0x13, JVS_CMD_GET_FEATURES = 0x14,
    JVS_CMD_RECEIVE_MAIN_ID = 0x15, JVS_CMD_READ_SW = 0x20, JVS_CMD_READ_COIN = 0x21,
    JVS_CMD_READ_ANALOG = 0x22, JVS_CMD_COIN_DECREASE = 0x30, JVS_CMD_WRITE_GPIO1 = 0x32,
    JVS_CMD_WRITE_GPIO2 = 0x37, JVS_CMD_WRITE_GPIO3 = 0x38,   /* (index,value) 2byte。micetools 確定 */
    JVS_REPORT_OK = 0x01, JVS_REPORT_PARAM_INVALID = 0x03,
    JVS_STATUS_OK = 0x01, JVS_STATUS_UKCOM = 0x02, JVS_STATUS_SUM = 0x03,
    JVS_FEAT_PLAYERS = 0x01, JVS_FEAT_COINS = 0x02, JVS_FEAT_ANALOG = 0x03,
    JVS_FEAT_GPIO = 0x12, JVS_FEAT_EOF = 0x00,
    JVS_PLAYERS = 2, JVS_BTNS = 13, JVS_COINS = 2, JVS_SWBYTES = 2, JVS_ANALOG_CH = 8,
    /* GET_FEATURES 申告値。nrs spec-check FUN_0067afa0 の受理条件は次の 4 つの ≥ のみ（満たさないと jvs_error_state=-102）:
         buttons/player >= 0x0e (node+0x101) / analog ch >= 0x02 (node+0x108) /
         gpio 出力数 >= 0x0d (node+0x124) / cmd_ver >= 0x13 (node+0x134)。BTNS/GPO は閾値ちょうどの最小値。
       sw ビット詰めは JVS_BTNS(=13) を使う（START→byte0 bit7 を保つため FEAT とは分離）。 */
    JVS_FEAT_BTNS = 14, JVS_FEAT_GPO = 13
};

/* JVS ボード状態。host arena に置く（型変更=restart）。 */
typedef struct {
    uint8_t  address;                 /* ASSIGN_ADDR で設定 */
    uint8_t  sense;                   /* sense out（1=未割当）*/
    uint8_t  test;                    /* TEST スイッチ (1bit) */
    uint8_t  coin_prev;               /* コイン投入のエッジ検出用 */
    uint16_t sw[JVS_PLAYERS];         /* プレイヤ別スイッチ 13bit（bit12=最上位ボタン）*/
    uint16_t coin[JVS_COINS];         /* コインカウンタ */
    uint16_t analog[JVS_ANALOG_CH];   /* アナログ ch（中心 0x8000）*/
} JvsBoard;

/* 論理入力（host が GetAsyncKeyState/XInput から poll → mxjvs_set_input でボードへ反映）。 */
typedef struct {
    uint8_t test, service, start, up, down, left, right, jump, dash, action;
    uint8_t coin;                     /* 押下中=1。立ち上がりで coin[0]++ */
    uint16_t analog_x, analog_y;      /* 中心 0x8000 */
} NrsInput;

void mxjvs_init(JvsBoard *b);
/* 論理入力 → JVS ボード状態（sw 13bit 配置/analog ch/test/coin エッジ）。bit 配置は facts/devices.md 準拠。 */
void mxjvs_set_input(JvsBoard *b, const NrsInput *in);

/* masked 配線フレーム in → masked 配線フレーム out。戻り=out バイト数（0=無応答/silence）。 */
int mxjvs_handle_frame(JvsBoard *b, const uint8_t *in, int in_len, uint8_t *out, int out_cap);
