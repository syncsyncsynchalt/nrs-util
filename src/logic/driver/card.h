/* card — COM2 IC Card R/W（class 0x21, SEGA 独自・**Aime 非該当**）。
 *
 * 素性（facts/devices.md §カードリーダー, 2026-06-30 Ghidra 実体 sweep で確定）:
 *   bare-byte command/ACK シリアル, **checksum 無し**, 8E1 / 9600。nrs.exe 自称 "IC Card R/W"。
 *   opcode→期待ACK は card_cmd_ack_expected(0x8850c0)、応答 status(* : J Z)は card_rx_status_decode(0x66f8a0)、
 *   カード種別バイト(0x36/0xc9/0xff)→容量(1984/960/4032B)は card_type_to_datalen(0x66f690)。
 *
 * 実装方針（touch.c と同型・CLAUDE.md 鉄則 #2 = OS 境界で仮想 COM 化, game 自身のパーサに解釈させる）:
 *   bring-up 第1段は **仮想化＋生バイトログ**。COM2 open/comm-control を成功させ、game が書く TX バイト列を
 *   観測してフレーミング（可変長・終端）を実トラフィックで裏取りしてから protocol logic を確定する
 *   （static RE のコマンド長は現状すべて推定。二度解かないため観測で確証する）。
 *
 * pure protocol（host 非依存・global 無し・reload 安全）。状態は host arena 上の CardReader。 */
#pragma once
#include "abi.h"
#include <stdint.h>

/* ---- 検証済みプロトコル定数（証明済みバイト定数。Builder VA は Ghidra DB）---- */
/* TX opcode（game→reader）。低ニブルが操作種別を符号化。 */
#define CARD_CMD_RESET      0xF7u  /* Reset / open                 (card_cmd_reset_0xF7  0x66fb80) */
#define CARD_CMD_INIT       0x28u  /* Init / session 開始 (→0xF7)  (card_cmd_init_0x28   0x66fcc0) */
#define CARD_CMD_POLL       0x4Du  /* Poll / カード検出            (card_cmd_poll_0x4D   0x670040) */
#define CARD_CMD_READ_ATTR  0x0Du  /* 属性ブロック read (+2B addr) (card_cmd_read_attr_0x0D 0x6704e0) */
#define CARD_CMD_READ_DATA  0x2Du  /* データ read (+8B addr/len BE)(card_cmd_read_data_0x2D 0x670300) */
#define CARD_CMD_READ_DATA2 0x8Du  /* データ read variant (+2B)    (card_cmd_read_data_0x8D 0x6708e0) */
#define CARD_CMD_WRITE      0xADu  /* データ write (+4B BE)        (card_cmd_write_0xAD  0x670dd0) */
#define CARD_CMD_STATUS     0x38u  /* Status / verify (→0xF7)      (card_cmd_status_0x38 0x66fe60) */
#define CARD_CMD_SLOT_ADDR  0x68u  /* スロット addressed (0x68,1,slot) (card_send_addressed_cmd_0x68 0x884f40) */
#define CARD_CMD_SLOT_SEL   0x6Du  /* スロット選択                 (ACK 'K') */
#define CARD_CMD_SETSPEED   0xB8u  /* SET COMM SPEED (0xB8 0xCF, init 最終段, card_cmd_setspeed_B8 0x884ff0)。
                                      ACK 0x0A→成功で game が SetCommState で baud 変更（仮想 COM は任意 baud 受容）*/
#define CARD_SPEED_ARG      0xCFu  /* 0xB8 の 2 バイト目（baud param）*/

/* opcode → 期待 ACK バイト（card_cmd_ack_expected 0x8850c0 の写し。送信側がこの 1 バイトを待つ）。 */
#define CARD_ACK_RESET      0xABu  /* 0x1D→0xAB（※ reset 系。0xF7→'\n' は下記 NL）*/
#define CARD_ACK_NL         0x0Au  /* '\n': {0x28,0x38,0x48,0x58,0x68,0x88,0xB8,0xF7} */
#define CARD_ACK_PLUS       0x2Bu  /* '+' : 0x0D */
#define CARD_ACK_8B         0x8Bu  /* 0x8B: {0x2D,0x8D,0xAD,0xCD,0xED} */
#define CARD_ACK_VT         0x0Bu  /* '\v': 0x4D */
#define CARD_ACK_K          0x4Bu  /* 'K' : 0x6D */

/* 応答ステータスバイト（card_rx_status_decode 0x66f8a0）。内部コード 0=pending,1=OK。 */
#define CARD_ST_OK_STAR     0x2Au  /* '*' → 3 */
#define CARD_ST_COLON       0x3Au  /* ':' → 4 */
#define CARD_ST_J           0x4Au  /* 'J' → 5 */
#define CARD_ST_Z           0x5Au  /* 'Z' → 6 */
#define CARD_ST_CB          0xCBu  /* 0xCB → 7 */
#define CARD_ST_BUSY        0x1Au  /* 0x1A → busy/retry */

/* カード種別バイト（reader→game）→ データ容量（card_type_to_datalen 0x66f690）。 */
#define CARD_TYPE_1984      0x36u  /* → 0x7C0 (1984B) */
#define CARD_TYPE_960       0xC9u  /* → 0x3C0 (960B)  */
#define CARD_TYPE_4032      0xFFu  /* → 0xFC0 (4032B) */
#define CARD_DATALEN_1984   0x7C0
#define CARD_DATALEN_960    0x3C0
#define CARD_DATALEN_4032   0xFC0

#define CARD_MAX_SLOTS      7      /* slot_addr_table_00b40bf4[0..6] */
#define CARD_HDR_BYTES      64     /* 16dword BE byte-swap ヘッダ(UID/属性) card_header_byteswap_be 0x66f6d0 */

/* status byte (フレーム byte1)。decode は card_rx_status_decode(0x66f8a0)。 */
#define CARD_STAT_OK        0x1Au  /* present/good（decode 8）*/
#define CARD_STAT_NOCARD    0x5Au  /* 'Z' = no-card（decode 6）*/

#define CARD_IMAGE_BYTES    0x1008 /* 永続カード image（card_op_dispatch cmd-class 3 / DAT_016b05f4）*/
#define CARD_HDR_UID_OFF    0x04   /* ヘッダ内 UID dword 位置（BE）。whitelist DAT_016a55b0[] 比較値 */

#define CARD_RX_CAP         32     /* game→reader コマンド組立（最長 0x2D=9B）*/
#define CARD_TX_CAP         256    /* reader→game 応答（最大 0x0D=129B）*/

/* COM2 IC Card R/W のプロトコル状態。host arena に置く（型変更=restart）。 */
typedef struct {
    uint8_t  rx[CARD_RX_CAP];   /* game→reader コマンド組立（1 バイト/WriteFile を蓄積）*/
    int      rx_len;            /* 組立中バイト数 */
    uint8_t  tx[CARD_TX_CAP];   /* reader→game 応答（[ACK b0][status b1][payload]）*/
    int      tx_len, tx_off;    /* 応答の書込/読出位置 */
    /* --- カード状態（Phase B: 仮想カード永続 R/W）--- */
    uint8_t  present;           /* カード挿入中（simulated）。Phase A 初期=0 */
    uint32_t uid;               /* カード UID（ヘッダ +0x04 BE。whitelist 照合値）*/
    uint8_t  card_type;         /* 種別バイト 0x36/0xC9/0xFF → 容量 1984/960/4032 */
    uint8_t  image[CARD_IMAGE_BYTES];  /* 永続カードデータ（card.bin の中身）*/
    /* --- Phase B R/W カーソル（0x2D select → 0x0D read / 0xAD write）--- */
    int      read_cursor;       /* 0x0D 連続 read の image オフセット（0x2D の addr で設定, +128/回）*/
    int      read_len;          /* 0x2D が指定した残り read 長（BE 4B。診断/境界）*/
    uint32_t write_addr;        /* 0xAD が指定した次 write の image オフセット（BE 4B）*/
    uint8_t  dirty;             /* image を変更済（eject/halt 契機で card.bin へ保存）*/
    /* --- 診断 --- */
    unsigned reads;             /* ReadFile 回数 */
    unsigned writes;            /* WriteFile バイト数 */
    unsigned cmds;              /* 認識した完全コマンド数 */
    uint8_t  last_op;           /* 直近に処理した opcode（診断/ログ）*/
} CardReader;

void card_init(CardReader *c);

/* game が COM2 へ書いたバイト列を蓄積し、opcode 長テーブルで完全コマンドを認識したら
   [ACK][status][payload] 応答を tx へ組む（半二重 turnaround モデル）。 */
void card_on_write(CardReader *c, const uint8_t *buf, int n);

/* ReadFile 応答を out(cap) に詰める（tx を排出）。戻り = 書込バイト数。 */
int  card_on_read(CardReader *c, uint8_t *out, int cap);

/* comm-control CLEAR_ERROR が申告すべき cbInQue（= tx の残量）。
   touch（常時 streaming）と異なり card は request/response ゆえ「応答がある時だけ」非ゼロ。 */
int  card_rx_pending(const CardReader *c);
