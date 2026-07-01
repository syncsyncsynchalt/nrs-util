/* card — COM2 IC Card R/W のワイヤプロトコル emulate（card.h 参照）。
 * nrs.exe の native serial 経路にそのまま wire bytes を渡す＝OS 境界仮想化（CLAUDE.md 鉄則 #2）。
 * カードコンテキスト内部(0x6720B)には触らず、game 自身のパーサ/state machine に解釈させる。
 *
 * プロトコル（facts/devices.md §カードリーダー, 2026-06-30 byte-exact RE で確定）:
 *   フレーム = [ACK byte0][status byte1][payload...]、可変長・checksum 無し・start/length/terminator 無し。
 *   受信側(card_rx_frame_complete 0x8848d0)は (受信byte0, 送信opcode) 対で長さを確定し、**再同期しない**。
 *   ゆえに「ACK byte0 を先頭に、opcode 表が要求する長さちょうど」を emit する（過剰=次フレーム破壊／不足=timeout）。
 *   consume 順 = byte0(ACK 一致必須, card_cmd_ack_expected 0x8850c0)→byte1(status, card_rx_status_decode 0x66f8a0)→payload。
 *
 * 半二重 turnaround モデル: game は 1 コマンド送信→応答 read→次、を厳守（phase 1→2 busy）。よって
 *   opcode 長テーブルで完全コマンドを認識したら即応答を組む（TX 長の不確実性に強い）。
 *
 * Phase A（現在）= handshake + poll-absent（no-card）。これで reader init が device-found/READY に到達し、
 *   boot CHECKING IC CARD R/W が実コードの ready bit で通る（→将来 RET1 patch 撤去可）。
 * Phase B（次）= カード挿入(present=1)＋ヘッダ/データ read(0x0D/0x2D)＋write(0xAD)＋card.bin 永続化。
 *   8B poll record と 0x1008B image の内部レイアウトは live 観測（card.write/card.read）で最終確証してから実装。 */
#include "driver/card.h"
#include <string.h>

void card_init(CardReader *c) {
    memset(c, 0, sizeof *c);
    c->card_type = CARD_TYPE_4032;   /* 既定 4032B カード（Phase B で挿入時に使用）*/
    /* present=0: Phase A はカード未挿入。boot は ready bit のみ要求しカード挿入は要求しないため通る。 */
}

/* opcode → 送信コマンド総バイト数（先頭 opcode 含む）。完全コマンド認識用（card.h のコマンド表）。
   不確実な trailer（0xF7/0x4D に "+trailer" 疑いあり）は core 長 1 とし、card.write ログで検証する。 */
static int card_cmd_len(uint8_t op) {
    switch (op) {
    case CARD_CMD_READ_DATA:  return 9;   /* 0x2D + 8B UID(select by UID) */
    case CARD_CMD_WRITE:      return 5;   /* 0xAD + 4B addr BE (card_cmd_commit_AD) */
    case CARD_CMD_SLOT_ADDR:  return 3;   /* 0x68, p1, p2 (card_send_68) */
    case CARD_CMD_SETSPEED:   return 2;   /* 0xB8 0xCF SET COMM SPEED (card_cmd_setspeed_B8 0x884ff0) */
    /* 0x0D read block = **3 バイト** `0d HH LL`（live 確証 2026-07-01: `0d 00 00`。static の「単バイト」推測は誤り。
       1B 扱いだと続く `00 00` を別 opcode 0x00 として処理し card_build_response が tx をリセット→0x2B+128B 応答を消去し
       「データ読み込み中…」で停止する）。*/
    case CARD_CMD_READ_ATTR:  return 3;
    default:                  return 1;   /* handshake/poll/slot-sel 等（単バイト）*/
    }
}

static void emit(CardReader *c, uint8_t b) {
    if (c->tx_len < CARD_TX_CAP) c->tx[c->tx_len++] = b;
}
static void emit_n(CardReader *c, uint8_t b, int n) { for (int i = 0; i < n; i++) emit(c, b); }

/* 完全コマンド rx[0..rx_len) を解釈し、[ACK][status][payload] 応答を tx へ組む（半二重ゆえ tx は空のはず）。 */
static void card_build_response(CardReader *c) {
    uint8_t op = c->rx[0];
    c->tx_len = c->tx_off = 0;        /* 直前応答は read 済（半二重）。新規フレーム */
    c->last_op = op;
    c->cmds++;

    switch (op) {
    /* ---- handshake: ACK 0x0A 単バイト（status byte 無し→decode 9 generic OK で前進）---- */
    case CARD_CMD_RESET:    /* 0xF7 */
    case CARD_CMD_INIT:     /* 0x28 */
    case CARD_CMD_STATUS:   /* 0x38 */
    case 0x48u:             /* init step */
    case CARD_CMD_SLOT_ADDR:/* 0x68 slot/addr select */
    case CARD_CMD_SETSPEED: /* 0xB8 0xCF SET COMM SPEED（init 最終段）→ ACK 0x0A、成功で game が SetCommState */
        emit(c, CARD_ACK_NL);                 /* 0x0A（frame len: byte0=0x0A & 非0x58/0x88 → count==1）*/
        break;
    case 0x58u:                               /* byte0=0x0A cmd==0x58 → len 2 */
        emit(c, CARD_ACK_NL); emit(c, CARD_STAT_OK);   /* 0A 1A */
        break;
    case 0x88u:                               /* byte0=0x0A cmd==0x88 → len 19 */
        emit(c, CARD_ACK_NL); emit_n(c, 0x00, 18);
        break;

    /* ---- poll 0x4D SEARCH（anti-collision/UID read）。present/absent は ACK 一致極性で決まる ---- */
    case CARD_CMD_POLL:
        if (c->present) {
            /* present: byte0=0x0B が 0x4D の ACK と一致 → card_status_decode(0x66f8a0)→1（present）。
               続く 8B は card_get_uid_record(0x885260) が byteswap して UID(DAT_0169e314)/type(DAT_0169e31c)を取る。
               frame len: byte0=0x0B → count==9。
               ★ Phase B 暫定エンコード: [0B][status 1A][type][UID 4B BE][pad 1B]。
                 8B record の **正確なバイト順は未確定**。挿入後に card.read ログの hex を実トラフィックと突き合わせて
                 確定する（facts/devices.md §B2）。boot は present=0 経路なので本エンコード誤りは boot を壊さない。*/
            /* frame len 則: byte0=0x0B → **計 9 バイト**（0x0B + 8B payload。card_get_uid_record 0x885260 が
               payload 8B を DAT_01265722..29 に取り込む）。payload が 8B 未満だと re-sync 崩壊→read SM が -0x61(-97)。 */
            emit(c, CARD_ACK_VT);             /* 0x0B（ACK・frame 先頭）*/
            emit(c, CARD_STAT_OK);            /* payload[0] = 0x1A status */
            emit(c, c->card_type);            /* payload[1] = 種別バイト */
            emit(c, (uint8_t)(c->uid >> 24)); /* payload[2..5] = UID BE（whitelist 照合値・byte順は live 確証中）*/
            emit(c, (uint8_t)(c->uid >> 16));
            emit(c, (uint8_t)(c->uid >> 8));
            emit(c, (uint8_t)(c->uid));
            emit(c, 0x00);                    /* payload[6] */
            emit(c, 0x00);                    /* payload[7] → payload 計 8B、frame 計 9B */
        } else {
            /* no-card: 単バイト 0x5A。byte0=0x5A は ACK(0x0B)と不一致→cVar1=0、DL に残る 0x5A='Z'→decode 6（nocard）。
               frame validator(0x8848d0) は byte0=0x5A を count==1 で完成扱い。
               ※`0B 5A…` だと byte0=0x0B が ACK 一致→decode 1=present 誤認になる（実機極性 FUN_008850c0 で確定）。*/
            emit(c, CARD_STAT_NOCARD);        /* 0x5A 単独 */
        }
        break;

    /* ---- read block 0x0D: ACK 0x2B + 128B（image[read_cursor..]を順次供給）。len 129 ----
       card.bin = ワイヤ image そのもの（loader が UID@+0x04 BE 込みで生成）ゆえ swap せず素直に供給する。
       ヘッダ byteswap は game 内部（card_header_byteswap_be 0x66f6d0）の仕事でエミュ側は不要。
       0x2D select が read_cursor を立てる。未 select 時は cursor=0（先頭=ヘッダ block）から。*/
    case CARD_CMD_READ_ATTR:
        emit(c, CARD_ACK_PLUS);               /* 0x2B */
        if (c->present) {
            int off = c->read_cursor;
            for (int i = 0; i < 128; i++) {
                int p = off + i;
                emit(c, (p >= 0 && p < CARD_IMAGE_BYTES) ? c->image[p] : 0x00);
            }
            c->read_cursor = off + 128;       /* 次 block へ前進 */
            if (c->read_len > 0) c->read_len -= (c->read_len < 128 ? c->read_len : 128);
        } else {
            emit_n(c, 0x00, 128);
        }
        break;

    /* ---- select-by-UID 0x2D（+8B UID record）: addr ではなく UID 選択。read cursor を image 先頭へ戻す ----
       live 確証(2026-07-01): 0x2D の 8B は SEARCH で返した UID record（例 `5991...`）であって read アドレスではない。
       以後の 0x0D 連続 read は image を先頭から順次供給する（block index は 0x68/0x0D 引数だが、まず順次供給で読込完了を狙う）。*/
    case CARD_CMD_READ_DATA:
        c->read_cursor = 0;                   /* image 先頭から順次 read */
        c->read_len = 0;
        emit(c, CARD_ACK_8B);                 /* 0x8B */
        break;

    /* ---- write commit 0xAD（+4B addr BE）: write_addr を立て ACK 0x8B（len1）----
       ★ 後続 write データのフレーミングは **未確定**。0xAD 自体はコミット指示で本コマンドにデータは載らない
       （card_cmd_len(0xAD)=5）。実 write が走ったときの data-bearing 経路は card.write ログで観測して確定する
       （最も live 観測を要する箇所。facts/devices.md §B2）。確定したら image[write_addr++] へ staging＋dirty。*/
    case CARD_CMD_WRITE:
        if (c->rx_len >= 5)
            c->write_addr = (uint32_t)((c->rx[1] << 24) | (c->rx[2] << 16) | (c->rx[3] << 8) | c->rx[4]);
        emit(c, CARD_ACK_8B);                 /* 0x8B */
        break;

    /* ---- read-data2 0x8D/0xCD/0xED: ACK 0x8B + b1 + b2（card_get_status2 0x885350, 容量/free 等）---- */
    case CARD_CMD_READ_DATA2:
    case 0xCDu:
    case 0xEDu: {
        /* 暫定: card_type→容量(byte) を 2B status2 に載せる。正確な意味（free/ptr）は live 確証。 */
        uint8_t cap_hi = 0x00, cap_lo = 0x00;
        switch (c->card_type) {
        case CARD_TYPE_1984: cap_hi = (CARD_DATALEN_1984 >> 8) & 0xFF; cap_lo = CARD_DATALEN_1984 & 0xFF; break;
        case CARD_TYPE_960:  cap_hi = (CARD_DATALEN_960  >> 8) & 0xFF; cap_lo = CARD_DATALEN_960  & 0xFF; break;
        default:             cap_hi = (CARD_DATALEN_4032 >> 8) & 0xFF; cap_lo = CARD_DATALEN_4032 & 0xFF; break;
        }
        emit(c, CARD_ACK_8B); emit(c, cap_hi); emit(c, cap_lo);
        break;
    }

    /* ---- 0x6D slot-sel: ACK 0x4B + b1 + b2 ---- */
    case CARD_CMD_SLOT_SEL:
        emit(c, CARD_ACK_K); emit(c, 0x00); emit(c, 0x00);
        break;

    /* ---- 0x1D: ACK 0xAB + 8B ---- */
    case 0x1Du:
        emit(c, CARD_ACK_RESET); emit_n(c, 0x00, 8);
        break;

    default:
        /* 未知 opcode: ACK せず観測のみ（card.write ログで拾う）。tx 空のまま=cbInQue 0。 */
        break;
    }
}

void card_on_write(CardReader *c, const uint8_t *buf, int n) {
    c->writes += (unsigned)(n < 0 ? 0 : n);
    for (int i = 0; i < n; i++) {
        uint8_t b = buf[i];
        if (c->rx_len >= CARD_RX_CAP) c->rx_len = 0;          /* overflow 保護（再同期）*/
        c->rx[c->rx_len++] = b;
        if (c->rx_len >= card_cmd_len(c->rx[0])) {            /* 完全コマンド認識 → 応答生成 */
            card_build_response(c);
            c->rx_len = 0;
        }
    }
}

int card_on_read(CardReader *c, uint8_t *out, int cap) {
    int o = 0;
    c->reads++;
    while (c->tx_off < c->tx_len && o < cap) out[o++] = c->tx[c->tx_off++];
    if (c->tx_off >= c->tx_len) c->tx_len = c->tx_off = 0;    /* drained → rewind */
    return o;
}

int card_rx_pending(const CardReader *c) {
    int avail = c->tx_len - c->tx_off;
    return avail > 0 ? avail : 0;
}
