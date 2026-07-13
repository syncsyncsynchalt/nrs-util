#!/usr/bin/env python3
"""make_card.py — BB (Border Break Scramble) 仮想カードイメージ生成。

RE 実証（facts/devices.md）: nrs.exe にとってカードは **ID に過ぎない**。プロフィールはサーバ側
（ALL.Net cardinfo 応答）で保持され、カードイメージ自体は UID + 空データで足りる。read SM
（card_read_sm 0x671470, bypass=1）はカード内容を検証せず、UID だけを抽出する。

イメージ構造（0x1008=4104B, card.c CARD_IMAGE_BYTES と一致）:
  [0x00..0x03]  予約/属性（byteswap 対象 u16 @0x02。既定 0）
  [0x04..0x07]  UID（big-endian dword）← card_header_byteswap_be 0x66f6d0 が in_EAX[1] として読む
  [0x08..0x3f]  ヘッダ残り属性（byteswap 対象 u16 @0x18/0x1a↔0x32/0x36。未解明・既定 0）
  [0x40..0xFC7] データ領域（4032B, サーバ authoritative ゆえ新規カードは 0 埋め）
  [0xFC8..0x1007] パディング

使い方:
  python make_card.py <出力パス> [UID(hex, 例 3a2a2d9d)]
  UID 省略時はランダム風の固定でなく引数必須（再現性のため）。
"""
import sys, struct

CARD_IMAGE_BYTES = 0x1008
UID_OFFSET = 0x04

def make_card(uid: int) -> bytes:
    buf = bytearray(CARD_IMAGE_BYTES)
    # UID を big-endian で offset 4 に配置（api.c: h[4]<<24|h[5]<<16|h[6]<<8|h[7] と対）
    struct.pack_into(">I", buf, UID_OFFSET, uid & 0xFFFFFFFF)
    return bytes(buf)

def main(argv):
    if len(argv) < 3:
        print("usage: make_card.py <out.bin> <UID hex, e.g. 3a2a2d9d>", file=sys.stderr)
        return 2
    out_path = argv[1]
    uid = int(argv[2], 16)
    data = make_card(uid)
    with open(out_path, "wb") as f:
        f.write(data)
    print(f"wrote {out_path} ({len(data)} bytes), UID={uid:08x} (BE @offset {UID_OFFSET:#x})")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
