#!/usr/bin/env python3
"""TrueCrypt LRW mode (GfMul128Basic 準拠) — 公式テストベクタで検証。
出典: TrueCrypt 7.1a Common/GfMul.c, Volume/EncryptionModeLRW.cpp, Volume/EncryptionTest.cpp"""
import binascii
from Crypto.Cipher import AES

def is_bit_set128(i, a):
    return (a[(127 - i) // 8] >> (7 - ((127 - i) % 8))) & 1

def shl128(a):
    x = 0
    for i in range(15, -1, -1):
        xx = (a[i] & 0x80) >> 7
        a[i] = ((a[i] << 1) | x) & 0xff
        x = xx

def gf_mul128(a_in, b):
    la = bytearray(a_in); p = bytearray(16)
    for i in range(128):
        if is_bit_set128(i, b):
            for k in range(16): p[k] ^= la[k]
        if la[0] & 0x80:
            shl128(la); la[15] ^= 0x87
        else:
            shl128(la)
    return bytes(p)

def _tweak(tweak_key, block_index):
    # B = ゼロ8バイト + block_index の big-endian 8バイト ; t = tweak_key (x) B
    B = b'\x00'*8 + block_index.to_bytes(8, 'big')
    return gf_mul128(tweak_key, B)

def lrw_process(aes_key, tweak_key, data, block_index, decrypt):
    ecb = AES.new(aes_key, AES.MODE_ECB)
    out = bytearray(); idx = block_index
    for b in range(len(data)//16):
        t = _tweak(tweak_key, idx)
        blk = bytearray(data[b*16:b*16+16])
        for k in range(16): blk[k] ^= t[k]
        blk = ecb.decrypt(bytes(blk)) if decrypt else ecb.encrypt(bytes(blk))
        blk = bytearray(blk)
        for k in range(16): blk[k] ^= t[k]
        out += blk
        idx += 1
    return bytes(out)

def lrw_decrypt_header(aes_key, tweak_key, data):  # header: blockIndex は 1 始まり
    return lrw_process(aes_key, tweak_key, data, 1, True)

def sector_to_block_index(sector_index, sector_offset=1):
    return ((sector_index - sector_offset) << 5) | 1

if __name__ == '__main__':
    # 公式 LRW テストベクタ (EncryptionTest.cpp TestLegacyModes, AES)
    buf = bytes(range(256)) * 4  # 1024 バイト, buf[i]=i&0xff
    buf = bytes((i & 0xff) for i in range(1024))
    iv  = bytes(range(32))
    aes_key = buf[:32]          # AES-256 鍵
    tweak_key = iv[:16]         # LRW tweak 鍵 (mode key)
    secNo = 0x0234567890ABCDEF
    bi = sector_to_block_index(secNo, 1)
    ct = lrw_process(aes_key, tweak_key, buf, bi, decrypt=False)
    crc = binascii.crc32(ct) & 0xffffffff
    print("LRW AES test CRC = %08x  expected 5237acf9  %s" % (crc, "PASS" if crc==0x5237acf9 else "FAIL"))
