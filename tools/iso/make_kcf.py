#!/usr/bin/env python3
"""SBVA KCF ファイル生成（micekeychip 用）。
AM_KCF = AM_APPBOOT(0x18) + AppData[216] + Seed[16] + Key[16] + Iv[16] + Unk[128] = 416B。
MiceParseKcf が読み込み後 m_Seed/m_Key/m_Iv を unscramble するので、ファイルには
scramble 済(=usable値に swap を適用)を書く。usable 値は kcf-ringedge.html(SBVA/JPN)。"""
import struct, binascii

SEED=binascii.unhexlify("DB86373A5A2E05B963C282D789128D0D")  # usable appboot seed
KEY =binascii.unhexlify("6ACB8DC90049927AEACF71C9740B6FF9")  # usable AES key
IV  =binascii.unhexlify("A47A668EC0DA675E10E3A3EBE5328CF0")  # usable AES iv

def swap(b,a1,a2,a3,a4):  # self-inverse: file = swap(usable) so MiceParseKcf swap(file)=usable
    d=bytearray(b); d[a1],d[a2]=d[a2],d[a1]; d[a3],d[a4]=d[a4],d[a3]; return bytes(d)

seed_f=swap(SEED,1,8,12,15)
key_f =swap(KEY,0,4,2,14)
iv_f  =swap(IV,0,11,5,15)

# AM_APPBOOT header (SBVA / RingEdge / JPN) from decrypted Boot ID + KCF DB
hdr=bytearray(0x18)
struct.pack_into('<I',hdr,0,0)            # m_Crc (unused by micekeychip path)
struct.pack_into('<I',hdr,4,1)            # m_Format: byte value (micekeychip sends %02X) &
                                          # KeychipCheck requires formattype==1. (was 0x00010000,
                                          # >0xFF -> overflowed micekeychip 3-byte buf -> fast-fail crash)
hdr[8:12]=b'SBVA'                          # m_GameId
hdr[0xc]=0x01                              # m_Region: 1=JPN
hdr[0xd]=0x02                              # m_ModelType (ST/SV; 2 ~ RingEdge2)
hdr[0xe]=0x64                              # m_SystemFlag (BTID flags 0x64)
hdr[0xf]=0
hdr[0x10:0x13]=b'AAL'                      # m_PlatformId: RingEdge (AAL)
hdr[0x13]=0x01                             # m_DvdFlag
struct.pack_into('<I',hdr,0x14,0x0035A8C0) # m_NetworkAddr 192.168.53.0 (from HTML subnet)

kcf=bytearray()
kcf+=hdr
kcf+=bytes(216)        # m_AppData
kcf+=seed_f            # m_Seed (scrambled)
kcf+=key_f             # m_Key (scrambled)
kcf+=iv_f             # m_Iv (scrambled)
kcf+=bytes(128)        # Unk
assert len(kcf)==0x18+216+16+16+16+128, len(kcf)

out=r"C:\src\nrs-util\tools\iso\config.kcf"
open(out,'wb').write(kcf)
print("wrote",out,len(kcf),"bytes")
print("verify: MiceParseKcf would unscramble to:")
print("  key:", binascii.hexlify(swap(key_f,0,4,2,14)).decode())
print("  iv :", binascii.hexlify(swap(iv_f,0,11,5,15)).decode())
print("  seed:",binascii.hexlify(swap(seed_f,1,8,12,15)).decode())
