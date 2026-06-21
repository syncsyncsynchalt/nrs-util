#!/usr/bin/env python3
"""検証済み TC4.3 AES-LRW で SSD パーティション(TC ボリューム)を復号してプレーン像を出力。
LRW tweak は M[k]=K2⊗2^k テーブルで高速化、AES-256-ECB は pycryptodome(C)。
usage: tc_decrypt_volume.py <img> <part_start_lba> <part_sectors> <keyfile|-> <password> <out>
"""
import sys, binascii, hashlib
sys.path.insert(0, __import__('os').path.dirname(__file__) or '.')
from lrw import gf_mul128
from Crypto.Cipher import AES

IMG, LBA, NSEC, KFP, PW, OUT = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5], sys.argv[6]
kf = b'' if KFP == '-' else open(KFP, 'rb').read()
pw = PW.encode() if PW != '-' else b''

_T=[]
for n in range(256):
    c=n
    for _ in range(8): c=(0xEDB88320^(c>>1)) if c&1 else c>>1
    _T.append(c)
def pool(password, keyfile):
    P=64;p=bytearray(P);crc=0xffffffff;w=0
    for b in keyfile[:1<<20]:
        crc=(crc>>8)^_T[(crc^b)&0xff]
        for sh in(24,16,8,0):p[w]=(p[w]+((crc>>sh)&0xff))&0xff;w=(w+1)%P
    q=bytearray(password)
    if len(q)<P:q+=bytes(P-len(q))
    for i in range(P):q[i]=(q[i]+p[i])&0xff
    return bytes(q)

def lrw_decrypt_header(aes_key, tweak_key, data):
    # header: block index は 1 始まり (低速パスだが 28 ブロックのみ)
    ecb=AES.new(aes_key,AES.MODE_ECB); out=bytearray(); idx=1
    for b in range(len(data)//16):
        B=b'\x00'*8+idx.to_bytes(8,'big'); t=gf_mul128(tweak_key,B)
        blk=bytes(a^b for a,b in zip(data[b*16:b*16+16],t))
        blk=ecb.decrypt(blk)
        out+=bytes(a^b for a,b in zip(blk,t)); idx+=1
    return bytes(out)

f=open(IMG,'rb')
f.seek(LBA*512); hdr=f.read(512); salt=hdr[:64]; e=hdr[64:512]
PWp=pool(pw,kf)
dk=hashlib.pbkdf2_hmac('ripemd160',PWp,salt,2000,64)
d=lrw_decrypt_header(dk[32:64],dk[0:16],e)
assert d[0:4]==b'TRUE', "not a valid TC volume / wrong keyfile"
mk=d[192:192+256]; m_tweak=mk[0:16]; m_aes=mk[32:64]
print("master AES:",binascii.hexlify(m_aes).decode(),flush=True)
ecb=AES.new(m_aes,AES.MODE_ECB)

# M[k] = K2 (x) 2^k を事前計算 (block_index は 64bit; k=0..47 をカバー)
M=[]
for k in range(48):
    B=b'\x00'*8 + (1<<k).to_bytes(8,'big')
    M.append(int.from_bytes(gf_mul128(m_tweak,B),'big'))
def tweak_int(n):
    t=0; k=0
    while n:
        if n&1: t^=M[k]
        n>>=1; k+=1
    return t

import time
out=open(OUT,'wb')
data_sectors=NSEC-1  # sector 0 = header; データはパーティション sector 1 から
CHUNK=8192  # 1回の読み込みあたりのセクタ数
written=0
f.seek((LBA+1)*512)
n=1                    # データ全体を通した連続 LRW block index (1 始まり)
T=tweak_int(n)        # 現在の tweak を int で保持 (block n 用)
t0=time.time()
while written < data_sectors:
    nsec=min(CHUNK, data_sectors-written)
    buf=f.read(nsec*512)
    if len(buf)<nsec*512: nsec=len(buf)//512
    ob=bytearray(nsec*512)
    for s in range(nsec):
        # 512バイトの tweak ストリーム (32 ブロック) を逐次構築
        tws=bytearray(512)
        for j in range(32):
            tws[j*16:j*16+16]=T.to_bytes(16,'big')
            d=n^(n+1); n+=1; k=0
            while d:
                if d&1: T^=M[k]
                d>>=1; k+=1
        tw_int=int.from_bytes(tws,'big')
        seg=int.from_bytes(buf[s*512:s*512+512],'big')^tw_int
        dec=ecb.decrypt(seg.to_bytes(512,'big'))
        ob[s*512:s*512+512]=((int.from_bytes(dec,'big')^tw_int).to_bytes(512,'big'))
    out.write(ob); written+=nsec
    if written % (CHUNK*8)==0 or written==data_sectors:
        mb=written*512/2**20; el=time.time()-t0
        print(f"  {mb:.0f} MB / {data_sectors*512/2**20:.0f} MB  ({mb/max(el,0.1):.1f} MB/s)",flush=True)
out.close(); f.close()
print("DONE ->",OUT,flush=True)
