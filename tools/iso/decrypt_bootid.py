#!/usr/bin/env python3
"""Boot ID を AES-128-CBC(m_Key,m_Iv) セクタ毎IVリセットで復号して構造をダンプ。
BTID 平文には game data 用のマスター鍵/keyfile が埋まっているはず。"""
import binascii,math
from collections import Counter
from Crypto.Cipher import AES
ISO=r"C:\src\DVR-5001.iso"; S=2048
KEY=binascii.unhexlify("6ACB8DC90049927AEACF71C9740B6FF9")
IV =binascii.unhexlify("A47A668EC0DA675E10E3A3EBE5328CF0")
def ap(b): return ''.join(chr(x) if 32<=x<127 else '.' for x in b)

# decrypt boot id region: vol 512.. (abs 1856), 128 sectors reserved
out=bytearray()
with open(ISO,'rb') as f:
    for sec in range(1856, 1856+128):
        f.seek(sec*S); d=f.read(S)
        out += AES.new(KEY,AES.MODE_CBC,IV).decrypt(d)   # per-sector IV reset

# trim trailing zeros for display
n=len(out)
while n>0 and out[n-1]==0: n-=1
print(f"Boot ID plaintext: {len(out)} bytes, non-zero up to {n}")
# hexdump first non-zero region
for off in range(0, min(n+16, len(out)), 16):
    chunk=out[off:off+16]
    if not any(chunk) and off>0 and not any(out[off-16:off]) and off+16<n:
        continue
    print(f"{off:05x}  {binascii.hexlify(chunk).decode():32}  {ap(chunk)}")
# save full plaintext
open(r"C:\src\nrs-util\tools\iso\bootid_plain.bin","wb").write(bytes(out))
print("saved bootid_plain.bin")
