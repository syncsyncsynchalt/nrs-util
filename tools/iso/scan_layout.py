#!/usr/bin/env python3
"""ISO のセクタ毎エントロピーをスキャンして暗号化領域の正確な開始を特定。
salt(高エントロピー)の開始 = TrueCrypt ボリューム先頭。"""
import math
from collections import Counter

ISO = r"C:\src\Border Break (Japan) (DVR-5001).iso"
SECTOR = 2048

def ent(b):
    if not b: return 0.0
    c = Counter(b); n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

with open(ISO, 'rb') as f:
    prev = None
    for sec in range(1340, 2130):
        f.seek(sec*SECTOR); d = f.read(SECTOR)
        e = ent(d)
        allzero = not any(d)
        kind = "ZERO" if allzero else ("HIGH" if e > 7.5 else ("low" if e < 4 else "mid"))
        if kind != prev or sec in (1855,1856,1983,1984,2111,2112):
            head = ' '.join(f'{x:02x}' for x in d[:12])
            print(f"sec {sec:5d} vol{sec-1344:5d}  H={e:5.3f} {kind:4}  {head}")
            prev = kind
