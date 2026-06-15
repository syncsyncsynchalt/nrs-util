#!/usr/bin/env python3
"""プロセスメモリを走査して needle 文字列(ASCII/UTF-16)を探す.

VMProtect 等でパックされた DLL をロードした host プロセスのメモリを読み、
ロード時アンパックで復号された文字列が現れるかを確認する。
64bit python から WOW64(32bit) プロセスも読める(ReadProcessMemory)。

usage: python tools/re/memscan.py <pid> <needle1> [needle2 ...]
"""
import sys, ctypes as C
from ctypes import wintypes as W

k32 = C.WinDLL('kernel32', use_last_error=True)

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
READABLE = (0x02, 0x04, 0x08, 0x20, 0x40, 0x80, 0x10)  # any committed readable prot


class MEMORY_BASIC_INFORMATION64(C.Structure):
    _fields_ = [("BaseAddress", C.c_ulonglong), ("AllocationBase", C.c_ulonglong),
                ("AllocationProtect", W.DWORD), ("__alignment1", W.DWORD),
                ("RegionSize", C.c_ulonglong), ("State", W.DWORD),
                ("Protect", W.DWORD), ("Type", W.DWORD), ("__alignment2", W.DWORD)]


def main():
    pid = int(sys.argv[1])
    needles = sys.argv[2:]
    pats = []
    for n in needles:
        pats.append((n, n.encode('ascii', 'ignore'), 'ascii'))
        pats.append((n, n.encode('utf-16-le'), 'utf16'))

    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        print(f"OpenProcess failed err={C.get_last_error()}")
        return 1
    k32.VirtualQueryEx.restype = C.c_size_t
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION64()
    total = 0
    found = {}
    while addr < 0x7fffffff0000:
        r = k32.VirtualQueryEx(h, C.c_void_p(addr), C.byref(mbi), C.sizeof(mbi))
        if not r:
            break
        size = mbi.RegionSize
        if mbi.State == MEM_COMMIT and (mbi.Protect & 0xff) in READABLE and not (mbi.Protect & PAGE_GUARD):
            buf = (C.c_char * min(size, 64*1024*1024))()
            read = C.c_size_t(0)
            if k32.ReadProcessMemory(h, C.c_void_p(mbi.BaseAddress), buf, len(buf), C.byref(read)):
                data = buf.raw[:read.value]
                total += len(data)
                for label, pat, enc in pats:
                    off = data.find(pat)
                    if off >= 0:
                        found.setdefault(label, []).append((mbi.BaseAddress + off, enc, mbi.Protect))
        addr = mbi.BaseAddress + size if size else addr + 0x1000
    k32.CloseHandle(h)
    print(f"scanned {total/1024/1024:.1f} MB")
    if not found:
        print("NO MATCHES (strings not present in cleartext -> likely per-use encryption)")
    for label, hits in found.items():
        for va, enc, prot in hits[:5]:
            print(f"FOUND '{label}' [{enc}] at 0x{va:x} prot=0x{prot:x}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
