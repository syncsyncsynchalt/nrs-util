#!/usr/bin/env python3
"""TeknoParrot クローズド実装の静的 RE ヘルパ.

注入実体 TeknoParrot.dll(32bit, teknoGod パックセクション) と
インジェクタ BudgieLoader.exe(.brr パックセクション) を解析する。
pefile + capstone のみ使用（dumpbin/objdump 不要）。

usage: python tools/re/tp_re.py <pe-path> [--imports] [--exports] [--sections] [--ep]
"""
import sys, math, argparse
from collections import Counter
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

KEYWORDS = ('CreateFileMapping', 'MapViewOfFile', 'OpenFileMapping', 'CreateNamedPipe',
            'CreateFile', 'DeviceIoControl', 'LoadLibrary', 'GetProcAddress',
            'VirtualAlloc', 'VirtualProtect', 'CreateThread', 'mscoree', 'CLRCreate')


def entropy(b):
    if not b:
        return 0.0
    c = Counter(b); n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('path')
    ap.add_argument('--imports', action='store_true')
    ap.add_argument('--exports', action='store_true')
    ap.add_argument('--sections', action='store_true')
    ap.add_argument('--ep', action='store_true')
    ap.add_argument('--all', action='store_true')
    a = ap.parse_args()
    if a.all:
        a.imports = a.exports = a.sections = a.ep = True

    pe = pefile.PE(a.path, fast_load=False)
    is64 = pe.OPTIONAL_HEADER.Magic == 0x20b
    print(f"== {a.path}")
    print(f"   arch={'x64' if is64 else 'x86'} entry_rva=0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x} "
          f"imagebase=0x{pe.OPTIONAL_HEADER.ImageBase:x}")

    if a.sections:
        print("-- sections (entropy>7.0 ≈ packed/encrypted) --")
        for s in pe.sections:
            nm = s.Name.rstrip(b'\x00').decode('latin1')
            data = s.get_data()[:200000]
            print(f"   {nm:10s} vaddr=0x{s.VirtualAddress:08x} vsz=0x{s.Misc_VirtualSize:08x} "
                  f"rawsz=0x{s.SizeOfRawData:08x} ent={entropy(data):.2f}")

    if a.imports:
        print("-- imports (filtered to RE-relevant + DLL names) --")
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for imp in pe.DIRECTORY_ENTRY_IMPORT:
                dll = imp.dll.decode('latin1')
                names = [i.name.decode('latin1') for i in imp.imports if i.name]
                hits = [n for n in names if any(k.lower() in n.lower() for k in KEYWORDS)]
                print(f"   {dll}  (total {len(names)} fns)" + (f"  >> {hits}" if hits else ""))
        else:
            print("   (no import directory — likely resolved at runtime by packer)")

    if a.exports:
        print("-- exports --")
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                nm = e.name.decode('latin1') if e.name else f"ord#{e.ordinal}"
                print(f"   {nm}  rva=0x{e.address:x}")
        else:
            print("   (no exports)")

    if a.ep:
        print("-- entry point disasm (unpacking stub, first 40 insns) --")
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        code = pe.get_memory_mapped_image()[ep:ep+200]
        md = Cs(CS_ARCH_X86, CS_MODE_64 if is64 else CS_MODE_32)
        base = pe.OPTIONAL_HEADER.ImageBase + ep
        for i, ins in enumerate(md.disasm(code, base)):
            print(f"   0x{ins.address:x}: {ins.mnemonic} {ins.op_str}")
            if i >= 39:
                break


if __name__ == '__main__':
    main()
