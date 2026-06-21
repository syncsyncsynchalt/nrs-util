#!/usr/bin/env python3
"""nrs.exe 静的解析。STATIC VA 方言（Ghidra MCP と一致）。

番地引数は全て Ghidra の static VA（ImageBase 0x400000）で、常に hex。
RVA モードは無く、単一方言で変換もしない。RVA は runtime の va() helper の
内部にのみ存在し、ツール境界には一切出ない。

使い方:
  disasm.py <VA>                     20 命令を disassemble
  disasm.py <VA> -n 40              40 命令を disassemble
  disasm.py <VA> -x [N]             N バイトを hex ダンプ（既定 64）
  disasm.py <VA> -b [N]            patchCode 用のバイト配列（既定 16）+ va() 形式 +
                                    MANIFEST patch-site の相互参照
  disasm.py <VA> -r [N]            C 文字列を読む（既定 最大 256）
  disasm.py <VA> --xrefs           この VA を指す CALL/JMP を全て探す
  disasm.py -s 31C0C390             バイトパターンを検索（hex、空白なし）
  disasm.py -S "RingEdge"          ASCII 文字列を検索
  disasm.py --imports [FILTER]     imports を列挙
  disasm.py --sections             PE の section を列挙
-x/-b/-n/--xrefs/-s/-S に --json を付けると機械可読出力になる。
"""

import sys, os, json, struct
import pefile
import capstone
from capstone import x86

BINARY = os.environ.get("NRS_EXE", r"C:\src\bbs\nrs.exe")
IMAGE_BASE = 0x400000
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MANIFEST = os.path.join(ROOT, "boot", "MANIFEST.json")

_pe = None


def get_pe():
    global _pe
    if _pe is None:
        if not os.path.exists(BINARY):
            print(f"ERROR: {BINARY} not found", file=sys.stderr)
            sys.exit(1)
        print(f"Loading {BINARY}...", file=sys.stderr)
        _pe = pefile.PE(BINARY, fast_load=False)
    return _pe


def parse_va(s):
    """番地引数 -> static VA。常に hex（nrs の番地は全て hex）。"""
    s = s.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    v = int(s, 16)
    if v < IMAGE_BASE:
        print(f"WARNING: 0x{v:X} < ImageBase 0x{IMAGE_BASE:X}. Args are static VAs, "
              f"not RVAs — did you mean 0x{v + IMAGE_BASE:X}?", file=sys.stderr)
    return v


def to_rva(va):
    return va - IMAGE_BASE


# MANIFEST patch-site の相互参照
def manifest_sites():
    """MANIFEST の 'va' 配列から {static_VA: [module, ...]} を返す（best-effort）。"""
    out = {}
    try:
        with open(MANIFEST, encoding="utf-8") as f:
            mani = json.load(f)
    except Exception:
        return out
    for e in mani.get("load_order", []):
        for tok in e.get("va", []):
            try:
                out.setdefault(int(tok, 16), []).append(e["module"])
            except (ValueError, KeyError):
                pass
    return out


# disassemble
def do_disasm(va, count, as_json=False):
    pe = get_pe()
    data = pe.get_data(to_rva(va), max(count * 15, 64))
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    rows = []
    for insn in md.disasm(data, va):
        tgt = None
        if insn.mnemonic in ("call", "jmp") or insn.mnemonic.startswith("j") or insn.mnemonic == "loop":
            for op in insn.operands:
                if op.type == x86.X86_OP_IMM and IMAGE_BASE <= op.imm < IMAGE_BASE + 0x02132000:
                    tgt = op.imm
        rows.append({
            "va": insn.address, "bytes": insn.bytes.hex(),
            "asm": (insn.mnemonic + " " + insn.op_str).strip(),
            "target_va": tgt,
        })
        if len(rows) >= count:
            break
    if as_json:
        print(json.dumps(rows))
        return
    for r in rows:
        bs = " ".join(f"{b:02X}" for b in bytes.fromhex(r["bytes"]))
        tgt = f"  ; -> 0x{r['target_va']:X}" if r["target_va"] else ""
        print(f"  0x{r['va']:08X}  {bs:<24}  {r['asm']}{tgt}")


def do_hexdump(va, size, as_json=False):
    pe = get_pe()
    data = pe.get_data(to_rva(va), size)
    if as_json:
        print(json.dumps({"va": va, "bytes": data.hex()}))
        return
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexp = " ".join(f"{b:02X}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  0x{va + i:08X}  {hexp:<47}  {asc}")


def do_bytearray(va, size, as_json=False):
    pe = get_pe()
    data = pe.get_data(to_rva(va), size)
    sites = manifest_sites().get(va, [])
    if as_json:
        print(json.dumps({"va": va, "bytes": data.hex(),
                          "patch_call": f"va(0x{va:X})", "manifest_modules": sites}))
        return
    arr = ", ".join(f"0x{b:02X}" for b in data)
    print(f"  // {size} bytes at va(0x{va:X})")
    print(f"  Memory.patchCode(va(0x{va:X}), {size}, c => c.writeByteArray([{arr}]));")
    if sites:
        print(f"  // MANIFEST patch-site: {', '.join(sites)}")
    else:
        print(f"  // (not currently a MANIFEST patch-site)")


def do_read_string(va, maxlen, as_json=False):
    pe = get_pe()
    data = pe.get_data(to_rva(va), maxlen)
    end = data.find(b"\x00")
    if end >= 0:
        data = data[:end]
    if as_json:
        print(json.dumps({"va": va, "string": data.decode("latin-1"), "len": len(data)}))
        return
    s = "".join(chr(b) if 32 <= b < 127 else f"\\x{b:02x}" for b in data)
    sys.stdout.buffer.write(f'  0x{va:X}: "{s}"  ({len(data)} bytes)\n'.encode("utf-8"))


def do_xrefs(va, as_json=False):
    pe = get_pe()
    results = []
    for section in pe.sections:
        if not (section.Characteristics & 0x20000000):
            continue
        data = section.get_data()
        base_va = IMAGE_BASE + section.VirtualAddress
        for i in range(len(data) - 5):
            b = data[i]
            if b in (0xE8, 0xE9):
                rel = struct.unpack_from("<i", data, i + 1)[0]
                caller_va = base_va + i
                if caller_va + 5 + rel == va:
                    results.append({"va": caller_va, "kind": "call" if b == 0xE8 else "jmp"})
    if as_json:
        print(json.dumps({"target_va": va, "xrefs": results}))
        return
    if not results:
        print(f"  No xrefs to 0x{va:X}")
    else:
        print(f"  {len(results)} xref(s) to 0x{va:X}:")
        for r in sorted(results, key=lambda x: x["va"]):
            print(f"    {r['kind']:4s}  0x{r['va']:X}")


def do_search_bytes(pattern_hex, as_json=False):
    pe = get_pe()
    pattern = bytes.fromhex(pattern_hex.replace(" ", ""))
    hits = []
    for section in pe.sections:
        data = section.get_data()
        off = 0
        while True:
            pos = data.find(pattern, off)
            if pos < 0:
                break
            hits.append(IMAGE_BASE + section.VirtualAddress + pos)
            off = pos + 1
    if as_json:
        print(json.dumps({"pattern": pattern_hex, "va": hits}))
        return
    if not hits:
        print(f"  Pattern {pattern_hex} not found")
    else:
        print(f"  {len(hits)} match(es) for {pattern_hex}:")
        for va in hits:
            print(f"    0x{va:X}")


def do_imports(filt=None):
    pe = get_pe()
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        print("No import directory.")
        return
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode("ascii", "replace")
        for imp in entry.imports:
            name = imp.name.decode("ascii", "replace") if imp.name else f"ord_{imp.ordinal}"
            if filt and filt.lower() not in name.lower() and filt.lower() not in dll.lower():
                continue
            print(f"  {dll:<30} {name:<40} IAT va 0x{imp.address:X}")


def do_sections():
    pe = get_pe()
    print(f"  {'Name':<10} {'VA':>10} {'VirtSize':>10} {'RawOff':>10} {'RawSize':>10}  Flags")
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("ascii", "replace")
        flags = "".join(c for c, bit in (("X", 0x20000000), ("R", 0x40000000), ("W", 0x80000000))
                        if s.Characteristics & bit)
        print(f"  {name:<10} 0x{IMAGE_BASE + s.VirtualAddress:08X} 0x{s.Misc_VirtualSize:08X} "
              f"0x{s.PointerToRawData:08X} 0x{s.SizeOfRawData:08X}  {flags}")


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    as_json = "--json" in args
    args = [a for a in args if a != "--json"]

    if args[0] == "-s":
        return do_search_bytes(args[1] if len(args) > 1 else "", as_json)
    if args[0] == "-S":
        return do_search_bytes((args[1] if len(args) > 1 else "").encode("ascii").hex(), as_json)
    if args[0] == "--imports":
        return do_imports(args[1] if len(args) > 1 else None)
    if args[0] == "--sections":
        return do_sections()

    va = parse_va(args[0])
    rest = args[1:]
    if not rest:
        return do_disasm(va, 20, as_json)
    flag = rest[0]
    n = lambda d: int(rest[1]) if len(rest) > 1 else d
    if flag == "-n":
        do_disasm(va, n(20), as_json)
    elif flag == "-x":
        do_hexdump(va, n(64), as_json)
    elif flag == "-b":
        do_bytearray(va, n(16), as_json)
    elif flag == "-r":
        do_read_string(va, n(256), as_json)
    elif flag == "--xrefs":
        do_xrefs(va, as_json)
    else:
        try:
            do_disasm(va, int(flag), as_json)
        except ValueError:
            print(f"Unknown flag: {flag}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
