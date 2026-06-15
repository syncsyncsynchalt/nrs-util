"""PE analyzer for BBS investigation targets.

Usage:
  python pe_analyze.py tp         -- TeknoParrot.dll
  python pe_analyze.py nrs        -- nrs.exe
  python pe_analyze.py dlls       -- lib/win32/bin/*.dll + mxGetHwInfo.exe
  python pe_analyze.py <path>     -- arbitrary PE file
"""
import pefile, math, re, os, sys

_GAME = os.environ.get("NRS_GAME_DIR", r"C:\src\bbs")
_TP   = os.environ.get("NRS_TP_DIR",   r"C:\src\TPBootstrapper")
TARGETS = {
    "tp":  os.path.join(_TP, "TeknoParrot", "TeknoParrot.dll"),
    "nrs": os.environ.get("NRS_EXE", os.path.join(_GAME, "nrs.exe")),
    "dlls": [
        os.path.join(_GAME, "lib", "win32", "bin", "dinput8.dll"),
        os.path.join(_GAME, "lib", "win32", "bin", "dsound.dll"),
        os.path.join(_GAME, "tools", "ringedge", "mxGetHwInfo.exe"),
    ],
}

PACKER_SIGS = {
    b"VMProtect": "VMProtect", b".vmp0": "VMProtect",
    b"Themida": "Themida", b".Themida": "Themida",
    b"UPX!": "UPX", b"UPX0": "UPX",
    b"ASPack": "ASPack", b"PELock": "PELock",
    b"MPRESS": "MPRESS", b"Enigma": "Enigma",
    b"yC": "yC packer", b"teknoGod": "teknoGod (custom)",
}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def analyze(path: str) -> None:
    print(f"\n{'=' * 70}")
    print(f"FILE: {path}")
    print(f"{'=' * 70}")

    if not os.path.exists(path):
        print("  ERROR: file not found")
        return

    with open(path, "rb") as f:
        raw = f.read()

    pe = pefile.PE(data=raw)
    oh = pe.OPTIONAL_HEADER
    fh = pe.FILE_HEADER
    arch = "x86" if fh.Machine == 0x14C else "x64" if fh.Machine == 0x8664 else f"0x{fh.Machine:04X}"
    fsize = len(raw)

    print(f"\n--- HEADER ---")
    print(f"  Arch:        {arch}")
    print(f"  ImageBase:   0x{oh.ImageBase:08X}")
    print(f"  OEP RVA:     0x{oh.AddressOfEntryPoint:08X}")
    print(f"  SizeOfImage: 0x{oh.SizeOfImage:08X}  ({oh.SizeOfImage // 1024 // 1024} MB)")
    print(f"  File size:   0x{fsize:08X}  ({fsize // 1024 // 1024} MB)")
    if fsize > oh.SizeOfImage:
        print(f"  Overlay:     0x{fsize - oh.SizeOfImage:08X} bytes beyond SizeOfImage")

    print(f"\n--- SECTIONS ---")
    print(f"  {'Name':12s} {'VA':>10s} {'FileOff':>10s} {'RawSz':>10s} {'VirtSz':>10s} {'Entropy':>8s}  Flags")
    for s in pe.sections:
        name = s.Name.decode(errors="replace").rstrip("\x00")
        data = s.get_data()
        e = entropy(data)
        chars = s.Characteristics
        flags = "".join([
            "X" if chars & 0x20000000 else "-",
            "R" if chars & 0x40000000 else "-",
            "W" if chars & 0x80000000 else "-",
        ])
        print(f"  {name:12s} 0x{s.VirtualAddress:08X} 0x{s.PointerToRawData:08X} "
              f"0x{s.SizeOfRawData:08X} 0x{s.Misc_VirtualSize:08X} {e:8.2f}  {flags}")

    # OEP section
    oep_va = oh.ImageBase + oh.AddressOfEntryPoint
    for s in pe.sections:
        if oh.ImageBase + s.VirtualAddress <= oep_va < oh.ImageBase + s.VirtualAddress + s.Misc_VirtualSize:
            print(f"  OEP in section: '{s.Name.decode(errors='replace').rstrip(chr(0))}'")
            break

    print(f"\n--- PACKER DETECTION ---")
    found_any = False
    for sig, name in PACKER_SIGS.items():
        idx = raw.find(sig)
        if idx != -1:
            loc = "header" if idx < 0x10000 else f"0x{idx:08X}"
            print(f"  {name:25s} @ {loc}")
            found_any = True
    if not found_any:
        print("  (none detected)")

    print(f"\n--- IMPORTS ---")
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("utf-8", errors="replace")
            funcs = []
            for imp in entry.imports:
                funcs.append(imp.name.decode("utf-8", errors="replace") if imp.name else f"ord#{imp.ordinal}")
            print(f"  [{dll}] ({len(funcs)}): {', '.join(funcs[:8])}")
    else:
        print("  (no import table)")

    print(f"\n--- EXPORTS ---")
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        exps = []
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exps.append(exp.name.decode() if exp.name else f"ord#{exp.ordinal}")
        print(f"  {', '.join(exps)}")
    else:
        print("  (no exports)")

    print(f"\n--- CLEARTEXT STRINGS (header 64KB, 8+ chars, filtered) ---")
    header = raw[:0x10000]
    interesting = re.compile(
        r"(\\\\|pipe|tekno|keychip|jvs|sram|eeprom|dongle|columba|naominet"
        r"|ringedge|amlib|\.ini|\.cfg|\.dat|auth|region|gameid|playcount"
        r"|GetProcAddress|LoadLibrary|CreateFile|VirtualAlloc)",
        re.IGNORECASE,
    )
    for m in re.finditer(rb"[\x20-\x7E]{8,}", header):
        s = m.group().decode("ascii")
        if interesting.search(s):
            print(f"  [0x{m.start():06X}] {repr(s)}")


def main() -> None:
    arg = sys.argv[1] if len(sys.argv) > 1 else "help"

    if arg == "help":
        print(__doc__)
        return

    paths = TARGETS.get(arg)
    if paths is None:
        paths = arg  # treat as file path

    if isinstance(paths, list):
        for p in paths:
            analyze(p)
    else:
        analyze(paths)


if __name__ == "__main__":
    main()
