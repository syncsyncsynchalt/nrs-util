"""Extract filtered strings from nrs.exe relevant to BBS investigation.

Usage:
  python nrs_strings.py [--all]   -- omit --all to show only high-interest strings
"""
import os, re, sys

PATH = os.environ.get("NRS_EXE", r"C:\src\bbs\nrs.exe")

FILTER = re.compile(
    r"(com\d|\\\\.\\|keychip|dongle|sbva|sega|ringedge|amlib|mxGetHw|HwInfo"
    r"|jvs|coin|service|\.sega\.|naomi|alls|auth|license|teknoparrot"
    r"|\.ini|\.cfg|\.dat|ram\\\\|rom\\\\|b[o]rder.?br[e]ak|nrs|wsvga|1024"
    r"|baud|comm|serial|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|http://|https://"
    r"|pcpa|amDongle|amJvs|amRtc|amPlatform|amHm|alpb|Auth Server)",
    re.IGNORECASE,
)

SHOW_ALL = "--all" in sys.argv

with open(PATH, "rb") as f:
    data = f.read()

results = []

# ASCII
for m in re.finditer(rb"[\x20-\x7E]{5,}", data):
    s = m.group().decode("ascii", errors="replace")
    results.append((m.start(), "A", s))

# UTF-16LE
for m in re.finditer(rb"(?:[\x20-\x7E]\x00){5,}", data):
    s = m.group().decode("utf-16-le", errors="replace")
    results.append((m.start(), "U", s))

results.sort(key=lambda x: x[0])

seen: set[str] = set()
count = 0
for off, enc, s in results:
    s = s.strip()
    if len(s) < 5 or s in seen:
        continue
    if SHOW_ALL or FILTER.search(s):
        seen.add(s)
        print(f"[0x{off:08X}] [{enc}] {s}")
        count += 1

print(f"\n{count} strings printed.")
