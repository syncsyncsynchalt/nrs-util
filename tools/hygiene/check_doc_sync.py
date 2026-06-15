#!/usr/bin/env python3
"""check_doc_sync.py — boot/MANIFEST.json <-> boot modules <-> FACTS integrity + dialect guard.

Single address dialect: STATIC VA (Ghidra ImageBase 0x400000) everywhere a human/tool
touches an address. RVA exists only inside the va() helper in lib/base.js.

HARD checks (exit 1 on failure):
  1. load_order[0] == "lib/base.js"  (defines va()/logMsg used by every module).
  2. each module file exists.
  3. each MANIFEST 'va' (static VA) appears verbatim in its module file (drift detection).
  4. DIALECT GUARD: no module addresses nrs.exe by raw module base — i.e. no
     `nrsBase.add(` / `nb.add(` call. All addressing must go through va(). (lib/base.js,
     which defines the helper, is exempt.)
  5. known_names.json keys are static VAs (>= ImageBase). Catches an accidental RVA entry.
  6. MANIFEST 'va' values are plausible static VAs (>= ImageBase). Catches a stale RVA.

SOFT checks (warn only):
  7. each 'va' is documented somewhere under FACTS.md / ARCH.md.
  8. persistence plausibility (Interceptor/timer vs persistent; patchCode vs monitor).

Usage:  python tools/hygiene/check_doc_sync.py [--quiet] [--warn-only]
"""
import io, os, re, json, sys

try:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BOOT = os.path.join(ROOT, "boot")
MANIFEST = os.path.join(BOOT, "MANIFEST.json")
KNOWN_NAMES = os.path.join(ROOT, "data", "known_names.json")
IMAGE_BASE = 0x400000
HEX = re.compile(r"0x[0-9a-fA-F]{3,8}")
RAW_BASE_ADD = re.compile(r"\b(?:nrsBase|nb)\.add\(")


def hexset(text):
    return {int(t, 16) for t in HEX.findall(text)}


def collect_facts_hex():
    paths = [p for p in (os.path.join(ROOT, "FACTS.md"), os.path.join(BOOT, "ARCH.md"))
             if os.path.isfile(p)]
    for dp, _d, fs in os.walk(BOOT):
        paths += [os.path.join(dp, fn) for fn in fs if fn == "FACTS.md"]
    hs = set()
    for p in paths:
        with open(p, encoding="utf-8") as f:
            hs |= hexset(f.read())
    return hs, paths


def main():
    args = sys.argv[1:]
    quiet = "--quiet" in args
    warn_only = "--warn-only" in args

    with open(MANIFEST, encoding="utf-8") as f:
        manifest = json.load(f)
    lo = manifest["load_order"]
    errors, warns = [], []

    # 1. base first
    if not lo or lo[0]["module"] != "lib/base.js":
        errors.append("load_order[0] must be 'lib/base.js' (defines va()/logMsg)")

    facts_hex, facts_paths = collect_facts_hex()

    for e in lo:
        mod = e["module"]
        path = os.path.join(BOOT, *mod.split("/"))
        if not os.path.isfile(path):
            errors.append(f"{mod}: module file missing")
            continue
        with open(path, encoding="utf-8") as f:
            text = f.read()
        fhex = hexset(text)
        # 4. dialect guard (exempt the helper definition file)
        if mod != "lib/base.js" and RAW_BASE_ADD.search(text):
            errors.append(f"{mod}: raw nrsBase/nb.add( — address via va(staticVA) instead")
        for tok in e.get("va", []):
            addr = int(tok, 16)
            # 6. plausibility
            if addr < IMAGE_BASE:
                errors.append(f"{mod}: MANIFEST va {tok} < ImageBase (stale RVA?)")
            # 3. present in module (exact static VA — one dialect, no tolerance)
            if addr not in fhex:
                errors.append(f"{mod}: MANIFEST va {tok} not found in module file (drift)")
            elif addr not in facts_hex:
                warns.append(f"{mod}: va {tok} not documented in any FACTS.md/ARCH.md")
        # 8. persistence plausibility
        persist = e.get("persistence")
        has_runtime = (re.search(r"Interceptor\.(attach|replace)\(", text) is not None
                       or "setInterval(" in text or "setTimeout(" in text)
        if persist == "persistent" and has_runtime:
            warns.append(f"{mod}: persistence=persistent but has Interceptor/timer (reverts on detach?)")
        if persist == "monitor" and "Memory.patchCode(" in text:
            warns.append(f"{mod}: persistence=monitor but has Memory.patchCode (not log-only?)")

    # 5. known_names static-VA keys
    try:
        with open(KNOWN_NAMES, encoding="utf-8") as f:
            kn = json.load(f)
        for sec in ("functions", "globals", "notes"):
            for k in kn.get(sec, {}):
                if int(k, 16) < IMAGE_BASE:
                    errors.append(f"known_names.json {sec}[{k}] < ImageBase (must be static VA)")
    except FileNotFoundError:
        warns.append("known_names.json not found")

    if errors:
        print("[FAIL] integrity / dialect errors:")
        for m in errors:
            print(f"  - {m}")
    else:
        n = sum(len(e.get("va", [])) for e in lo)
        print(f"OK: {len(lo)} modules, base-first, {n} va all static & present; no raw base addressing.")

    if warns and not quiet:
        print("\n[WARN] (non-blocking):")
        for m in warns:
            print(f"  - {m}")
        print(f"  FACTS scanned: {', '.join(os.path.relpath(p, ROOT) for p in facts_paths) or '(none)'}")

    if not quiet:
        runtime = [e["module"] for e in lo if e.get("persistence") == "runtime"]
        serve = [e["module"] for e in lo if e.get("network_role") == "serve"]
        print(f"\n[INFO] runtime (standalone blockers, {len(runtime)}): {', '.join(runtime)}")
        print(f"[INFO] serve (future-network layer, {len(serve)}): {', '.join(serve)}")

    return 0 if warn_only else (1 if errors else 0)


if __name__ == "__main__":
    sys.exit(main())
