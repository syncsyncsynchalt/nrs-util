#!/usr/bin/env python3
"""check_doc_sync.py — boot/MANIFEST.json <-> boot モジュール <-> FACTS の整合 + dialect guard。

単一番地方言: 人間/ツールが番地を触るところは全て STATIC VA（Ghidra ImageBase 0x400000）。
RVA は lib/base.js の va() helper の内部にのみ存在する。

HARD チェック（失敗で exit 1）:
  1. load_order[0] == "lib/base.js"（全モジュールが使う va()/logMsg を定義）。
  2. 各モジュールファイルが存在する。
  3. 各 MANIFEST 'va'（static VA）が当該モジュールファイルに逐語で現れる（drift 検出）。
  4. DIALECT GUARD: 生のモジュール base で nrs.exe を番地参照しない — つまり
     `nrsBase.add(` / `nb.add(` 呼び出しが無い。番地参照は全て va() 経由。（helper を
     定義する lib/base.js は除外。）
  5. known_names.json のキーが static VA（>= ImageBase）。誤った RVA エントリを検出。
  6. MANIFEST 'va' の値が妥当な static VA（>= ImageBase）。stale な RVA を検出。

SOFT チェック（warn のみ）:
  7. 各 'va' が FACTS.md / ARCH.md のどこかに記載されている。
  8. persistence の妥当性（Interceptor/timer と persistent、patchCode と monitor）。

使い方:  python tools/hygiene/check_doc_sync.py [--quiet] [--warn-only]
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

    # 1. base が先頭
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
        # 4. dialect guard（helper 定義ファイルは除外）
        if mod != "lib/base.js" and RAW_BASE_ADD.search(text):
            errors.append(f"{mod}: raw nrsBase/nb.add( — address via va(staticVA) instead")
        for tok in e.get("va", []):
            addr = int(tok, 16)
            # 6. 妥当性
            if addr < IMAGE_BASE:
                errors.append(f"{mod}: MANIFEST va {tok} < ImageBase (stale RVA?)")
            # 3. モジュール内に存在（厳密な static VA — 単一方言・許容なし）
            if addr not in fhex:
                errors.append(f"{mod}: MANIFEST va {tok} not found in module file (drift)")
            elif addr not in facts_hex:
                warns.append(f"{mod}: va {tok} not documented in any FACTS.md/ARCH.md")
        # 8. persistence の妥当性。生のプリミティブと base.js の helper イディオム
        # （hook()/watch()=runtime、patch()=persistent なバイト書き込み）の両方を認識し、
        # モジュールが宣言的になっても heuristic が機能しなくならないようにする。
        persist = e.get("persistence")
        has_runtime = (re.search(r"Interceptor\.(attach|replace)\(", text) is not None
                       or "setInterval(" in text or "setTimeout(" in text
                       or re.search(r"\b(hook|watch)\(", text) is not None)
        has_patch = "Memory.patchCode(" in text or re.search(r"\bpatch\(", text) is not None
        if persist == "persistent" and has_runtime:
            warns.append(f"{mod}: persistence=persistent but has Interceptor/timer/hook/watch (reverts on detach?)")
        if persist == "monitor" and has_patch:
            warns.append(f"{mod}: persistence=monitor but has patchCode/patch() (not log-only?)")

    # 5. known_names の static-VA キー
    try:
        with open(KNOWN_NAMES, encoding="utf-8") as f:
            kn = json.load(f)
        for sec in ("functions", "globals", "notes"):
            for k in kn.get(sec, {}):
                if int(k, 16) < IMAGE_BASE:
                    errors.append(f"known_names.json {sec}[{k}] < ImageBase (must be static VA)")
    except FileNotFoundError:
        warns.append("known_names.json not found")

    # 9. patches.json（データ駆動の純バイト patch テーブル）— 各行の va が static VA で
    # 一意であり、bytes 指定が解決可能（mnemonic | {retImm/retN} | hex）かを検証する。
    patches_path = os.path.join(BOOT, "patches.json")
    n_patches = 0
    try:
        with open(patches_path, encoding="utf-8") as f:
            rows = json.load(f)
        seen = set()
        for i, row in enumerate(rows):
            tok = row.get("va", "")
            try:
                addr = int(tok, 16)
            except (TypeError, ValueError):
                errors.append(f"patches.json[{i}]: va {tok!r} not a hex static VA")
                continue
            if addr < IMAGE_BASE:
                errors.append(f"patches.json[{i}]: va {tok} < ImageBase (stale RVA?)")
            if addr in seen:
                errors.append(f"patches.json[{i}]: duplicate va {tok}")
            seen.add(addr)
            b = row.get("bytes")
            ok_bytes = (b in ("RET0", "RET1")
                        or (isinstance(b, dict) and ("retImm" in b or "retN" in b))
                        or (isinstance(b, list) and all(isinstance(x, int) for x in b))
                        or (isinstance(b, str) and re.fullmatch(r"[0-9A-Fa-f]{2}( [0-9A-Fa-f]{2})*", b.strip())))
            if not ok_bytes:
                errors.append(f"patches.json[{i}] ({tok}): unresolvable bytes spec {b!r}")
            if addr not in facts_hex:
                warns.append(f"patches.json {tok} not documented in any FACTS.md/ARCH.md")
        n_patches = len(rows)
    except FileNotFoundError:
        pass

    if errors:
        print("[FAIL] integrity / dialect errors:")
        for m in errors:
            print(f"  - {m}")
    else:
        n = sum(len(e.get("va", [])) for e in lo)
        print(f"OK: {len(lo)} modules, base-first, {n} va all static & present; "
              f"{n_patches} patches.json rows; no raw base addressing.")

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
