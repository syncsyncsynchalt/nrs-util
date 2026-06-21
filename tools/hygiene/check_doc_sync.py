#!/usr/bin/env python3
"""boot/MANIFEST.json と boot モジュールと FACTS の整合、および dialect guard を検査する。

単一番地方言: 人間/ツールが番地を触るところは全て STATIC VA（Ghidra ImageBase 0x400000）。
RVA は lib/base.js の va() helper の内部にのみ存在する。

番地の唯一ソースは各モジュール先頭ヘッダの `// va:` 行（MANIFEST は va を持たない）。
disasm.py の逆引き索引もこのヘッダから動的構築される。

HARD チェック（失敗で exit 1）:
  1. load_order[0] == "lib/base.js"（全モジュールが使う va()/logMsg を定義）。
  2. 各モジュールファイルが存在する。
  3. ヘッダ `// va:` の各番地が当該モジュールの本体（ヘッダ va 行を除く）に逐語で現れる
     （declared but unused = stale ヘッダ entry を検出）。
  4. DIALECT GUARD: 生のモジュール base で nrs.exe を番地参照しない。すなわち
     `nrsBase.add(` や `nb.add(` の呼び出しが無い。番地参照は全て va() 経由。（helper を
     定義する lib/base.js は除外。）
  4b. MANIFEST の 'subsys' がモジュール先頭ヘッダの `// subsys:` 行と一致する（命名 drift 検出）。
      ヘッダ（ディレクトリ名）を正とする。
  5. known_names.json のキーが static VA（>= ImageBase）。誤った RVA エントリを検出。
  6. ヘッダ `// va:` の値が妥当な static VA（>= ImageBase）。stale な RVA を検出。

SOFT チェック（warn のみ）:
  7. 各ヘッダ va が FACTS.md / ARCH.md のどこかに記載されている。
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
SUBSYS_HDR = re.compile(r"^//\s*subsys:\s*(\S+)", re.MULTILINE)
VA_HDR = re.compile(r"^\s*//\s*va:\s*(.*)$", re.MULTILINE)


def hexset(text):
    return {int(t, 16) for t in HEX.findall(text)}


def header_va(text):
    """モジュール先頭ヘッダの `// va:` 行から static VA トークンを返す（全 hex。妥当性は呼び元で検査）。
    注釈 (FUN_... など) は 0x 接頭辞が無いので自然に除外される。`// va:` 行が無ければ空。"""
    m = VA_HDR.search(text)
    return [int(t, 16) for t in HEX.findall(m.group(1))] if m else []


def body_without_va_header(text):
    """ヘッダ `// va:` 行を除いたモジュール本文（drift 検査で自己満足を避けるため）。"""
    return VA_HDR.sub("", text, count=1)


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
    n_va = 0

    for e in lo:
        mod = e["module"]
        path = os.path.join(BOOT, *mod.split("/"))
        if not os.path.isfile(path):
            errors.append(f"{mod}: module file missing")
            continue
        with open(path, encoding="utf-8") as f:
            text = f.read()
        body_hex = hexset(body_without_va_header(text))
        # 4. dialect guard（helper 定義ファイルは除外）
        if mod != "lib/base.js" and RAW_BASE_ADD.search(text):
            errors.append(f"{mod}: raw nrsBase/nb.add( — address via va(staticVA) instead")
        # 4b. subsys が MANIFEST とモジュール先頭ヘッダで一致（命名 drift 検出）。
        # ヘッダ（5行ヘッダの subsys: 行）を正とする。
        hdr = SUBSYS_HDR.search(text)
        if hdr and hdr.group(1) != e.get("subsys"):
            errors.append(f"{mod}: MANIFEST subsys={e.get('subsys')!r} != header subsys={hdr.group(1)!r}")
        # 番地ソース＝ヘッダ `// va:` 行（MANIFEST は va を持たない）。
        vas = header_va(text)
        n_va += len(vas)
        for addr in vas:
            tok = f"0x{addr:X}"
            # 6. 妥当性
            if addr < IMAGE_BASE:
                errors.append(f"{mod}: header va {tok} < ImageBase (stale RVA?)")
            # 3. 本体（ヘッダ va 行を除く）に存在 = 実際に使われている（declared-but-unused 検出）
            elif addr not in body_hex:
                errors.append(f"{mod}: header va {tok} declared but not used in module body (stale)")
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

    # 9. 静的パッチは各サブシステムモジュールに patch() 呼び出しとして在る（中央テーブルなし。
    # 旧 patches.json / lib/static_patches.js は廃止）。その番地はヘッダ `// va:` 経由で
    # section 3（本体に実在）として検証される。人間向けの一覧監査はオフラインツール
    # tools/static/patch_audit.py が担う（全 .js の patch() を横断走査）。

    if errors:
        print("[FAIL] integrity / dialect errors:")
        for m in errors:
            print(f"  - {m}")
    else:
        print(f"OK: {len(lo)} modules, base-first, {n_va} header-va all static & used; "
              f"no raw base addressing.")

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
