#!/usr/bin/env python3
"""静的バイトパッチのオフライン一覧監査（旧 boot/patches.json の後継）。

nrs.exe を起動せずに boot/**/*.js を走査し、`patch(staticVA, bytes, note)` 呼び出し
（＝静的バイトパッチ）を一覧化する。中央テーブルは無く、各パッチは所属サブシステムの
モジュールに分散して在る（devices/mxstorage/mxsegaboot/mxnetwork/ambilling/amjvs/amdongle 等）。
patch() を通る限りどこに在っても全部拾うので、住所が分散しても完全カタログになる。

STATIC VA 方言（Ghidra MCP と一致）。番地は全て hex。

解決できる bytes:
  RET0 / RET1 / retImm(n) / retN(n) / [0x..,..]   → バイト列とバイト数を表示
解決できない bytes/addr（ループ変数・実行時計算）は **DYN** として明示し、黙って落とさない。
Interceptor フックや Memory.patchCode（条件付き・実行時組立の動的パッチ）は静的パッチでは
ないので一覧の対象外。末尾にその件数だけ参考表示する。

使い方:
  patch_audit.py                既定の boot/ を監査して表を出力
  patch_audit.py --json         機械可読出力
"""
import io, sys, os, re, json

try:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BOOT = os.path.join(ROOT, "boot")
# base.js は patch()/hook()/Memory.patchCode の helper を *定義* するだけで実パッチではない。監査対象外。
SKIP = {"lib/base.js"}

RET0 = [0x31, 0xC0, 0xC3]
RET1 = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]


def _split_args(s):
    """トップレベルのカンマで引数を分割（[] () '' "" の内側は無視）。"""
    args, depth, i, start, quote = [], 0, 0, 0, None
    while i < len(s):
        c = s[i]
        if quote:
            if c == quote and s[i - 1] != "\\":
                quote = None
        elif c in "'\"":
            quote = c
        elif c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == "," and depth == 0:
            args.append(s[start:i].strip())
            start = i + 1
        i += 1
    args.append(s[start:].strip())
    return args


def _resolve_bytes(expr):
    """bytes 引数式 -> (バイト列 list, 表示文字列)。解決不能なら (None, 説明)。"""
    e = expr.strip()
    if e == "RET0":
        return RET0, "xor eax,eax; ret (=ret 0)"
    if e == "RET1":
        return RET1, "mov eax,1; ret (=ret 1)"
    m = re.fullmatch(r"retImm\(\s*(\d+)\s*\)", e)
    if m:
        n = int(m.group(1))
        return [0xB8, n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF, (n >> 24) & 0xFF, 0xC3], f"mov eax,{n}; ret (=ret {n})"
    m = re.fullmatch(r"retN\(\s*(\d+)\s*\)", e)
    if m:
        n = int(m.group(1))
        return [0xC2, n & 0xFF, (n >> 8) & 0xFF], f"ret {n} (stdcall cleanup)"
    if e.startswith("[") and e.endswith("]"):
        try:
            vals = [int(x.strip(), 0) for x in e[1:-1].split(",") if x.strip()]
            return vals, " ".join(f"{b:02X}" for b in vals)
        except ValueError:
            return None, expr
    return None, expr  # 変数・実行時計算 (DYN)


_PATCH_RE = re.compile(r"\bpatch\(")


def _scan_file(path):
    """1ファイルの patch() 呼び出しを抽出。返り: list of dict。"""
    rows = []
    text = open(path, encoding="utf-8").read()
    for m in _PATCH_RE.finditer(text):
        # コメント行内の "patch(" は除外
        line_start = text.rfind("\n", 0, m.start()) + 1
        if text[line_start:m.start()].lstrip().startswith("//"):
            continue
        # 関数定義 `function patch(` は呼び出しでないので除外
        if text[line_start:m.start()].rstrip().endswith("function"):
            continue
        # 対応する閉じ括弧までを取る（呼び出しは単一行想定。balance で多行も best-effort）
        i, depth = m.end(), 1
        while i < len(text) and depth:
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
            i += 1
        inner = text[m.end():i - 1]
        args = _split_args(inner)
        if len(args) < 2:
            continue
        addr_expr = args[0].strip()
        addr = int(addr_expr, 16) if re.fullmatch(r"0[xX][0-9A-Fa-f]+", addr_expr) else None
        b, desc = _resolve_bytes(args[1])
        note = ""
        if len(args) >= 3:
            nm = re.fullmatch(r"['\"](.*)['\"]", args[2].strip())
            note = nm.group(1) if nm else args[2].strip()
        rows.append({
            "addr": addr, "addr_expr": addr_expr,
            "len": len(b) if b else None, "bytes": desc, "note": note,
            "dynamic": addr is None or b is None,
        })
    return rows


def _count_dynamic_sites():
    """参考: Interceptor.* と Memory.patchCode の出現数（静的パッチではない動的サイト）。"""
    n_hook = n_patchcode = 0
    files = []
    for dp, _d, fs in os.walk(BOOT):
        for fn in fs:
            if not fn.endswith(".js"):
                continue
            rel = os.path.relpath(os.path.join(dp, fn), BOOT).replace("\\", "/")
            if rel in SKIP:
                continue
            t = open(os.path.join(dp, fn), encoding="utf-8").read()
            h = len(re.findall(r"Interceptor\.(?:attach|replace)\(", t))
            p = len(re.findall(r"Memory\.patchCode\(", t))
            if h or p:
                files.append((os.path.relpath(os.path.join(dp, fn), BOOT), h, p))
            n_hook += h
            n_patchcode += p
    return n_hook, n_patchcode, files


def main():
    as_json = "--json" in sys.argv[1:]
    by_file = {}
    for dp, _d, fs in os.walk(BOOT):
        for fn in sorted(fs):
            if not fn.endswith(".js"):
                continue
            path = os.path.join(dp, fn)
            rel = os.path.relpath(path, BOOT).replace("\\", "/")
            if rel in SKIP:
                continue
            rows = _scan_file(path)
            if rows:
                by_file[rel] = rows

    total = sum(len(r) for r in by_file.values())
    dyn = sum(1 for rs in by_file.values() for r in rs if r["dynamic"])
    n_hook, n_patchcode, dyn_files = _count_dynamic_sites()

    if as_json:
        print(json.dumps({
            "static_patches": by_file,
            "totals": {"patches": total, "unresolved": dyn},
            "dynamic_sites": {"hooks": n_hook, "patchCode": n_patchcode},
        }, indent=2, ensure_ascii=False))
        return 0

    print(f"=== 静的バイトパッチ監査 ({total} 件, {len(by_file)} モジュール) ===\n")
    for mod in sorted(by_file):
        print(f"# {mod}")
        for r in by_file[mod]:
            va = r["addr_expr"] if r["addr"] is None else f"0x{r['addr']:X}"
            tag = "DYN " if r["dynamic"] else "    "
            ln = "  ?" if r["len"] is None else f"{r['len']:3d}"
            print(f"  {tag}{va:<10} {ln}b  {r['bytes']:<28} {r['note']}")
        print()

    if dyn:
        print(f"[NOTE] {dyn} 件は addr/bytes が実行時計算（DYN）。表の bytes 列は式のまま表示している。")
    print(f"[INFO] 静的パッチ以外の動的サイト（一覧対象外）: "
          f"Interceptor フック {n_hook} 件, Memory.patchCode {n_patchcode} 件。")
    for f, h, p in sorted(dyn_files):
        bits = []
        if h:
            bits.append(f"hook×{h}")
        if p:
            bits.append(f"patchCode×{p}")
        print(f"         {f}: {', '.join(bits)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
