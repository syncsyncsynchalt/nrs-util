#!/usr/bin/env python3
"""boot/ のリファクタが挙動保存であることを証明する。

boot シムが nrs.exe に与える観測可能な効果の全ては、次の集合だけ:
  * byte patches   : Memory.patchCode で書く (static_VA, [bytes])
  * interceptions  : Interceptor.attach でフックする (static_VA)

リファクタ（helper 抽出、データテーブル移行、ファイル分割、ディレクトリ改名）が
純粋なリファクタなら、この集合は前後でビット単位まで一致する。本ツールは
それを決定論的に捕捉し、2 つの捕捉結果を diff する。

捕捉のしかた（ゲームロジックは一切走らない）:
  nrs.exe を SUSPENDED で spawn する。計測用 prologue を先頭に付け、
  Memory.patchCode / Interceptor.attach をラップして全呼び出しを記録し（実際の
  patch 適用後にメモリからバイトを読み戻すので、計算された書き込みも捕捉される）、
  記録した集合を send() する epilogue を末尾に付け、スクリプトをロードして集合を
  取得し、resume せずにプロセスを KILL する。こうして全 patch/hook を観測しつつ
  ゲームコードは実行しない。

使い方:
  # 現在の作業ツリーの effect-set をファイルに捕捉
  python tools/hygiene/patch_invariance.py --dump cur.json

  # 使い捨て worktree 経由で git ref（HEAD）を捕捉
  python tools/hygiene/patch_invariance.py --dump head.json --ref HEAD

  # ワンショット: HEAD と作業ツリーを捕捉し diff、差分があれば exit 1
  python tools/hygiene/patch_invariance.py --compare HEAD

exit 0 = effect-set が同一（純粋なリファクタ）。exit 1 = drift（diff を出力）。
"""
import argparse
import io
import json
import os
import subprocess
import sys
import tempfile
import time

try:  # Windows のコンソールは既定 cp932。出力が落ちないよう UTF-8 を強制する。
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GAME_DIR = os.environ.get("NRS_GAME_DIR", r"C:\src\bbs")
GAME_EXE = os.environ.get("NRS_EXE", os.path.join(GAME_DIR, "nrs.exe"))
GAME_ARGS = ["-wsvga", "-full", "-img"]

# 組み立てた boot スクリプトの周囲に注入する計測コード
# Frida の QuickJS では Memory.patchCode / Interceptor.attach は read-only かつ
# non-configurable なプロパティで、直接は再代入できない。だがグローバル束縛の
# `Memory` と `Interceptor` は writable。そこで各々を、本物を継承する（他のメンバは
# prototype 経由で本物の receiver に束縛されて通る。native Frida 束縛はこれを要求する）
# オブジェクトで shadow し、効果を生むメソッドだけを上書きする。モジュールは
# グローバルを参照するので、その呼び出しは shadow に当たる。rtToVa()（直後に連結される
# lib/base.js 由来）は CALL 時に解決され、その時点では定義済み。
_PROLOGUE = r"""
'use strict';
var __INV = { patches: [], hooks: [], seq: [] };
// Stable, ASLR-independent identifier for an effect target. nrs.exe addresses ->
// Ghidra static VA via rtToVa (stable). Win32/NT export targets (mxdrivers hooks
// on kernel32/ntdll/setupapi) -> "module+0xRVA": rtToVa would yield an nrsBase-
// dependent value that drifts between two spawns, causing false drift; module+RVA
// is invariant. Falls back to rtToVa if the module can't be resolved.
function __stableVa(addr) {
    try {
        var m = Process.findModuleByAddress(addr);
        if (m) {
            if (m.name.toLowerCase() === 'nrs.exe') return rtToVa(addr);
            return m.name.toLowerCase() + '+0x' + addr.sub(m.base).toString(16);
        }
    } catch (e) {}
    return rtToVa(addr);
}
(function () {
    // patchCode/attach are non-configurable+non-writable, so a Proxy get-trap that
    // returns a wrapper violates the "inconsistent get" invariant. Instead shadow
    // each global with a plain object that INHERITS from the real one (so alloc,
    // protect, replace, … pass through via the prototype, bound to the real
    // receiver) and overrides only the one effect-producing method as an own prop.
    // Use defineProperty (not assignment): the inherited patchCode/attach are
    // non-writable, so plain assignment throws "read-only" in strict mode.
    var _M = Memory;
    var sM = Object.create(_M);
    Object.defineProperty(sM, 'patchCode', { configurable: true, writable: true, value:
        function (addr, size, cb) {
            _M.patchCode(addr, size, cb);
            var bytes = [];
            try {
                var a = new Uint8Array(addr.readByteArray(size));
                for (var i = 0; i < a.length; i++) bytes.push(a[i]);
            } catch (e) {}
            var v = __stableVa(addr);
            __INV.patches.push({ va: v, bytes: bytes });
            __INV.seq.push({ op: 'patch', va: v });
        }
    });
    Memory = sM;

    var _I = Interceptor;
    var sI = Object.create(_I);
    Object.defineProperty(sI, 'attach', { configurable: true, writable: true, value:
        function (addr, cbs) {
            try { var v = __stableVa(addr); __INV.hooks.push({ va: v });
                  __INV.seq.push({ op: 'hook', va: v }); } catch (e) {}
            return _I.attach(addr, cbs);
        }
    });
    Interceptor = sI;
})();
"""

# epilogue は全モジュールの後に走り（モジュールは scr.load() 中に同期実行される）、
# 記録した effect-set をハーネスへ送り返す。
_EPILOGUE = r"""
send({ tag: '__inv__', data: __INV });
"""


def _assemble(boot_dir: str) -> str:
    """MANIFEST の load_order モジュールを launch.py と全く同じ順で連結し、計測用の
    prologue/epilogue で包む。"""
    manifest_path = os.path.join(boot_dir, "MANIFEST.json")
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)
    parts = [_PROLOGUE]
    for entry in manifest["load_order"]:
        mod_path = os.path.join(boot_dir, *entry["module"].split("/"))
        with open(mod_path, encoding="utf-8", newline="") as mf:
            parts.append(mf.read())
        # launch.py に倣う: base.js の直後にデータ駆動の patch テーブルを注入し、
        # テーブル適用の patch も捕捉対象に含める。
        if entry["module"] == "lib/base.js":
            tbl = os.path.join(boot_dir, "patches.json")
            try:
                with open(tbl, encoding="utf-8") as tf:
                    lit = tf.read().strip() or "[]"
            except FileNotFoundError:
                lit = "[]"
            parts.append("\nvar __PATCH_TABLE__ = " + lit + ";\n")
    parts.append(_EPILOGUE)
    return "".join(parts)


def _canonical(effects: dict) -> dict:
    """正規形。patches/hooks は集合（SET）として比較する（純粋なリファクタは、独立した
    patch がいつ適用されるかを並べ替えうる。例えばデータテーブルの集約。だが集合は
    変えない）。ただし patch と hook の両方が当たる番地では、patch と hook の順序それ自体が
    挙動になる（'1 つの番地で patchCode + Interceptor を混在させない' というアンチパターン
    参照）。そのため、そうした衝突番地ごとに op 列を別途捕捉し、順序を含めて比較する。"""
    patches = sorted(
        ({"va": p["va"].lower(), "bytes": p["bytes"]} for p in effects.get("patches", [])),
        key=lambda p: (p["va"], tuple(p["bytes"])),
    )
    hooks = sorted({h["va"].lower() for h in effects.get("hooks", [])})
    # 番地ごとの op 列。op の種類が 2 つ以上ある番地についてのみ保持する。
    seq_by_va: dict = {}
    for ev in effects.get("seq", []):
        seq_by_va.setdefault(ev["va"].lower(), []).append(ev["op"])
    collisions = {va: ops for va, ops in seq_by_va.items() if len(set(ops)) > 1}
    return {"patches": patches, "hooks": hooks, "collisions": collisions}


def capture(boot_dir: str) -> dict:
    """nrs.exe を suspended で spawn し、計測済み boot スクリプトをロードして
    effect-set を捕捉し、resume せずに kill する。"""
    import frida

    script_src = _assemble(boot_dir)
    captured = {}

    subprocess.run(["taskkill", "/F", "/IM", "nrs.exe"], capture_output=True)
    time.sleep(0.3)
    lib_path = os.path.join(GAME_DIR, "lib", "win32", "bin")
    env = os.environ.copy()
    env["PATH"] = lib_path + os.pathsep + env.get("PATH", "")
    pid = frida.spawn([GAME_EXE] + GAME_ARGS, cwd=GAME_DIR, env=env)
    try:
        sess = frida.attach(pid)

        def on_message(message, data):
            if message["type"] == "send" and message["payload"].get("tag") == "__inv__":
                captured["effects"] = message["payload"]["data"]
            elif message["type"] == "error":
                print(f"[FRIDA_ERR] {message.get('description','')}", file=sys.stderr)

        scr = sess.create_script(script_src)
        scr.on("message", on_message)
        scr.load()  # モジュールはここで同期実行され、epilogue の send() が発火する
        # 非同期メッセージ配送が flush されるのを少し待つ。
        deadline = time.time() + 3.0
        while "effects" not in captured and time.time() < deadline:
            time.sleep(0.05)
    finally:
        # 決して resume しない。ゲームコードは走らせず、後片付けのみ行う。
        subprocess.run(["taskkill", "/F", "/IM", "nrs.exe"], capture_output=True)

    if "effects" not in captured:
        raise RuntimeError("no __inv__ payload received — script error? (see FRIDA_ERR above)")
    return _canonical(captured["effects"])


def capture_ref(ref: str) -> dict:
    """git ref の effect-set を、使い捨て worktree にチェックアウトして捕捉する
    （作業ツリーには手を付けない）。"""
    wt = tempfile.mkdtemp(prefix="nrs-inv-")
    try:
        subprocess.run(["git", "-C", ROOT, "worktree", "add", "--detach", wt, ref],
                       check=True, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
        return capture(os.path.join(wt, "boot"))
    finally:
        subprocess.run(["git", "-C", ROOT, "worktree", "remove", "--force", wt],
                       capture_output=True)


def _diff(a: dict, b: dict) -> list:
    """2 つの正規化済み effect-set 間の差分を人間可読で返す。"""
    out = []
    ap = {(p["va"], tuple(p["bytes"])) for p in a["patches"]}
    bp = {(p["va"], tuple(p["bytes"])) for p in b["patches"]}
    for va, by in sorted(ap - bp):
        out.append(f"  - patch only in A: {va} = {list(by)}")
    for va, by in sorted(bp - ap):
        out.append(f"  + patch only in B: {va} = {list(by)}")
    for va in sorted(set(a["hooks"]) - set(b["hooks"])):
        out.append(f"  - hook only in A: {va}")
    for va in sorted(set(b["hooks"]) - set(a["hooks"])):
        out.append(f"  + hook only in B: {va}")
    # patch と hook の両方が当たる番地での順序 drift。
    ca, cb = a.get("collisions", {}), b.get("collisions", {})
    for va in sorted(set(ca) | set(cb)):
        if ca.get(va) != cb.get(va):
            out.append(f"  ! patch/hook ORDER differs at {va}: A={ca.get(va)} B={cb.get(va)}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dump", metavar="FILE", help="effect-set を FILE に捕捉する（JSON）")
    ap.add_argument("--ref", metavar="GITREF", help="作業ツリーの代わりにこの git ref を捕捉する")
    ap.add_argument("--compare", metavar="GITREF",
                    help="GITREF と作業ツリーを捕捉して diff、差分があれば exit 1")
    args = ap.parse_args()

    if args.compare:
        print(f"[*] Capturing ref {args.compare} ...")
        a = capture_ref(args.compare)
        print("[*] Capturing working tree ...")
        b = capture(os.path.join(ROOT, "boot"))
        d = _diff(a, b)
        if d:
            print(f"[FAIL] effect-set DRIFT ({args.compare} = A, working tree = B):")
            print("\n".join(d))
            return 1
        print(f"OK: effect-set identical — "
              f"{len(b['patches'])} patches, {len(b['hooks'])} hooks. Pure refactor.")
        return 0

    if args.dump:
        eff = capture_ref(args.ref) if args.ref else capture(os.path.join(ROOT, "boot"))
        with open(args.dump, "w", encoding="utf-8") as f:
            json.dump(eff, f, indent=2)
        print(f"OK: {len(eff['patches'])} patches, {len(eff['hooks'])} hooks -> {args.dump}")
        return 0

    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
