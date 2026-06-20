#!/usr/bin/env python3
"""patch_invariance.py — prove a boot/ refactor is behaviour-preserving.

The boot shim's ENTIRE observable effect on nrs.exe is the set of:
  * byte patches   — (static_VA, [bytes]) written via Memory.patchCode
  * interceptions  — (static_VA) hooked via Interceptor.attach

If a refactor (helper extraction, data-table migration, file split, dir rename)
is a *pure* refactor, that set is bit-for-bit identical before and after. This
tool captures it deterministically and diffs two captures.

HOW IT CAPTURES (no game logic runs):
  nrs.exe is spawned SUSPENDED. We prepend an instrumentation prologue that wraps
  Memory.patchCode / Interceptor.attach to record every call (reading the bytes
  back from memory AFTER the real patch applies, so computed writes are captured
  too), append an epilogue that send()s the recorded set, load the script, grab
  the set, and KILL the process without ever resuming. So every patch/hook is
  observed but no game code executes.

USAGE:
  # capture the current working tree's effect-set to a file
  python tools/hygiene/patch_invariance.py --dump cur.json

  # capture a git ref (HEAD) via a throwaway worktree
  python tools/hygiene/patch_invariance.py --dump head.json --ref HEAD

  # one-shot: capture HEAD and the working tree, diff, exit 1 on any difference
  python tools/hygiene/patch_invariance.py --compare HEAD

Exit 0 = identical effect-set (refactor is pure). Exit 1 = drift (diff printed).
"""
import argparse
import io
import json
import os
import subprocess
import sys
import tempfile
import time

try:  # Windows consoles default to cp932; force UTF-8 so output never crashes.
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GAME_DIR = os.environ.get("NRS_GAME_DIR", r"C:\src\bbs")
GAME_EXE = os.environ.get("NRS_EXE", os.path.join(GAME_DIR, "nrs.exe"))
GAME_ARGS = ["-wsvga", "-full", "-img"]

# ── Instrumentation injected around the assembled boot script ────────────────
# Memory.patchCode / Interceptor.attach are read-only, non-configurable props in
# Frida's QuickJS, so they can't be reassigned directly. BUT the *global bindings*
# `Memory` and `Interceptor` are writable — so we shadow each with a Proxy that
# intercepts the effect-producing method and forwards every other member (bound to
# the real receiver, which native Frida bindings require). Modules reference the
# globals, so their calls hit the proxies. rtToVa() (from lib/base.js, concatenated
# right after) is resolved at CALL time, by when it is defined.
_PROLOGUE = r"""
'use strict';
var __INV = { patches: [], hooks: [], seq: [] };
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
            var v = rtToVa(addr);
            __INV.patches.push({ va: v, bytes: bytes });
            __INV.seq.push({ op: 'patch', va: v });
        }
    });
    Memory = sM;

    var _I = Interceptor;
    var sI = Object.create(_I);
    Object.defineProperty(sI, 'attach', { configurable: true, writable: true, value:
        function (addr, cbs) {
            try { var v = rtToVa(addr); __INV.hooks.push({ va: v });
                  __INV.seq.push({ op: 'hook', va: v }); } catch (e) {}
            return _I.attach(addr, cbs);
        }
    });
    Interceptor = sI;
})();
"""

# Epilogue runs after every module (modules execute synchronously during
# scr.load()), shipping the recorded effect-set back to the harness.
_EPILOGUE = r"""
send({ tag: '__inv__', data: __INV });
"""


def _assemble(boot_dir: str) -> str:
    """Concatenate MANIFEST load_order modules exactly as launch.py does, wrapped
    in the instrumentation prologue/epilogue."""
    manifest_path = os.path.join(boot_dir, "MANIFEST.json")
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)
    parts = [_PROLOGUE]
    for entry in manifest["load_order"]:
        mod_path = os.path.join(boot_dir, *entry["module"].split("/"))
        with open(mod_path, encoding="utf-8", newline="") as mf:
            parts.append(mf.read())
    # If launch.py injects a patch table (data-driven patches), mirror that here
    # so the captured effect-set includes table-applied patches. The table file
    # is optional; absent before Phase 1.
    parts.append(_EPILOGUE)
    return "".join(parts)


def _canonical(effects: dict) -> dict:
    """Normal form. Patches/hooks are compared as SETS (a pure refactor may reorder
    *when* independent patches apply — e.g. data-table collapse — without changing
    the set). BUT at any address that is BOTH patched and hooked, the patch-vs-hook
    ORDER is itself behaviour (cf. the 'don't mix patchCode + Interceptor at one
    address' anti-pattern), so we additionally capture the op sequence per such
    collision address and compare it order-sensitively."""
    patches = sorted(
        ({"va": p["va"].lower(), "bytes": p["bytes"]} for p in effects.get("patches", [])),
        key=lambda p: (p["va"], tuple(p["bytes"])),
    )
    hooks = sorted({h["va"].lower() for h in effects.get("hooks", [])})
    # Per-address op sequence, retained only for addresses with >1 distinct op type.
    seq_by_va: dict = {}
    for ev in effects.get("seq", []):
        seq_by_va.setdefault(ev["va"].lower(), []).append(ev["op"])
    collisions = {va: ops for va, ops in seq_by_va.items() if len(set(ops)) > 1}
    return {"patches": patches, "hooks": hooks, "collisions": collisions}


def capture(boot_dir: str) -> dict:
    """Spawn nrs.exe suspended, load the instrumented boot script, capture the
    effect-set, and kill without resuming."""
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
        scr.load()  # modules run synchronously here; epilogue send() fires
        # Give async message delivery a moment to flush.
        deadline = time.time() + 3.0
        while "effects" not in captured and time.time() < deadline:
            time.sleep(0.05)
    finally:
        # Never resume — no game code runs. Just tear down.
        subprocess.run(["taskkill", "/F", "/IM", "nrs.exe"], capture_output=True)

    if "effects" not in captured:
        raise RuntimeError("no __inv__ payload received — script error? (see FRIDA_ERR above)")
    return _canonical(captured["effects"])


def capture_ref(ref: str) -> dict:
    """Capture the effect-set of a git ref by checking it out into a throwaway
    worktree (so the working tree is untouched)."""
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
    """Human-readable differences between two canonical effect-sets."""
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
    # Ordering drift at addresses that are both patched and hooked.
    ca, cb = a.get("collisions", {}), b.get("collisions", {})
    for va in sorted(set(ca) | set(cb)):
        if ca.get(va) != cb.get(va):
            out.append(f"  ! patch/hook ORDER differs at {va}: A={ca.get(va)} B={cb.get(va)}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dump", metavar="FILE", help="capture effect-set to FILE (JSON)")
    ap.add_argument("--ref", metavar="GITREF", help="capture this git ref instead of the working tree")
    ap.add_argument("--compare", metavar="GITREF",
                    help="capture GITREF and the working tree, diff, exit 1 on any difference")
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
