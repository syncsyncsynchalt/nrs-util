"""Standalone boot launcher for nrs.exe: spawns the game suspended, installs the boot
hooks (assembled from MANIFEST.json), resumes, and auto-starts pcpa_server.py.

Usage:
  python boot/launch.py --spawn              # 起動+アタッチ（推奨）
  python boot/launch.py --spawn --duration 300  # 5分間キャプチャ
  python boot/launch.py --pid 1234           # 実行中プロセスにアタッチ

Log: captures\frida-YYYYMMDD-HHMMSS.txt に自動保存
"""
import frida, sys, time, os, argparse, subprocess, threading

def _safe_print(text, file=None):
    """Print with UTF-8 fallback for Windows cp932 consoles."""
    f = file or sys.stdout
    try:
        print(text, file=f)
    except UnicodeEncodeError:
        encoded = text.encode('ascii', errors='replace').decode('ascii')
        print(encoded, file=f)

CAPTURES_DIR   = os.path.join(os.path.dirname(__file__), "..", "captures")
GAME_DIR       = os.environ.get("NRS_GAME_DIR", r"C:\src\bbs")
GAME_EXE       = os.environ.get("NRS_EXE", os.path.join(GAME_DIR, "nrs.exe"))
GAME_ARGS      = ["-wsvga", "-full", "-img"]  # -img: game mode (from game.bat via nrs.bat)
PYTHON_EXE     = os.path.join(os.environ.get("LOCALAPPDATA", ""), r"Programs\Python\Python313\python.exe")
PCPA_SERVER_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mxkeychip", "server", "pcpa_server.py")

# FRIDA_SCRIPT is assembled by concatenating the boot modules listed in MANIFEST.json
# in load order (lib/base.js first). MANIFEST.json is the single source of truth for
# boot composition (which modules, in what order, with persistence/rva/ssot metadata).
# Edit a subsystem in boot/<subsys>/<file>.js; add/remove a module in MANIFEST.json.
_BOOT_DIR = os.path.dirname(os.path.abspath(__file__))
_MANIFEST = os.path.join(_BOOT_DIR, "MANIFEST.json")

def _patch_table_literal():
    """Raw JSON text of boot/patches.json (the data-driven pure-byte patch table),
    injected into the script as `var __PATCH_TABLE__ = [...]` right after lib/base.js
    so lib/patch_table.js can apply it. Absent/empty file -> '[]'."""
    p = os.path.join(_BOOT_DIR, "patches.json")
    try:
        with open(p, encoding="utf-8") as f:
            return f.read().strip() or "[]"
    except FileNotFoundError:
        return "[]"

def _load_boot_script():
    import json
    with open(_MANIFEST, encoding="utf-8") as f:
        manifest = json.load(f)
    parts = []
    for entry in manifest["load_order"]:
        mod_path = os.path.join(_BOOT_DIR, *entry["module"].split("/"))
        with open(mod_path, encoding="utf-8", newline="") as mf:
            parts.append(mf.read())
        # Inject the patch table right after base.js (keeps base.js's 'use strict'
        # first, and defines __PATCH_TABLE__ before lib/patch_table.js consumes it).
        if entry["module"] == "lib/base.js":
            parts.append("\nvar __PATCH_TABLE__ = " + _patch_table_literal() + ";\n")
    return "".join(parts)

FRIDA_SCRIPT = _load_boot_script()


def on_message(log_path: str):
    def handler(message, data):
        if message['type'] == 'send':
            payload = message['payload']
            line = f"[{payload.get('tag','?'):25s}] {payload.get('msg','')}"
            _safe_print(line)
            with open(log_path, 'a', encoding='utf-8') as f:
                f.write(line + '\n')
        elif message['type'] == 'error':
            err = f"[FRIDA_ERR] {message.get('description','')} | {message.get('stack','')[:300]}"
            _safe_print(err, file=sys.stderr)
            with open(log_path, 'a', encoding='utf-8') as f:
                f.write(err + '\n')
    return handler


def wait_for_process(name: str = "nrs.exe", timeout: int = 15) -> int | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = subprocess.run(['tasklist', '/FI', f'IMAGENAME eq {name}', '/FO', 'CSV', '/NH'],
                           capture_output=True, text=True)
        for line in r.stdout.splitlines():
            parts = line.strip('"').split('","')
            if len(parts) >= 2 and parts[0].lower() == name.lower():
                return int(parts[1])
        time.sleep(0.1)
    return None


def _is_pcpa_running() -> bool:
    """Return True if pcpa_server.py is already listening (port 40106 open)."""
    import socket
    try:
        s = socket.create_connection(("127.0.0.1", 40106), timeout=0.3)
        s.close()
        return True
    except OSError:
        return False


def _ensure_pcpa_server() -> subprocess.Popen | None:
    """Start pcpa_server.py in the background if not already running. Returns Popen or None."""
    if _is_pcpa_running():
        print("[*] pcpa_server already running — skipping auto-start.")
        return None
    print("[*] Starting pcpa_server.py in background...")
    proc = subprocess.Popen(
        [PYTHON_EXE, PCPA_SERVER_PY],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Wait up to 3s for the server to open its port
    deadline = time.time() + 3.0
    while time.time() < deadline:
        if _is_pcpa_running():
            print(f"[*] pcpa_server.py started (PID={proc.pid})")
            return proc
        time.sleep(0.1)
    print(f"[!] pcpa_server.py PID={proc.pid} started but port 40106 not yet open — continuing anyway.")
    return proc


def _nrs_env() -> dict:
    """Environment for spawning nrs.exe: lib/win32/bin on PATH + captures dir hint."""
    lib_path = os.path.join(GAME_DIR, "lib", "win32", "bin")
    env = os.environ.copy()
    env["PATH"] = lib_path + os.pathsep + env.get("PATH", "")
    # exit.js (boot/app) reads this to write captures/exit_debug.txt without hardcoding a repo path.
    env["NRS_CAPTURES_DIR"] = os.path.abspath(CAPTURES_DIR)
    return env


def _spawn_nrs_suspended() -> int:
    """
    Kill any running nrs.exe, then spawn a fresh one SUSPENDED via frida.spawn().
    Returns the pid. The process is frozen at its entry point until frida.resume(pid),
    so every boot hook is installed before any game code (incl. amlib/device init) runs.
    """
    subprocess.run(['taskkill', '/F', '/IM', 'nrs.exe'], capture_output=True)
    time.sleep(0.3)
    pid = frida.spawn([GAME_EXE] + GAME_ARGS, cwd=GAME_DIR, env=_nrs_env())
    return pid


def _attach_and_monitor(pid: int, log_path: str, duration: int | None, resume: bool = False) -> None:
    """
    Attach Frida to `pid`, run the script, then wait for `duration` seconds
    (or until the process exits / Ctrl+C).

    If `resume` is True the pid was created suspended via frida.spawn(): we install
    ALL hooks first, then frida.resume(pid) so no game code runs un-instrumented.
    This is required for device/init emulation that the game touches at the very
    first instructions (e.g. amSramInit/amEepromInit → mxsram/mxsmbus).
    """
    detached_event = threading.Event()

    def _on_detached(reason, crash=None):
        print(f"[*] Frida detached: reason={reason}")
        detached_event.set()

    try:
        sess = frida.attach(pid)
        sess.on('detached', _on_detached)
        scr  = sess.create_script(FRIDA_SCRIPT)
        scr.on('message', on_message(log_path))
        scr.load()
        if resume:
            # Hooks are live — let the suspended process run.
            frida.resume(pid)
            print(f"[*] Resumed PID={pid} (hooks installed before any game code ran)")

        if duration:
            print(f"[*] Monitoring for up to {duration}s (or until process exits)...")
            detached_event.wait(timeout=duration)
        else:
            print("[*] Monitoring (Ctrl+C to stop)...")
            try:
                detached_event.wait()
            except KeyboardInterrupt:
                pass
    except Exception as e:
        print(f"[!] Frida error: {e}")
    finally:
        try:
            sess.detach()
        except Exception:
            pass


def run(pid: int | None = None, spawn: bool = False, duration: int | None = None) -> None:
    """
    Single-phase RingEdge boot: current builds boot straight to ATTRACT with no
    early auth-exit, so we spawn nrs.exe once and monitor it.

    If spawn=True we start pcpa_server (if needed) and spawn nrs.exe.
    If pid is given we just attach to an existing process (manual mode).
    """
    os.makedirs(CAPTURES_DIR, exist_ok=True)
    log_path = os.path.join(CAPTURES_DIR, f"frida-{time.strftime('%Y%m%d-%H%M%S')}.txt")

    with open(log_path, 'w', encoding='utf-8') as f:
        f.write(f"=== Frida API Capture | {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n\n")
    print(f"[*] Log: {log_path}")

    if pid:
        # Manual attach — single session, no relaunch logic
        print(f"[*] Attaching to PID={pid}")
        _attach_and_monitor(pid, log_path, duration)
        print(f"[*] Done. Log: {log_path}")
        return

    if not spawn:
        print("[*] Waiting for nrs.exe (no --spawn)...")
        pid = wait_for_process("nrs.exe", timeout=20)
        if not pid:
            print("[!] nrs.exe not found within 20s")
            return
        print(f"[*] Attaching to PID={pid}")
        _attach_and_monitor(pid, log_path, duration)
        print(f"[*] Done. Log: {log_path}")
        return

    # ── Spawn mode (suspended) ──────────────────────────────────────────────
    # Ensure pcpa_server.py is running before nrs.exe tries to connect
    pcpa_proc = _ensure_pcpa_server()

    print("[*] Spawning nrs.exe SUSPENDED (frida.spawn)...")
    pid = _spawn_nrs_suspended()
    print(f"[*] nrs.exe PID={pid} (suspended)")

    with open(log_path, 'a', encoding='utf-8') as f:
        f.write(f"\n=== PID={pid} (spawned suspended) ===\n")

    boot_dur = duration or 120
    print(f"[*] Attaching to PID={pid}, installing hooks, then resuming (up to {boot_dur}s)")
    _attach_and_monitor(pid, log_path, duration=boot_dur, resume=True)
    # nrs.exe keeps running after Frida detaches; watch the screen for Error 09xx.
    print(f"[*] Done (process left running). Log: {log_path}")


if __name__ == "__main__":
    # Windows console is cp932; em-dash etc. in prints would raise UnicodeEncodeError
    # and abort the run. Replace unencodable chars instead of crashing.
    try:
        sys.stdout.reconfigure(errors='replace')
        sys.stderr.reconfigure(errors='replace')
    except Exception:
        pass
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--pid',      type=int,  help='attach to existing PID')
    p.add_argument('--spawn',    action='store_true', help='spawn nrs.exe suspended via frida.spawn (recommended)')
    p.add_argument('--duration', type=int,  help='capture duration in seconds (default: until Ctrl+C)')
    a = p.parse_args()
    run(pid=a.pid, spawn=a.spawn, duration=a.duration)
