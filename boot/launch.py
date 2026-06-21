"""nrs.exe のスタンドアロンブートランチャ: ゲームを suspended で spawn し、ブートフック
（MANIFEST.json から組み立て）を導入、resume して pcpa_server.py を自動起動する。

Usage:
  python boot/launch.py --spawn              # 起動+アタッチ（推奨）
  python boot/launch.py --spawn --duration 300  # 5分間キャプチャ
  python boot/launch.py --pid 1234           # 実行中プロセスにアタッチ

Log: captures\frida-YYYYMMDD-HHMMSS.txt に自動保存
"""
import frida, sys, time, os, argparse, subprocess, threading

def _safe_print(text, file=None):
    """Windows の cp932 コンソール向けに UTF-8 フォールバックして print する。"""
    f = file or sys.stdout
    try:
        print(text, file=f)
    except UnicodeEncodeError:
        encoded = text.encode('ascii', errors='replace').decode('ascii')
        print(encoded, file=f)

CAPTURES_DIR   = os.path.join(os.path.dirname(__file__), "..", "captures")
GAME_DIR       = os.environ.get("NRS_GAME_DIR", r"C:\src\bbs")
GAME_EXE       = os.environ.get("NRS_EXE", os.path.join(GAME_DIR, "nrs.exe"))
GAME_ARGS      = ["-wsvga", "-full", "-img"]  # -img: game mode（nrs.bat 経由の game.bat より）
PYTHON_EXE     = os.path.join(os.environ.get("LOCALAPPDATA", ""), r"Programs\Python\Python313\python.exe")
PCPA_SERVER_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mxkeychip", "server", "pcpa_server.py")

# FRIDA_SCRIPT は MANIFEST.json に列挙されたブートモジュールを load 順（lib/base.js が先頭）に
# 連結して組み立てる。MANIFEST.json はブート構成（どのモジュールを、どの順で、subsys/persistence/
# va/network_role メタデータ付きで）の単一ソース。サブシステムは boot/<subsys>/<file>.js を編集し、モジュールの
# 追加/削除は MANIFEST.json で行う。
_BOOT_DIR = os.path.dirname(os.path.abspath(__file__))
_MANIFEST = os.path.join(_BOOT_DIR, "MANIFEST.json")

def _load_boot_script():
    import json
    with open(_MANIFEST, encoding="utf-8") as f:
        manifest = json.load(f)
    parts = []
    for entry in manifest["load_order"]:
        mod_path = os.path.join(_BOOT_DIR, *entry["module"].split("/"))
        with open(mod_path, encoding="utf-8", newline="") as mf:
            parts.append(mf.read())
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
    """pcpa_server.py が既に listen している（ポート 40106 が open）なら True を返す。"""
    import socket
    try:
        s = socket.create_connection(("127.0.0.1", 40106), timeout=0.3)
        s.close()
        return True
    except OSError:
        return False


def _ensure_pcpa_server() -> subprocess.Popen | None:
    """未起動なら pcpa_server.py をバックグラウンドで起動する。Popen または None を返す。"""
    if _is_pcpa_running():
        print("[*] pcpa_server already running — skipping auto-start.")
        return None
    print("[*] Starting pcpa_server.py in background...")
    proc = subprocess.Popen(
        [PYTHON_EXE, PCPA_SERVER_PY],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # サーバがポートを open するまで最大 3 秒待つ
    deadline = time.time() + 3.0
    while time.time() < deadline:
        if _is_pcpa_running():
            print(f"[*] pcpa_server.py started (PID={proc.pid})")
            return proc
        time.sleep(0.1)
    print(f"[!] pcpa_server.py PID={proc.pid} started but port 40106 not yet open — continuing anyway.")
    return proc


def _nrs_env() -> dict:
    """nrs.exe を spawn する際の環境: PATH に lib/win32/bin + captures ディレクトリのヒント。"""
    lib_path = os.path.join(GAME_DIR, "lib", "win32", "bin")
    env = os.environ.copy()
    env["PATH"] = lib_path + os.pathsep + env.get("PATH", "")
    # exit.js (boot/app) はこれを読み、リポジトリパスをハードコードせずに captures/exit_debug.txt を書く。
    env["NRS_CAPTURES_DIR"] = os.path.abspath(CAPTURES_DIR)
    return env


def _spawn_nrs_suspended() -> int:
    """
    実行中の nrs.exe を kill してから、frida.spawn() で新しいものを SUSPENDED で spawn する。
    pid を返す。プロセスは frida.resume(pid) まで entry point で凍結されるため、ゲームコード
    （amlib/device init を含む）が走る前に全ブートフックが導入される。
    """
    subprocess.run(['taskkill', '/F', '/IM', 'nrs.exe'], capture_output=True)
    time.sleep(0.3)
    pid = frida.spawn([GAME_EXE] + GAME_ARGS, cwd=GAME_DIR, env=_nrs_env())
    return pid


def _attach_and_monitor(pid: int, log_path: str, duration: int | None, resume: bool = False) -> None:
    """
    `pid` に Frida を attach してスクリプトを走らせ、`duration` 秒（またはプロセス終了 / Ctrl+C まで）
    待つ。

    `resume` が True なら、その pid は frida.spawn() で suspended に作られている: 先に全フックを
    導入してから frida.resume(pid) し、計測なしでゲームコードが走らないようにする。
    これは、ゲームが最初の命令で触る device/init エミュレーション（例: amSramInit/amEepromInit →
    mxsram/mxsmbus）に必要。
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
            # フックは live — suspended のプロセスを走らせる。
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
    単一フェーズの RingEdge ブート: 現行ビルドは early auth-exit 無しで ATTRACT まで直行するため、
    nrs.exe を 1 回 spawn して監視する。

    spawn=True なら（必要に応じて）pcpa_server を起動し nrs.exe を spawn する。
    pid が与えられた場合は既存プロセスへ attach するだけ（手動モード）。
    """
    os.makedirs(CAPTURES_DIR, exist_ok=True)
    log_path = os.path.join(CAPTURES_DIR, f"frida-{time.strftime('%Y%m%d-%H%M%S')}.txt")

    with open(log_path, 'w', encoding='utf-8') as f:
        f.write(f"=== Frida API Capture | {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n\n")
    print(f"[*] Log: {log_path}")

    if pid:
        # 手動 attach — 単一セッション、再起動ロジック無し
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

    # ── Spawn モード (suspended) ──────────────────────────────────────────────
    # nrs.exe が接続を試みる前に pcpa_server.py が起動していることを保証する
    pcpa_proc = _ensure_pcpa_server()

    print("[*] Spawning nrs.exe SUSPENDED (frida.spawn)...")
    pid = _spawn_nrs_suspended()
    print(f"[*] nrs.exe PID={pid} (suspended)")

    with open(log_path, 'a', encoding='utf-8') as f:
        f.write(f"\n=== PID={pid} (spawned suspended) ===\n")

    boot_dur = duration or 120
    print(f"[*] Attaching to PID={pid}, installing hooks, then resuming (up to {boot_dur}s)")
    _attach_and_monitor(pid, log_path, duration=boot_dur, resume=True)
    # Frida detach 後も nrs.exe は走り続ける。画面で Error 09xx を監視する。
    print(f"[*] Done (process left running). Log: {log_path}")


if __name__ == "__main__":
    # Windows コンソールは cp932。print 中の em-dash 等は UnicodeEncodeError を起こし run を中断させる。
    # クラッシュさせず、エンコードできない文字を置換する。
    try:
        sys.stdout.reconfigure(errors='replace')
        sys.stderr.reconfigure(errors='replace')
    except Exception:
        pass
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--pid',      type=int,  help='既存の PID に attach する')
    p.add_argument('--spawn',    action='store_true', help='frida.spawn で nrs.exe を suspended で spawn する（推奨）')
    p.add_argument('--duration', type=int,  help='キャプチャ秒数（デフォルト: Ctrl+C まで）')
    a = p.parse_args()
    run(pid=a.pid, spawn=a.spawn, duration=a.duration)
