"""nrs.exe のスタンドアロンブートランチャ: ゲームを suspended で spawn し、ブートフック
（MANIFEST.json から組み立て）を導入、resume して pcpa_server.py を自動起動する。

Usage:
  python boot/launch.py --spawn              # 起動+アタッチ（推奨）
  python boot/launch.py --spawn --duration 300  # 5分間キャプチャ
  python boot/launch.py --pid 1234           # 実行中プロセスにアタッチ
  python boot/launch.py --spawn --diag tools/runtime/frida_diag/gl_init_diag.js  # 観測 .js を併注入

Log: captures\frida-YYYYMMDD-HHMMSS.txt に自動保存
"""
import frida, sys, time, os, argparse, subprocess, threading, datetime, re, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # 同ディレクトリの log_gui を import
import log_gui  # GUI ログビューア（Tkinter 不在でも import 可。TK_OK で判定）

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

def _load_boot_script(extra_paths=None):
    import json
    with open(_MANIFEST, encoding="utf-8") as f:
        manifest = json.load(f)
    parts = []
    for entry in manifest["load_order"]:
        mod_path = os.path.join(_BOOT_DIR, *entry["module"].split("/"))
        with open(mod_path, encoding="utf-8", newline="") as mf:
            parts.append(mf.read())
    # --diag で渡された観測スクリプトを boot バンドル末尾に連結する。lib/base.js が先頭という不変条件は
    # 保たれるため、追記分は logMsg/hookFn/va/rtToVa/watch などの共通ヘルパをそのまま使える。frida_diag/*.js は
    # MANIFEST 非登録の観測専用で本番ブートには載せない（--diag を渡したときだけ連結される）。
    _repo_root = os.path.dirname(_BOOT_DIR)
    for p in (extra_paths or []):
        rp = p if os.path.isfile(p) else os.path.join(_repo_root, p)
        with open(rp, encoding="utf-8", newline="") as ef:
            parts.append("\n// ==== diag: %s ====\n" % os.path.basename(rp))
            parts.append(ef.read())
    return "".join(parts)


def _ts() -> str:
    """pcpa_server.py の ts() と同形式（HH:MM:SS.mmm）。全ログの時刻表記を揃える。"""
    return datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]


# pcpa_server.py の出力行 "[ts][PCPA:port] ..." をパースする。
_PCPA_RE = re.compile(r'^\[[\d:.]+\]\[PCPA:(\d+)\]\s*(.*)$')


class _Sink:
    """全ログの単一経路。human .txt ＋ 構造化 .jsonl（AI 解析向け）に書き、GUI があれば submit、
    無ければ本流コンソールへ print する。frida/pcpa/launcher の全ログがここを通る = 1窓集約。"""

    def __init__(self, log_path: str, jsonl_path: str, gui=None):
        self.log_path = log_path
        self.jsonl_path = jsonl_path
        self.gui = gui
        self._lock = threading.Lock()

    def emit(self, src: str, msg: str, lvl: str | None = None) -> None:
        ts = _ts()
        if lvl is None:
            lvl = log_gui.level_of(src, msg)
        human = f"[{ts}] [{src:25s}] {msg}"
        rec = {"ts": ts, "src": src, "lvl": lvl, "msg": msg}
        with self._lock:
            try:
                with open(self.log_path, 'a', encoding='utf-8') as f:
                    f.write(human + '\n')
            except Exception:
                pass
            try:
                with open(self.jsonl_path, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + '\n')
            except Exception:
                pass
        if self.gui is not None:
            self.gui.submit(rec)
        else:
            _safe_print(human, file=sys.stderr if lvl == "error" else None)


def on_message(sink: "_Sink"):
    def handler(message, data):
        if message['type'] == 'send':
            payload = message['payload']
            sink.emit(payload.get('tag', '?'), str(payload.get('msg', '')))
        elif message['type'] == 'error':
            sink.emit('FRIDA_ERR',
                      f"{message.get('description','')} | {message.get('stack','')[:300]}",
                      lvl='error')
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


def _kill_existing_pcpa() -> None:
    """ポート 40106 を握る既存 pcpa を終了する。前回ランの残存 pcpa があると今回は起動スキップされ、
    その keychip ログが現在のコンソール窓に出ない（=「全部出てない」の主因）。毎回 fresh に起動して
    本流コンソールへ集約するため、先に確実に落とす。"""
    try:
        r = subprocess.run(['netstat', '-ano', '-p', 'tcp'], capture_output=True, text=True)
        pids = set()
        for ln in r.stdout.splitlines():
            if ':40106' in ln and 'LISTEN' in ln.upper():
                tok = ln.split()
                if tok and tok[-1].isdigit():
                    pids.add(tok[-1])
        for pid in pids:
            subprocess.run(['taskkill', '/F', '/PID', pid], capture_output=True)
    except Exception:
        pass


def _ensure_pcpa_server(sink: "_Sink") -> subprocess.Popen | None:
    """pcpa_server.py を毎回 fresh に起動し、stdout を pipe で取り込んで sink へ流す（=全ログ1窓集約）。
    pcpa の各行 "[ts][PCPA:port] ..." をパースして src=PCPA:port の entry にする。"""
    _kill_existing_pcpa()
    time.sleep(0.2)
    sink.emit('LAUNCH', 'Starting pcpa_server.py (piped into log)...')
    proc = subprocess.Popen(
        [PYTHON_EXE, PCPA_SERVER_PY],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding='utf-8', errors='replace', bufsize=1)

    def _reader():
        try:
            for line in proc.stdout:
                line = line.rstrip('\r\n')
                if not line:
                    continue
                m = _PCPA_RE.match(line)
                if m:
                    sink.emit(f'PCPA:{m.group(1)}', m.group(2))
                else:
                    sink.emit('PCPA', line)
        except Exception:
            pass
    threading.Thread(target=_reader, daemon=True, name='pcpa-reader').start()

    deadline = time.time() + 3.0
    while time.time() < deadline:
        if _is_pcpa_running():
            sink.emit('LAUNCH', f'pcpa_server.py started (PID={proc.pid})')
            return proc
        time.sleep(0.1)
    sink.emit('LAUNCH', f'pcpa_server.py PID={proc.pid} started but port 40106 not open yet')
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


def _attach_and_monitor(pid: int, sink: "_Sink", duration: int | None, resume: bool = False,
                        script: str | None = None, stop_event: "threading.Event | None" = None) -> None:
    """
    `pid` に Frida を attach してスクリプトを走らせ、プロセス終了 / `duration` 秒 / `stop_event`
    （GUI 窓を閉じた）/ Ctrl+C まで待つ。

    `resume` が True なら、その pid は frida.spawn() で suspended に作られている: 先に全フックを
    導入してから frida.resume(pid) し、計測なしでゲームコードが走らないようにする。
    これは、ゲームが最初の命令で触る device/init エミュレーション（例: amSramInit/amEepromInit →
    mxsram/mxsmbus）に必要。
    """
    detached_event = threading.Event()

    def _on_detached(reason, crash=None):
        sink.emit('LAUNCH', f'Frida detached: reason={reason}')
        detached_event.set()

    sess = None
    try:
        sess = frida.attach(pid)
        sess.on('detached', _on_detached)
        scr  = sess.create_script(script if script is not None else _load_boot_script())
        scr.on('message', on_message(sink))
        scr.load()
        if resume:
            # フックは live — suspended のプロセスを走らせる。
            frida.resume(pid)
            sink.emit('LAUNCH', f'Resumed PID={pid} (hooks installed before any game code ran)')

        if duration:
            sink.emit('LAUNCH', f'Monitoring up to {duration}s (or until exit / window close)...')
        else:
            sink.emit('LAUNCH', 'Monitoring (close window or Ctrl+C to stop)...')
        end = (time.time() + duration) if duration else None
        try:
            while not detached_event.is_set():
                if stop_event is not None and stop_event.is_set():
                    break
                timeout = 0.3
                if end is not None:
                    rem = end - time.time()
                    if rem <= 0:
                        break
                    timeout = min(0.3, rem)
                detached_event.wait(timeout=timeout)
        except KeyboardInterrupt:
            pass
    except Exception as e:
        sink.emit('LAUNCH', f'Frida error: {e}', lvl='error')
    finally:
        try:
            if sess is not None:
                sess.detach()
        except Exception:
            pass


def _shutdown(sink: "_Sink | None" = None) -> None:
    """セッション終了（窓を閉じる / --duration 経過 / Ctrl+C）で nrs.exe と pcpa_server を
    まとめて終了する（クリーンな自動終了）。--keep 指定時は呼ばれない。"""
    def _say(m):
        if sink is not None:
            sink.emit('LAUNCH', m)
        else:
            print(f"[*] {m}")
    _say('Shutting down nrs.exe + pcpa_server...')
    subprocess.run(['taskkill', '/F', '/IM', 'nrs.exe'], capture_output=True)
    _kill_existing_pcpa()
    _say('Shutdown complete.')


def _session(sink: "_Sink", pid: int | None, spawn: bool, duration: int | None,
             script: str, stop_event: "threading.Event | None") -> None:
    """1回のブート/監視セッション本体。GUI モードでは worker スレッドから、console モードでは
    main スレッドから呼ばれる（Tk には触れず sink.emit のみ＝スレッド安全）。"""
    if pid:
        sink.emit('LAUNCH', f'Attaching to PID={pid}')
        _attach_and_monitor(pid, sink, duration, script=script, stop_event=stop_event)
        sink.emit('LAUNCH', 'Done.')
        return

    if not spawn:
        sink.emit('LAUNCH', 'Waiting for nrs.exe (no --spawn)...')
        pid = wait_for_process("nrs.exe", timeout=20)
        if not pid:
            sink.emit('LAUNCH', 'nrs.exe not found within 20s', lvl='error')
            return
        sink.emit('LAUNCH', f'Attaching to PID={pid}')
        _attach_and_monitor(pid, sink, duration, script=script, stop_event=stop_event)
        sink.emit('LAUNCH', 'Done.')
        return

    # ── Spawn モード (suspended) ──────────────────────────────────────────────
    _ensure_pcpa_server(sink)   # nrs 接続前に pcpa を起動（pipe で取り込み）
    sink.emit('LAUNCH', 'Spawning nrs.exe SUSPENDED (frida.spawn)...')
    pid = _spawn_nrs_suspended()
    sink.emit('LAUNCH', f'nrs.exe PID={pid} (suspended); installing hooks then resuming')
    _attach_and_monitor(pid, sink, duration=duration, resume=True, script=script,
                        stop_event=stop_event)
    # 後始末（nrs.exe/pcpa の終了）は run() が担う。
    sink.emit('LAUNCH', 'Monitoring ended.')


def run(pid: int | None = None, spawn: bool = False, duration: int | None = None,
        diag_paths: list | None = None, gui: bool = False, keep: bool = False) -> None:
    """
    RingEdge ブート: nrs.exe を spawn（または既存に attach）して全ログを集約表示する。
    gui=True かつ Tkinter 利用可なら GUI ログ窓を出す（プレイ中は開いたまま）。それ以外は console。
    全ログは captures/frida-*.txt（人間用）と captures/frida-*.jsonl（AI 解析用）に保存する。
    セッション終了（窓を閉じる / --duration 経過 / Ctrl+C）で nrs.exe と pcpa_server を自動終了する
    （keep=True なら残す）。
    """
    os.makedirs(CAPTURES_DIR, exist_ok=True)
    stamp = time.strftime('%Y%m%d-%H%M%S')
    log_path = os.path.join(CAPTURES_DIR, f"frida-{stamp}.txt")
    jsonl_path = os.path.join(CAPTURES_DIR, f"frida-{stamp}.jsonl")
    with open(log_path, 'w', encoding='utf-8') as f:
        f.write(f"=== Frida API Capture | {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n\n")
    open(jsonl_path, 'w', encoding='utf-8').close()

    script = _load_boot_script(diag_paths)

    use_gui = gui and log_gui.TK_OK
    if gui and not log_gui.TK_OK:
        print("[!] Tkinter 利用不可 — console モードにフォールバックします。")

    if not use_gui:
        sink = _Sink(log_path, jsonl_path, gui=None)
        sink.emit('LAUNCH', f'Log: {log_path}  |  JSONL: {jsonl_path}')
        if diag_paths:
            sink.emit('LAUNCH', f'diag appended: {", ".join(diag_paths)}')
        try:
            _session(sink, pid, spawn, duration, script, stop_event=None)
        finally:
            if keep:
                sink.emit('LAUNCH', 'nrs.exe / pcpa は継続させます（--keep）。')
            else:
                _shutdown(sink)
        return

    # ── GUI モード: Tk を main スレッドで、セッションを worker スレッドで動かす ──
    stop_event = threading.Event()
    gui_obj = log_gui.LogGui(title=f"nrs-util boot log — {stamp}", on_close=stop_event.set)
    sink = _Sink(log_path, jsonl_path, gui=gui_obj)
    sink.emit('LAUNCH', f'Log: {log_path}')
    sink.emit('LAUNCH', f'JSONL (AI 解析用): {jsonl_path}')
    if diag_paths:
        sink.emit('LAUNCH', f'diag appended: {", ".join(diag_paths)}')

    def _worker():
        try:
            _session(sink, pid, spawn, duration, script, stop_event=stop_event)
        except Exception as e:
            sink.emit('LAUNCH', f'session error: {e}', lvl='error')
        # 監視終了（detach / --duration 経過）後も GUI 窓は開いたまま。ログを読む・フィルタ/検索/書出が可能。
        msg = ('監視終了。窓を閉じると終了します（nrs.exe/pcpa は継続：--keep）。' if keep
               else '監視終了。窓を閉じると nrs.exe / pcpa も終了します。ログは引き続き読めます。')
        sink.emit('LAUNCH', msg)
    worker = threading.Thread(target=_worker, daemon=True, name='session')
    worker.start()
    gui_obj.run()           # 窓を閉じるまでブロック（プレイ中・監視終了後も開いたまま）
    stop_event.set()        # 窓が閉じられた → セッション停止を通知
    worker.join(timeout=5)
    if not keep:
        _shutdown(sink)     # 窓を閉じたら nrs.exe / pcpa も自動終了


def _ensure_console() -> None:
    """端末を持たずに起動された場合（pythonw / ダブルクリック）でも、デフォルトでコンソールを
    表示する。既にコンソールがあれば（PowerShell 等から実行）何もしない。"""
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        if k32.GetConsoleWindow() == 0:          # コンソール未接続なら新規割当
            if k32.AllocConsole():
                k32.SetConsoleTitleW("nrs-util launch (frida log)")
                sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="replace")
                sys.stderr = open("CONOUT$", "w", encoding="utf-8", errors="replace")
                sys.stdin  = open("CONIN$",  "r", encoding="utf-8", errors="replace")
    except Exception:
        pass


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--pid',      type=int,  help='既存の PID に attach する')
    p.add_argument('--spawn',    action='store_true', help='frida.spawn で nrs.exe を suspended で spawn する（推奨）')
    p.add_argument('--duration', type=int,  help='キャプチャ秒数（デフォルト: 窓を閉じる / Ctrl+C まで）')
    p.add_argument('--diag', action='append', default=None, metavar='PATH',
                   help='観測専用 .js を boot バンドル末尾に連結（繰り返し可）。'
                        '例: tools/runtime/frida_diag/gl_init_diag.js')
    g = p.add_mutually_exclusive_group()
    g.add_argument('--gui',    dest='gui', action='store_true',  default=True,
                   help='GUI ログ窓で表示（既定）。絞り込み/検索/JSONL 書出付き。')
    g.add_argument('--no-gui', dest='gui', action='store_false',
                   help='GUI を使わず console に出す（自動化/ヘッドレス向け）。')
    p.add_argument('--keep', action='store_true',
                   help='セッション終了後も nrs.exe / pcpa_server を残す（既定は自動終了）。')
    a = p.parse_args()

    # console モードのときだけ、端末なし起動でもログ窓を出す（GUI モードは Tk 窓があるので不要）。
    if not a.gui:
        _ensure_console()
        # Windows コンソールは cp932。print 中の em-dash 等の UnicodeEncodeError を置換でしのぐ。
        try:
            sys.stdout.reconfigure(errors='replace')
            sys.stderr.reconfigure(errors='replace')
        except Exception:
            pass
    run(pid=a.pid, spawn=a.spawn, duration=a.duration, diag_paths=a.diag, gui=a.gui, keep=a.keep)
