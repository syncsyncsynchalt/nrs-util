#!/usr/bin/env python3
"""
JvsState / TeknoParrot 観測キャプチャ（純観測・TeknoParrot 注入下用）.

モード:
  (1) デフォルト: jvsstate_trace.js のみ — TeknoParrot_JvsState 共有メモリの
      発生源コールスタックと 8 バイト変化を記録する。
  (2) --trace-tp:  jvsstate_trace.js + tp_trace.js を同時ロード —
      VirtualProtect/GetProcAddress/LoadLibrary/Socket も追跡し、TP が nrs.exe に
      当てるパッチの RVA と TP の実行時 API 解決を観測する（docs/teknoparrot.md §5 参照）。

★ boot/launch.py は boot/*.js を全連結し 08/09/10/13 等の patchCode を適用するため、
   TP 管理下の nrs.exe に attach すると二重適用で破綻する。観測時は必ず本スクリプトを使うこと。

使い方:
    # JvsState ビットマップ観測（入力束縛後に実行）
    python tools/runtime/jvsstate_capture.py --wait 60 --duration 120

    # TP 動作解析（VP_EXEC 行が TP のパッチ、GPA 行が API 解決）
    python tools/runtime/jvsstate_capture.py --trace-tp --wait 60 --duration 120

    # 別途 TeknoParrot を起動:
    #   cd C:\\src\\TPBootstrapper
    #   .\\OpenParrotWin32\\OpenParrotLoader.exe .\\TeknoParrot\\TeknoParrot "C:\\src\\bbs\\nrs.exe"
"""
import argparse, os, sys, time, subprocess

import frida

DIAG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frida_diag")
SCRIPT_PATH = os.path.join(DIAG_DIR, "jvsstate_trace.js")
SCRIPT_TRACE_TP = os.path.join(DIAG_DIR, "tp_trace.js")
CAPTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "captures")


def wait_for_process(name="nrs.exe", timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = subprocess.run(['tasklist', '/FI', f'IMAGENAME eq {name}', '/FO', 'CSV', '/NH'],
                           capture_output=True, text=True)
        for line in r.stdout.splitlines():
            parts = line.strip('"').split('","')
            if len(parts) >= 2 and parts[0].lower() == name.lower():
                return int(parts[1])
        time.sleep(0.2)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--duration", type=int, default=90)
    ap.add_argument("--wait", type=int, default=60, help="seconds to wait for nrs.exe")
    ap.add_argument("--trace-tp", action="store_true",
                    help="also load tp_trace.js to observe TeknoParrot.dll behavior "
                         "(VirtualProtect/GetProcAddress/LoadLibrary/Socket hooks)")
    args = ap.parse_args()

    os.makedirs(CAPTURES_DIR, exist_ok=True)
    suffix = "-tp" if args.trace_tp else ""
    log_path = os.path.join(CAPTURES_DIR, f"jvsstate{suffix}-{time.strftime('%Y%m%d-%H%M%S')}.txt")
    with open(log_path, 'w', encoding='utf-8') as f:
        f.write(f"=== JvsState capture | {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n\n")
    print(f"[*] Log: {log_path}")

    pid = args.pid or wait_for_process("nrs.exe", timeout=args.wait)
    if not pid:
        print(f"[!] nrs.exe not found within {args.wait}s. Launch it via "
              f"TeknoParrotUi.exe --profile=<NRS profile> first.")
        return 1
    print(f"[*] Attaching to nrs.exe PID={pid}")

    scripts = [SCRIPT_PATH]
    if args.trace_tp:
        if not os.path.exists(SCRIPT_TRACE_TP):
            print(f"[!] --trace-tp: {SCRIPT_TRACE_TP} not found")
            return 1
        scripts.append(SCRIPT_TRACE_TP)
        print(f"[*] Loading: jvsstate_trace.js + tp_trace.js")

    src_parts = []
    for sp in scripts:
        with open(sp, encoding="utf-8", newline="") as f:
            src_parts.append(f.read())
    src = "\n".join(src_parts)

    def on_message(message, data):
        if message['type'] == 'send':
            p = message['payload']
            line = f"[{p.get('tag','?'):20s}] {p.get('msg','')}"
        elif message['type'] == 'error':
            line = f"[FRIDA_ERR] {message.get('description','')}"
        else:
            line = f"[?] {message}"
        try:
            print(line)
        except Exception:
            print(line.encode('ascii', 'replace').decode('ascii'))
        with open(log_path, 'a', encoding='utf-8') as fh:
            fh.write(line + '\n')

    sess = frida.attach(pid)
    scr = sess.create_script(src)
    scr.on('message', on_message)
    scr.load()
    print(f"[*] Observing for {args.duration}s "
          f"(operate Test/Service/Coin/Start/Jump/Dash/Action to map bits)...")
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass
    try:
        sess.detach()
    except Exception:
        pass
    print(f"[*] Done. Log: {log_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
