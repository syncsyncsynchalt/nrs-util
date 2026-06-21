"""boot/launch.py が出力する Frida capture ログを要約する.

boot/launch.py の console.log() が書く以下の形式の行をパースする:
  [HH:MM:SS.mmm][TAG] message

Usage:
  python log_analyzer.py <logfile>           # 全体要約
  python log_analyzer.py <logfile> --iife X  # 1 つの IIFE に絞り込む (例: hookPcpa)
  python log_analyzer.py <logfile> --errors  # error/exception 行のみ表示
  python log_analyzer.py <logfile> --pcpa    # PCPA request/response テーブル
  python log_analyzer.py <logfile> --sm      # amDongle SM 状態遷移
  python log_analyzer.py <logfile> --jvs     # JVS フックイベント
  python log_analyzer.py -                   # 標準入力から読む

生の Frida 出力 ("[pid:...] message" 形式やプレーンテキスト) も受け付ける。
"""
import re, sys, collections, textwrap
from pathlib import Path
from datetime import datetime

# Frida モニタログ行のパターン
RE_LINE   = re.compile(r'^\[(\d{2}:\d{2}:\d{2}\.\d{3})\]\[([^\]]+)\]\s*(.*)')
RE_PCPA_REQ = re.compile(r'(?:PCPA|pcpa).*?(?:send|req)[:\s]+(.+)', re.IGNORECASE)
RE_PCPA_RSP = re.compile(r'(?:PCPA|pcpa).*?(?:recv|rsp|resp)[:\s]+(.+)', re.IGNORECASE)
RE_SM_STATE = re.compile(r'(?:outerSM|keychipSM|state)\s*[=:]\s*(\d+)', re.IGNORECASE)
RE_HOOK_ENTER = re.compile(r'(?:enter|onEnter)[:\s]+(0x[0-9a-fA-F]+|[A-Za-z]\w+)', re.IGNORECASE)
RE_HOOK_LEAVE = re.compile(r'(?:leave|onLeave|ret(?:val)?)[:\s]+(0x[0-9a-fA-F]+|-?\d+)', re.IGNORECASE)
RE_ERROR  = re.compile(r'(?:Error|Exception|CRASH|FAULT|assert)', re.IGNORECASE)
RE_NRSBASE = re.compile(r'nrsBase\s*[=:]\s*(0x[0-9a-fA-F]+)')


def parse_file(path: str) -> list[dict]:
    src = sys.stdin if path == "-" else open(path, encoding="utf-8", errors="replace")
    entries = []
    with src:
        for lineno, raw in enumerate(src, 1):
            raw = raw.rstrip()
            m = RE_LINE.match(raw)
            if m:
                ts, tag, msg = m.group(1), m.group(2), m.group(3)
            else:
                ts, tag, msg = "", "RAW", raw
            entries.append({"lineno": lineno, "ts": ts, "tag": tag, "msg": msg, "raw": raw})
    return entries


def summary(entries: list[dict]):
    tag_counts = collections.Counter(e["tag"] for e in entries)
    error_lines = [e for e in entries if RE_ERROR.search(e["msg"])]
    nrsbase_lines = [e for e in entries if RE_NRSBASE.search(e["msg"])]

    print(f"=== Log summary: {len(entries)} lines ===\n")

    if nrsbase_lines:
        print("nrsBase observations:")
        for e in nrsbase_lines[:5]:
            print(f"  [{e['ts']}] {e['msg']}")
        print()

    print("Tag counts (top 30):")
    for tag, cnt in tag_counts.most_common(30):
        print(f"  {cnt:6d}  {tag}")
    print()

    if error_lines:
        print(f"Errors/exceptions ({len(error_lines)} lines):")
        for e in error_lines[:20]:
            print(f"  L{e['lineno']:5d} [{e['ts']}][{e['tag']}] {e['msg']}")
        if len(error_lines) > 20:
            print(f"  ... and {len(error_lines)-20} more")
        print()


def show_pcpa(entries: list[dict]):
    print("=== PCPA exchange log ===\n")
    port_sessions: dict[str, list] = {}
    for e in entries:
        tag = e["tag"]
        msg = e["msg"]
        if "pcpa" not in tag.lower() and "pcpa" not in msg.lower():
            continue
        # port を検出できればそれでグループ化
        pm = re.search(r'\b(40\d{3})\b', msg)
        port = pm.group(1) if pm else "?"
        port_sessions.setdefault(port, []).append(e)

    for port, evts in sorted(port_sessions.items()):
        print(f"--- Port {port} ({len(evts)} events) ---")
        for e in evts[:50]:
            print(f"  [{e['ts']}] {e['msg']}")
        if len(evts) > 50:
            print(f"  ... {len(evts)-50} more events")
        print()


def show_sm(entries: list[dict]):
    print("=== amDongle SM state transitions ===\n")
    prev_outer = prev_keychip = None
    for e in entries:
        msg = e["msg"]
        if "outer" in msg.lower() or "keychip" in msg.lower() or "state" in msg.lower():
            sm = re.search(r'(outer|keychip)SM.*?state\s*[=:]\s*(\d+)', msg, re.IGNORECASE)
            if sm:
                kind, state = sm.group(1).lower(), sm.group(2)
                if kind == "outer" and state != prev_outer:
                    print(f"  [{e['ts']}] outerSM → state {state}")
                    prev_outer = state
                elif kind == "keychip" and state != prev_keychip:
                    print(f"  [{e['ts']}] keychipSM → state {state}")
                    prev_keychip = state
            else:
                print(f"  [{e['ts']}][{e['tag']}] {msg}")


def show_jvs(entries: list[dict]):
    print("=== JVS hook events ===\n")
    for e in entries:
        tag = e["tag"].lower()
        msg = e["msg"].lower()
        if any(k in tag or k in msg for k in ("jvs", "6401", "6402", "amjvs", "bypassjvs")):
            print(f"  [{e['ts']}][{e['tag']}] {e['msg']}")


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return

    path = args[0]
    flags = set(a.lower() for a in args[1:])

    entries = parse_file(path)

    # IIFE フィルタ
    iife_filter = None
    for i, a in enumerate(args[1:], 1):
        if a == "--iife" and i < len(args) - 1:
            iife_filter = args[i + 1].lower()
    if iife_filter:
        entries = [e for e in entries if iife_filter in e["tag"].lower() or iife_filter in e["msg"].lower()]
        print(f"Filtered to {len(entries)} lines matching '{iife_filter}'\n")

    if "--errors" in flags:
        errs = [e for e in entries if RE_ERROR.search(e["msg"])]
        print(f"=== Errors ({len(errs)} lines) ===")
        for e in errs:
            print(f"  L{e['lineno']:5d} [{e['ts']}][{e['tag']}] {e['msg']}")
    elif "--pcpa" in flags:
        show_pcpa(entries)
    elif "--sm" in flags:
        show_sm(entries)
    elif "--jvs" in flags:
        show_jvs(entries)
    else:
        summary(entries)


if __name__ == "__main__":
    main()
