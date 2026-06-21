#!/usr/bin/env python3
"""
最新の Frida capture ログを表示する (任意でフィルタ可能).

Usage:
  read_log.py                        最新ログ全体を表示
  read_log.py -f keychip             "keychip" を含む行に絞り込む
  read_log.py -f "JVS|WATCHDOG"      正規表現でフィルタ
  read_log.py -t 100                 末尾 100 行を表示
  read_log.py -l                     利用可能なログファイルを一覧
  read_log.py <filename_or_date>     特定のログを開く (例: "20260608-110910")
"""

import sys, os, re, glob

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "captures")
PATTERN = os.path.join(LOG_DIR, "frida-*.txt")

def latest_log():
    files = sorted(glob.glob(PATTERN))
    if not files:
        print(f"No logs found in {LOG_DIR}", file=sys.stderr)
        sys.exit(1)
    return files[-1]

def find_log(spec):
    files = sorted(glob.glob(PATTERN))
    for f in files:
        if spec in os.path.basename(f):
            return f
    print(f"No log matching '{spec}'", file=sys.stderr)
    sys.exit(1)

def show_log(path, filter_re=None, tail=None):
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        lines = fh.readlines()

    if filter_re:
        pat = re.compile(filter_re, re.IGNORECASE)
        lines = [l for l in lines if pat.search(l)]

    if tail:
        lines = lines[-tail:]

    print(f"=== {os.path.basename(path)} ({len(lines)} lines) ===")
    for line in lines:
        print(line, end='')

def main():
    args = sys.argv[1:]
    filter_re = None
    tail = None
    log_spec = None

    i = 0
    while i < len(args):
        a = args[i]
        if a == '-f' and i + 1 < len(args):
            filter_re = args[i + 1]; i += 2
        elif a == '-t' and i + 1 < len(args):
            tail = int(args[i + 1]); i += 2
        elif a == '-l':
            files = sorted(glob.glob(PATTERN))
            for f in files:
                size = os.path.getsize(f)
                print(f"  {os.path.basename(f)}  ({size:,} bytes)")
            return
        else:
            log_spec = a; i += 1

    path = find_log(log_spec) if log_spec else latest_log()
    show_log(path, filter_re, tail)

if __name__ == '__main__':
    main()
