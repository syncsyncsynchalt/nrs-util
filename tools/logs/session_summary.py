"""最新の Frida セッションログを観点ごとに 1 行で要約する.

Usage:
  python session_summary.py              # 最新の captures/frida-*.txt を要約
  python session_summary.py <logfile>    # 特定のログを要約
"""
import sys, os, re, glob, collections, io
from pathlib import Path

# Windows で UTF-8 出力を強制 (デフォルトの cp932 は多くの Unicode 文字を encode できない)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'captures')
PATTERN = os.path.join(LOG_DIR, 'frida-[0-9]*.txt')

# ログ形式: "[TAG                     ] message"
RE_LINE  = re.compile(r'^\[([^\]]+)\]\s+(.*)')
RE_HLSM  = re.compile(r'state=(\d+)', re.I)
RE_ERR   = re.compile(r'ERR_DISPLAY|Error \d{4}|EXCEPTION_HANDLER|EXCEPTION_ACCESS|TerminateProcess')
RE_PCPA_REQ = re.compile(r'request=(\w+)', re.I)
RE_BOOT  = re.compile(r'BOOT_DONE|ATTRACT', re.I)
RE_GETSTATUS_FIX = re.compile(r'GETSTATUS_FIX', re.I)
RE_HEADER = re.compile(r'^=== Frida API Capture \| (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})')

def latest_log():
    files = sorted(glob.glob(PATTERN))
    if not files:
        sys.exit(f'No logs in {LOG_DIR}')
    return files[-1]

def summarize(path):
    lines = Path(path).read_text(encoding='utf-8', errors='replace').splitlines()
    name = os.path.basename(path)

    start_time = None
    end_time = None
    hlsm_states = []
    errors = []
    pcpa_reqs = collections.Counter()
    boot_done = False
    getstatus_fixed = 0
    exit_reason = 'timeout'
    line_count = 0

    for raw in lines:
        # ヘッダのタイムスタンプを確認
        hm = RE_HEADER.match(raw)
        if hm and start_time is None:
            start_time = hm.group(1)
            continue

        m = RE_LINE.match(raw)
        if not m:
            continue
        tag, msg = m.group(1).strip(), m.group(2)
        line_count += 1

        # HLSM 状態遷移 (HLSM タグの行のみ)
        if 'HLSM' in tag:
            hm = RE_HLSM.search(msg)
            if hm:
                st = int(hm.group(1))
                if not hlsm_states or hlsm_states[-1] != st:
                    hlsm_states.append(st)

        # エラー
        if RE_ERR.search(msg):
            errors.append(msg[:80])

        # PCPA リクエスト
        for rm in RE_PCPA_REQ.finditer(msg):
            pcpa_reqs[rm.group(1)] += 1

        # ブート / アトラクト
        if RE_BOOT.search(msg):
            boot_done = True

        # get_status fix の発火回数
        if RE_GETSTATUS_FIX.search(msg):
            getstatus_fixed += 1

        # 終了シグナル
        if 'TerminateProcess' in msg or 'CRASH' in msg:
            exit_reason = 'crash'
        elif 'DETACH' in tag or 'duration' in msg.lower():
            exit_reason = 'timeout'

    duration = f'{line_count}lines'
    if start_time:
        duration = f'started {start_time}'

    # HLSM の経路を整形
    if hlsm_states:
        counts = []
        i = 0
        while i < len(hlsm_states):
            st = hlsm_states[i]
            cnt = 1
            while i+cnt < len(hlsm_states) and hlsm_states[i+cnt] == st:
                cnt += 1
            counts.append(f'{st}×{cnt}' if cnt > 2 else str(st))
            i += cnt
        hlsm_str = '->'.join(counts)
        last = hlsm_states[-1]
        if counts and counts[-1].startswith(str(last)) and '×' in counts[-1]:
            hlsm_str += f' (stuck@{last})'
    else:
        hlsm_str = 'none'

    # PCPA を整形
    top_reqs = sorted(pcpa_reqs.items(), key=lambda x: -x[1])[:6]
    pcpa_str = '  '.join(f'{k}×{v}' for k, v in top_reqs) or 'none'

    # 次のアクションのヒント
    if boot_done:
        next_hint = 'ATTRACT reached!'
    elif 'get_status' in pcpa_reqs and pcpa_reqs['get_status'] > 10 and getstatus_fixed == 0:
        next_hint = 'get_status looping — GETSTATUS_FIX did not fire. Check recv flag.'
    elif 'get_status' in pcpa_reqs and getstatus_fixed > 0:
        next_hint = f'get_status fix fired {getstatus_fixed}x — check if SM advanced'
    elif errors:
        next_hint = f'ERR: {errors[0]}'
    else:
        next_hint = f'HLSM last={hlsm_states[-1] if hlsm_states else "?"} — check HLSM log'

    print(f'SESSION {name} | t={duration} | exit={exit_reason}')
    print(f'HLSM  : {hlsm_str}')
    print(f'PCPA  : {pcpa_str}')
    print(f'FIX   : GETSTATUS_FIX×{getstatus_fixed}')
    if errors:
        print(f'ERRORS: {errors[0]}')
    else:
        print(f'ERRORS: none')
    print(f'-> NEXT: {next_hint}')

if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else latest_log()
    summarize(path)
