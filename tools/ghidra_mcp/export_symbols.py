#!/usr/bin/env python3
"""DB のシンボル名を data/re_symbols.json へ一方向ダンプする DR バックアップ。

稼働中の Ghidra MCP サーバ (既定 http://127.0.0.1:8080) の /list_functions を読み、
FUN_/LAB_/SUB_ 等の自動生成名を除いた named function を addr->name で書き出す。

**手編集しないこと。** Ghidra DB が真実の source of truth で、これはそこからの生成物。
.gpr は巨大バイナリで git 非追跡のため、human-assigned な名前マッピングだけを git 追跡の形で保全する
（DB 破損時の災害復旧用）。名前の付与/変更は MCP で DB に対して行い、必要時にこれを再生成する。
"""
import json
import os
import sys
import urllib.request

HOST = os.environ.get("GHIDRA_MCP", "http://127.0.0.1:8080")
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))        # tools/ghidra_mcp -> repo root
OUT = os.path.join(REPO, "data", "re_symbols.json")

_AUTO_PREFIXES = ("FUN_", "LAB_", "SUB_", "DAT_", "thunk_FUN_", "switchD_", "caseD_")


def main():
    try:
        raw = urllib.request.urlopen(HOST + "/list_functions", timeout=30).read().decode("utf-8", "replace")
    except Exception as e:
        print(f"ERROR: cannot reach MCP server at {HOST}: {e}", file=sys.stderr)
        print("start it first: powershell -File tools/ghidra_mcp/start_headless.ps1", file=sys.stderr)
        return 1

    syms = {}
    for line in raw.splitlines():
        # 形式: "<name> at <hexaddr>"  (例: "amJvspInit at 00986720")
        if " at " not in line:
            continue
        name, addr = line.rsplit(" at ", 1)
        name, addr = name.strip(), addr.strip()
        if not name or not addr or name.startswith(_AUTO_PREFIXES):
            continue
        try:
            key = "0x%x" % int(addr, 16)
        except ValueError:
            continue
        syms[key] = name

    syms = dict(sorted(syms.items(), key=lambda kv: int(kv[0], 16)))
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(
            {
                "_comment": "GENERATED from the Ghidra DB by tools/ghidra_mcp/export_symbols.py. "
                            "DO NOT hand-edit: the DB is the source of truth. DR backup of named functions only.",
                "functions": syms,
            },
            f, ensure_ascii=False, indent=2,
        )
        f.write("\n")
    print(f"OK: wrote {len(syms)} named functions -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
