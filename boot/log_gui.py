"""nrs-util ブートログ GUI ビューア（Tkinter, 標準ライブラリのみ・依存なし）。

launch.py が --gui で使う。frida ブートログ + pcpa サーバログを1つの窓に時刻付きで集約表示する。
プレイ中は開いたまま。設計目標:
  - 人間に分かりやすい: ソース別カラー、件数ステータス、自動スクロール。
  - 必要なときに必要な表示: 部分一致フィルタ、I/O ノイズ(NtCreateFile)抑制、エラーのみ、検索、一時停止。
  - AI 解析に便利: 各行は構造化 entry。表示中だけを JSONL でエクスポート可（launch.py 側も全件 JSONL 保存）。

ログ entry は dict: {"ts": "HH:MM:SS.mmm", "src": "RINGEDGE", "lvl": "info|setup|pcpa|io|error|...", "msg": str}。
submit() はスレッド安全（内部 Queue 経由。Tk 更新は main スレッドの after ループで行う）。
"""
import queue
import json
import re

try:
    import tkinter as tk
    from tkinter import ttk, filedialog
    TK_OK = True
except Exception:
    TK_OK = False

# ソース→カテゴリ（色分けと絞り込みの単位）。
# 本物のエラーだけ拾う: amlib の error(-N) / 明示的 fail / exception / FRIDA_ERR。
# 生の NTSTATUS(0xc0000xxx) は NtCreateFile 等の正常な I/O プローブ失敗で多発するため error 扱いしない。
_ERR_RE = re.compile(r"error\(|\bfail(?:ed|ure)?\b|exception|FRIDA_ERR", re.I)


def level_of(src: str, msg: str) -> str:
    """src/msg から表示レベル（=カテゴリ）を決める。色とフィルタの両方に使う。"""
    s = (src or "").upper()
    if src == "NtCreateFile":
        return "io"          # I/O プローブ。status の NTSTATUS は正常ノイズなので error 扱いしない
    if "ERR" in s or _ERR_RE.search(msg or ""):
        return "error"
    if s.startswith("PCPA") or src in ("pcpaSend", "pcpaSet", "pcpaAdd", "pcpaGet", "recv"):
        return "pcpa"
    if s.startswith("HLSM"):
        return "hlsm"
    if s.startswith(("AMDBG", "DIAG")):
        return "amdbg"
    if s.startswith("LAUNCH"):
        return "launch"
    if s.startswith(("PATCH", "INIT", "RINGEDGE", "WINDOWED", "CONSOLE")):
        return "setup"
    return "info"


# ダークテーマのカテゴリ色
_CAT_COLOR = {
    "error":  "#ff5f5f",
    "pcpa":   "#5fb0ff",
    "hlsm":   "#ffd24a",
    "amdbg":  "#c08bff",
    "setup":  "#7bd66b",
    "io":     "#7a7a7a",
    "launch": "#00d6c4",
    "info":   "#d8d8d8",
}
_BG = "#13161b"
_BG2 = "#1c212a"
_FG = "#d8d8d8"


class LogGui:
    """1窓に全ログを集約する Tkinter ビューア。launch.py からは submit()/run()/close 用 on_close を使う。"""

    MAX_ENTRIES = 80000     # メモリ保持上限（古いものから捨てる）
    DISPLAY_CAP = 8000      # Text に保持する最大行数（UI 応答性のため上から間引く）

    def __init__(self, title="nrs-util boot log", on_close=None):
        self.q = queue.Queue()
        self.entries = []        # 全 entry（フィルタ再描画の元）
        self.on_close = on_close
        self.paused = False
        self._shown = 0
        self._errors = 0
        self._disp_lines = 0
        self._search_from = "1.0"

        self.root = tk.Tk()
        self.root.title(title)
        self.root.geometry("1180x720")
        self.root.configure(bg=_BG)
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._handle_close)
        self.root.after(50, self._drain)

    # ---- public (スレッド安全) ----
    def submit(self, entry: dict):
        self.q.put(entry)

    def run(self):
        self.root.mainloop()

    def close(self):
        try:
            self.root.after(0, self.root.destroy)
        except Exception:
            pass

    # ---- UI 構築 ----
    def _build_ui(self):
        bar = tk.Frame(self.root, bg=_BG2)
        bar.pack(side=tk.TOP, fill=tk.X)

        tk.Label(bar, text="Filter:", bg=_BG2, fg=_FG).pack(side=tk.LEFT, padx=(8, 2), pady=6)
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self._rerender())
        e = tk.Entry(bar, textvariable=self.filter_var, width=26, bg=_BG, fg=_FG,
                     insertbackground=_FG)
        e.pack(side=tk.LEFT, padx=2)

        self.hide_io = tk.BooleanVar(value=True)
        tk.Checkbutton(bar, text="I/O ノイズ非表示", variable=self.hide_io, bg=_BG2, fg=_FG,
                       selectcolor=_BG, activebackground=_BG2, activeforeground=_FG,
                       command=self._rerender).pack(side=tk.LEFT, padx=6)

        self.err_only = tk.BooleanVar(value=False)
        tk.Checkbutton(bar, text="エラーのみ", variable=self.err_only, bg=_BG2, fg=_FG,
                       selectcolor=_BG, activebackground=_BG2, activeforeground=_FG,
                       command=self._rerender).pack(side=tk.LEFT, padx=2)

        tk.Label(bar, text="検索:", bg=_BG2, fg=_FG).pack(side=tk.LEFT, padx=(10, 2))
        self.search_var = tk.StringVar()
        se = tk.Entry(bar, textvariable=self.search_var, width=18, bg=_BG, fg=_FG,
                      insertbackground=_FG)
        se.pack(side=tk.LEFT, padx=2)
        se.bind("<Return>", lambda _e: self._search_next())
        tk.Button(bar, text="次へ", command=self._search_next, bg=_BG2, fg=_FG).pack(side=tk.LEFT, padx=2)

        self.autoscroll = tk.BooleanVar(value=True)
        tk.Checkbutton(bar, text="自動スクロール", variable=self.autoscroll, bg=_BG2, fg=_FG,
                       selectcolor=_BG, activebackground=_BG2, activeforeground=_FG
                       ).pack(side=tk.LEFT, padx=6)

        self.pause_var = tk.BooleanVar(value=False)
        tk.Checkbutton(bar, text="一時停止", variable=self.pause_var, bg=_BG2, fg=_FG,
                       selectcolor=_BG, activebackground=_BG2, activeforeground=_FG,
                       command=self._toggle_pause).pack(side=tk.LEFT, padx=2)

        tk.Button(bar, text="クリア", command=self._clear, bg=_BG2, fg=_FG).pack(side=tk.LEFT, padx=6)
        tk.Button(bar, text="JSONL書出(表示分)", command=self._export, bg=_BG2, fg=_FG
                  ).pack(side=tk.LEFT, padx=2)

        # 本文
        wrap = tk.Frame(self.root, bg=_BG)
        wrap.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        self.text = tk.Text(wrap, bg=_BG, fg=_FG, insertbackground=_FG, wrap=tk.NONE,
                            font=("Consolas", 10), undo=False)
        ys = tk.Scrollbar(wrap, orient=tk.VERTICAL, command=self.text.yview)
        xs = tk.Scrollbar(self.root, orient=tk.HORIZONTAL, command=self.text.xview)
        self.text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        ys.pack(side=tk.RIGHT, fill=tk.Y)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        xs.pack(side=tk.TOP, fill=tk.X)
        for cat, col in _CAT_COLOR.items():
            self.text.tag_configure(cat, foreground=col)
        self.text.tag_configure("search_hit", background="#5a4a00")
        self.text.configure(state=tk.DISABLED)

        self.status = tk.Label(self.root, text="", bg=_BG2, fg=_FG, anchor="w")
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

    # ---- 取り込み/描画 ----
    def _drain(self):
        n = 0
        try:
            while n < 3000:
                self._ingest(self.q.get_nowait())
                n += 1
        except queue.Empty:
            pass
        if n:
            self._refresh_status()
        self.root.after(50, self._drain)

    def _ingest(self, e):
        self.entries.append(e)
        if len(self.entries) > self.MAX_ENTRIES:
            self.entries = self.entries[-self.MAX_ENTRIES:]
        if e.get("lvl") == "error":
            self._errors += 1
        if not self.paused and self._passes(e):
            self._append_line(e)

    def _passes(self, e) -> bool:
        if self.hide_io.get() and e.get("lvl") == "io":
            return False
        if self.err_only.get() and e.get("lvl") != "error":
            return False
        f = self.filter_var.get().strip().lower()
        if f:
            hay = (e.get("src", "") + " " + e.get("msg", "")).lower()
            if f not in hay:
                return False
        return True

    def _fmt(self, e) -> str:
        return f"[{e.get('ts','')}] [{e.get('src',''):24.24s}] {e.get('msg','')}"

    def _append_line(self, e):
        self.text.configure(state=tk.NORMAL)
        self.text.insert(tk.END, self._fmt(e) + "\n", e.get("lvl", "info"))
        self._disp_lines += 1
        self._shown += 1
        if self._disp_lines > self.DISPLAY_CAP:        # 上から間引いて応答性維持
            self.text.delete("1.0", f"{self._disp_lines - self.DISPLAY_CAP + 1}.0")
            self._disp_lines = self.DISPLAY_CAP
        self.text.configure(state=tk.DISABLED)
        if self.autoscroll.get():
            self.text.see(tk.END)

    def _rerender(self):
        self.text.configure(state=tk.NORMAL)
        self.text.delete("1.0", tk.END)
        self._disp_lines = 0
        self._shown = 0
        rows = [e for e in self.entries if self._passes(e)]
        if len(rows) > self.DISPLAY_CAP:
            rows = rows[-self.DISPLAY_CAP:]
        for e in rows:
            self.text.insert(tk.END, self._fmt(e) + "\n", e.get("lvl", "info"))
        self._disp_lines = len(rows)
        self._shown = len(rows)
        self.text.configure(state=tk.DISABLED)
        if self.autoscroll.get():
            self.text.see(tk.END)
        self._refresh_status()

    def _toggle_pause(self):
        self.paused = self.pause_var.get()
        if not self.paused:
            self._rerender()   # 再開時に取りこぼし分を反映

    def _clear(self):
        self.entries = []
        self._errors = 0
        self.text.configure(state=tk.NORMAL)
        self.text.delete("1.0", tk.END)
        self.text.configure(state=tk.DISABLED)
        self._disp_lines = 0
        self._shown = 0
        self._refresh_status()

    def _search_next(self):
        term = self.search_var.get()
        self.text.tag_remove("search_hit", "1.0", tk.END)
        if not term:
            return
        pos = self.text.search(term, self._search_from, stopindex=tk.END, nocase=True)
        if not pos:
            pos = self.text.search(term, "1.0", stopindex=tk.END, nocase=True)  # 折り返し
            if not pos:
                self.status.configure(text=f"検索: \"{term}\" は見つかりません")
                return
        end = f"{pos}+{len(term)}c"
        self.text.tag_add("search_hit", pos, end)
        self.text.see(pos)
        self._search_from = end

    def _export(self):
        path = filedialog.asksaveasfilename(
            title="表示中のログを JSONL で保存（AI 解析向け）",
            defaultextension=".jsonl", filetypes=[("JSON Lines", "*.jsonl"), ("All", "*.*")])
        if not path:
            return
        rows = [e for e in self.entries if self._passes(e)]
        try:
            with open(path, "w", encoding="utf-8") as f:
                for e in rows:
                    f.write(json.dumps(e, ensure_ascii=False) + "\n")
            self.status.configure(text=f"書出: {len(rows)} 行 -> {path}")
        except Exception as ex:
            self.status.configure(text=f"書出失敗: {ex}")

    def _refresh_status(self):
        self.status.configure(
            text=f" 総数 {len(self.entries)} / 表示 {self._shown} / エラー {self._errors}"
                 f"{'  [一時停止中]' if self.paused else ''}")

    def _handle_close(self):
        if self.on_close:
            try:
                self.on_close()
            except Exception:
                pass
        self.root.destroy()
