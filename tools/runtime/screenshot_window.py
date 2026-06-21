"""Win32 PrintWindow でウィンドウを PNG にキャプチャする（ctypes のみ、外部依存なし）。

使い方:
  python tools/runtime/screenshot_window.py [--pid N | --title SUBSTR] [--out PATH]

対象のトップレベルウィンドウ（プロセス id またはタイトル部分文字列で指定。
デフォルトは nrs.exe のゲームウィンドウ、タイトル "WGL"）を探し、
PrintWindow(PW_RENDERFULLCONTENT) で描画して隠れていても GPU/D3D 内容を
キャプチャし、PNG を書き出す。
"""
import ctypes, ctypes.wintypes as wt, struct, zlib, sys, argparse, os, datetime

user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32
kernel32 = ctypes.windll.kernel32

SRCCOPY = 0x00CC0020
PW_RENDERFULLCONTENT = 0x00000002
DIB_RGB_COLORS = 0

def find_window(pid=None, title_sub=None):
    found = []
    @ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    def cb(hwnd, lparam):
        if not user32.IsWindowVisible(hwnd):
            return True
        wpid = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(wpid))
        n = user32.GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(n + 1)
        user32.GetWindowTextW(hwnd, buf, n + 1)
        title = buf.value
        r = wt.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(r))
        w, h = r.right - r.left, r.bottom - r.top
        if w < 50 or h < 50:
            return True
        ok = True
        if pid is not None and wpid.value != pid:
            ok = False
        if title_sub is not None and title_sub.lower() not in (title or '').lower():
            ok = False
        if ok:
            found.append((hwnd, title, w, h))
        return True
    user32.EnumWindows(cb, 0)
    return found

def capture(hwnd, out_path):
    r = wt.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(r))
    w, h = r.right - r.left, r.bottom - r.top
    hdc = user32.GetWindowDC(hwnd)
    mdc = gdi32.CreateCompatibleDC(hdc)
    bmp = gdi32.CreateCompatibleBitmap(hdc, w, h)
    gdi32.SelectObject(mdc, bmp)
    ok = user32.PrintWindow(hwnd, mdc, PW_RENDERFULLCONTENT)
    if not ok:
        gdi32.BitBlt(mdc, 0, 0, w, h, hdc, 0, 0, SRCCOPY)

    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [("biSize", wt.DWORD), ("biWidth", wt.LONG), ("biHeight", wt.LONG),
                    ("biPlanes", wt.WORD), ("biBitCount", wt.WORD), ("biCompression", wt.DWORD),
                    ("biSizeImage", wt.DWORD), ("biXPelsPerMeter", wt.LONG),
                    ("biYPelsPerMeter", wt.LONG), ("biClrUsed", wt.DWORD), ("biClrImportant", wt.DWORD)]
    bi = BITMAPINFOHEADER()
    bi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bi.biWidth = w
    bi.biHeight = -h  # トップダウン
    bi.biPlanes = 1
    bi.biBitCount = 32
    bi.biCompression = 0
    buf = (ctypes.c_char * (w * h * 4))()
    gdi32.GetDIBits(mdc, bmp, 0, h, buf, ctypes.byref(bi), DIB_RGB_COLORS)

    # BGRA → RGB 行に変換し PNG filter byte 0 を付ける
    data = bytes(buf)
    raw = bytearray()
    for y in range(h):
        raw.append(0)
        base = y * w * 4
        for x in range(0, w * 4, 4):
            i = base + x
            raw.append(data[i + 2]); raw.append(data[i + 1]); raw.append(data[i])
    comp = zlib.compress(bytes(raw), 6)

    def chunk(typ, data):
        return struct.pack(">I", len(data)) + typ + data + struct.pack(">I", zlib.crc32(typ + data) & 0xffffffff)
    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", comp)
    png += chunk(b"IEND", b"")
    with open(out_path, "wb") as f:
        f.write(png)

    gdi32.DeleteObject(bmp); gdi32.DeleteDC(mdc); user32.ReleaseDC(hwnd, hdc)
    return w, h

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--title", default=None)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    pid, title = a.pid, a.title
    if pid is None and title is None:
        title = "WGL"  # nrs.exe のゲームウィンドウ
    wins = find_window(pid=pid, title_sub=title)
    if not wins:
        print(f"No window found (pid={pid} title={title})")
        sys.exit(1)
    hwnd, t, w, h = wins[0]
    out = a.out or os.path.join(os.path.dirname(__file__), "..", "..", "captures",
                                f"shot-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.png")
    out = os.path.abspath(out)
    cw, ch = capture(hwnd, out)
    print(f"Captured hwnd=0x{hwnd:x} title={t!r} {cw}x{ch} -> {out}")
