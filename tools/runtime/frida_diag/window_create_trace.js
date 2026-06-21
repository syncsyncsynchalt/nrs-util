
// ─────────────────────────────────────────────────────────────────────────────
// CreateWindowEx — 全生成をログ + WS_POPUP → WS_OVERLAPPEDWINDOW にパッチ。
//
// CreateWindowEx(A/W) の引数レイアウト (x86 stdcall):
//   args[0] = dwExStyle
//   args[1] = lpClassName
//   args[2] = lpWindowName (タイトル文字列)
//   args[3] = dwStyle          ← WS_POPUP はここ
//   args[4..7] = x, y, w, h
// ─────────────────────────────────────────────────────────────────────────────
(function hookAllWindowCreate() {
    var WS_POPUP            = 0x80000000;
    var WS_OVERLAPPEDWINDOW = 0x00CF0000;
    var WS_EX_TOPMOST       = 0x00000008;

    function patchWin(args, isW) {
        var exStyle = 0, style = 0, cls = '', title = '';
        try { exStyle = args[0].toUInt32(); } catch(e) {}
        try { style   = args[3].toUInt32(); } catch(e) {}  // dwStyle = args[3]
        if (isW) {
            try { cls   = args[1].readUtf16String(); } catch(e) {}
            try { title = args[2].readUtf16String(); } catch(e) {}
        } else {
            try { cls   = args[1].readCString(); } catch(e) {}
            try { title = args[2].readCString(); } catch(e) {}
        }
        var patched = '';
        if (style & WS_POPUP) {
            args[3] = ptr((style & ~WS_POPUP) | WS_OVERLAPPEDWINDOW);
            args[0] = ptr(exStyle & ~WS_EX_TOPMOST);
            patched = ' PATCHED->OVERLAPPED';
        }
        logMsg('WINDOW', (isW ? 'CreateWindowExW' : 'CreateWindowExA') +
               ' exStyle=0x' + exStyle.toString(16) + ' style=0x' + style.toString(16) +
               ' cls="' + cls.slice(0, 32) + '" title="' + title.slice(0, 32) + '"' + patched);
    }
    try {
        Interceptor.attach(Module.getGlobalExportByName('CreateWindowExA'), {
            onEnter: function(args) { patchWin(args, false); }
        });
    } catch(e) {}
    try {
        Interceptor.attach(Module.getGlobalExportByName('CreateWindowExW'), {
            onEnter: function(args) { patchWin(args, true); }
        });
    } catch(e) {}
    logMsg('INIT_WIN', 'CreateWindowEx hooks (all styles, args[3]=dwStyle fix) installed');
})();

// ─────────────────────────────────────────────────────────────────────────────
// 例外 / クラッシュ検出 — fault アドレスの module+offset を解決し、
// fuzzy backtrace をダンプして、トリガと無害な first-chance を区別する
// (D3D/shader-cache の例外が多い)。
// ─────────────────────────────────────────────────────────────────────────────
function _modOff(addr) {
    try {
        var m = Process.findModuleByAddress(addr);
        return m ? m.name + '+0x' + addr.sub(m.base).toString(16) : '0x' + addr.toString(16);
    } catch(e) { return '0x' + addr.toString(16); }
}
function _bt(ctx) {
    try {
        return Thread.backtrace(ctx, Backtracer.FUZZY).slice(0, 12).map(_modOff).join(' <- ');
    } catch(e) { return '(bt err: ' + e + ')'; }
}
Process.setExceptionHandler(function(details) {
    var mem = '';
    try {
        if (details.memory) mem = ' memOp=' + details.memory.operation +
                                   ' memAddr=0x' + details.memory.address.toString(16);
    } catch(e) {}
    logMsg('EXCEPTION', 'type=' + details.type +
           ' addr=' + _modOff(details.address) +
           ' pc=' + _modOff(details.context.pc) + mem +
           ' bt=[' + _bt(details.context) + ']');
    // 握り潰さず OS に処理させる
    return false;
});

// ── RaiseException / RtlRaiseException — アプリが投げる (SEH) 例外を捕捉 ──────
// dwExceptionCode + 発生元の呼び出し箇所を取得する (Process.setExceptionHandler は
// 'system' についてこれを出せない)。
//   void RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags,
//                       DWORD nNumberOfArguments, const ULONG_PTR* lpArguments)
['RaiseException', 'RtlRaiseException'].forEach(function(fn) {
    try {
        var addr = Module.getGlobalExportByName(fn);
        Interceptor.attach(addr, {
            onEnter: function(args) {
                var info;
                if (fn === 'RaiseException') {
                    var code  = args[0].toUInt32();
                    var flags = args[1].toUInt32();
                    info = 'code=0x' + code.toString(16) + ' flags=0x' + flags.toString(16);
                } else {
                    // RtlRaiseException(PEXCEPTION_RECORD): code は [rec+0]、flags は [rec+4]
                    var rec = args[0];
                    var code = '?', flags = '?';
                    try { code  = '0x' + rec.readU32().toString(16); } catch(e) {}
                    try { flags = '0x' + rec.add(4).readU32().toString(16); } catch(e) {}
                    info = 'recCode=' + code + ' recFlags=' + flags;
                }
                logMsg('RAISE', fn + ' ' + info + ' bt=[' + _bt(this.context) + ']');
            }
        });
        logMsg('INIT_RAISE', fn + ' hooked');
    } catch(e) { logMsg('WARN', fn + ' hook: ' + e); }
});

logMsg('INIT', 'All hooks installed (Frida 17.x). Monitoring...');