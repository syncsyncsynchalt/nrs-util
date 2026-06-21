
// ─────────────────────────────────────────────────────────────────────────────
// CreateWindowEx — log ALL creations + patch WS_POPUP → WS_OVERLAPPEDWINDOW.
//
// CreateWindowEx(A/W) argument layout (x86 stdcall):
//   args[0] = dwExStyle
//   args[1] = lpClassName
//   args[2] = lpWindowName (title string)
//   args[3] = dwStyle          ← WS_POPUP lives here
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
// Exception / crash detector — resolves module+offset of the fault address and
// dumps a fuzzy backtrace to distinguish a trigger from a benign first-chance
// (D3D/shader-cache exceptions are common).
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
    // Don't swallow — let the OS handle it
    return false;
});

// ── RaiseException / RtlRaiseException — catch app-raised (SEH) exceptions ──────
// Captures dwExceptionCode + raising call site (which Process.setExceptionHandler
// cannot expose for 'system').
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
                    // RtlRaiseException(PEXCEPTION_RECORD): code at [rec+0], flags at [rec+4]
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