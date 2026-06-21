// subsys:      app
// persistence: runtime   // network_role=local
// va: —
// ssot:        app/FACTS.md
// role:        終了/exit 経路のフック。

// ─────────────────────────────────────────────────────────────────────────────
// ExitProcess / TerminateProcess — clean exit と強制 kill を検出する
// ─────────────────────────────────────────────────────────────────────────────
(function hookExit() {
    // ExitProcess で Frida のメッセージキューが落ちる前に、終了情報をファイルへ書き出す。
    // logMsg が失われても捕捉できるよう生の NativeFunction を使う。
    var _WriteFile = null, _CreateFileW = null, _CloseHandle = null;
    try {
        _WriteFile   = new NativeFunction(Module.getGlobalExportByName('WriteFile'),   'bool',    ['pointer','pointer','uint32','pointer','pointer']);
        _CreateFileW = new NativeFunction(Module.getGlobalExportByName('CreateFileW'), 'pointer', ['pointer','uint32','uint32','pointer','uint32','uint32','pointer']);
        _CloseHandle = new NativeFunction(Module.getGlobalExportByName('CloseHandle'), 'bool',    ['pointer']);
    } catch(e) {}

    // 出力パスは NRS_CAPTURES_DIR（launch.py が spawn 時に nrs.exe の環境変数へ注入）から取得する。
    // リポジトリの絶対パスをハードコードしないため。attach 時は %TEMP% にフォールバックする。
    var _exitFilePath = (function resolveExitPath() {
        function getEnv(name) {
            try {
                var GetEnv = new NativeFunction(Module.getGlobalExportByName('GetEnvironmentVariableW'),
                                                'uint32', ['pointer', 'pointer', 'uint32']);
                var buf = Memory.alloc(1024 * 2);
                var n = GetEnv(Memory.allocUtf16String(name), buf, 1024);
                return (n > 0 && n < 1024) ? buf.readUtf16String() : null;
            } catch (e) { return null; }
        }
        var dir = getEnv('NRS_CAPTURES_DIR') || getEnv('TEMP') || getEnv('TMP');
        return dir ? dir + '\\exit_debug.txt' : null;
    })();

    function writeExitFile(msg) {
        if (!_CreateFileW || !_WriteFile || !_exitFilePath) return;
        try {
            var pathPtr = Memory.allocUtf16String(_exitFilePath);
            var h = _CreateFileW(pathPtr, 0x40000000, 3, ptr(0), 4, 0x80, ptr(0));
            if (h.equals(ptr('0xFFFFFFFF'))) return;
            var buf = Memory.allocUtf8String(msg + '\\n');
            var written = Memory.alloc(4);
            _WriteFile(h, buf, msg.length + 1, written, ptr(0));
            if (_CloseHandle) _CloseHandle(h);
        } catch(e) {}
    }

    function logExit(name) {
        return function(args) {
            var code = args[0].toUInt32();
            var bt = '';
            try {
                bt = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0, 6)
                     .map(function(f) {
                         var mod = Process.findModuleByAddress(f);
                         return '0x' + f.toString(16) + '(' + (mod ? mod.name + '+0x' + (f.sub(mod.base)).toString(16) : '?') + ')';
                     }).join('<-');
            } catch(e) {}
            var msg = name + ' code=' + code + ' bt=' + bt;
            writeExitFile(msg);
            logMsg('EXIT', msg);
        };
    }
    try { hookFn('ExitProcess',       logExit('ExitProcess'),       null); } catch(e) {}
    try { hookFn('TerminateProcess',  logExit('TerminateProcess'),  null); } catch(e) {}
    try { hookFn('ExitThread',        logExit('ExitThread'),        null); } catch(e) {}
    // NtTerminateProcess: kernel32 の ExitProcess フックを迂回する ntdll 直接呼び出し
    try {
        var ntTermAddr = null;
        try { ntTermAddr = Module.getGlobalExportByName('NtTerminateProcess'); } catch(e) {}
        if (ntTermAddr && !ntTermAddr.isNull()) {
            Interceptor.attach(ntTermAddr, {
                onEnter: function(args) {
                    var code = args[1].toInt32();
                    var bt = '';
                    try {
                        bt = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0, 6)
                             .map(function(f) {
                                 var mod = Process.findModuleByAddress(f);
                                 return '0x' + f.toString(16) + '(' + (mod ? mod.name + '+0x' + (f.sub(mod.base)).toString(16) : '?') + ')';
                             }).join('<-');
                    } catch(e) {}
                    var msg = 'NtTerminateProcess code=' + code + ' bt=' + bt;
                    writeExitFile(msg);
                    logMsg('EXIT', msg);
                }
            });
        }
    } catch(e) {}
    logMsg('INIT_EXIT', 'ExitProcess/TerminateProcess/NtTerminateProcess hooks installed');
})();
