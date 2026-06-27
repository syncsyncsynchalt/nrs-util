// subsys:      app
// persistence: runtime   // network_role=local
// va: —
// ssot:        app/FACTS.md
// role:        ウィンドウモード化（フルスクリーン抑止と窓スタイル）。

// ウィンドウモード: ChangeDisplaySettings* をブロックし、ウィンドウから WS_POPUP を除去する
//
// TeknoParrot 相当: ChangeDisplaySettingsA + CreateWindowExA/W をフックし、フルスクリーンへの
// モード切替を防いで overlapped（ウィンドウ）スタイルを強制する。
// nrs.exe が使う D3D11 では ChangeDisplaySettings が発火しない場合があるため、CreateWindowExA/W
// フックがトップレベルウィンドウを必ずウィンドウモード（タイトルバー＋枠）で生成する。
// 引数レイアウトと WS_POPUP 観測は tools/runtime/frida_diag/window_create_trace.js で実機裏取り済み。
(function windowedMode() {
    ['ChangeDisplaySettingsA', 'ChangeDisplaySettingsW',
     'ChangeDisplaySettingsExA', 'ChangeDisplaySettingsExW'].forEach(function(fnName) {
        try {
            Interceptor.attach(Module.getGlobalExportByName(fnName), {
                onLeave: function(ret) {
                    logMsg('WINDOWED', fnName + ' -> DISP_CHANGE_SUCCESSFUL (blocked)');
                    ret.replace(0);
                }
            });
        } catch(e) {}
    });

    // CreateWindowEx(A/W) の dwStyle (x86 stdcall: args[3]) から WS_POPUP を外し、
    // WS_OVERLAPPEDWINDOW（タイトルバー＋枠＋リサイズ）を立てる。WS_EX_TOPMOST も除去して
    // 最前面固定を解く。これで窓が移動可能になる。
    var WS_POPUP            = 0x80000000;
    var WS_OVERLAPPEDWINDOW = 0x00CF0000;
    var WS_EX_TOPMOST       = 0x00000008;

    function forceWindowed(args, isW) {
        var exStyle = 0, style = 0;
        try { exStyle = args[0].toUInt32(); } catch(e) {}
        try { style   = args[3].toUInt32(); } catch(e) {}  // dwStyle = args[3]
        if (style & WS_POPUP) {
            args[3] = ptr((style & ~WS_POPUP) | WS_OVERLAPPEDWINDOW);
            args[0] = ptr(exStyle & ~WS_EX_TOPMOST);
            var title = '';
            try { title = isW ? args[2].readUtf16String() : args[2].readCString(); } catch(e) {}
            logMsg('WINDOWED', (isW ? 'CreateWindowExW' : 'CreateWindowExA') +
                   ' WS_POPUP removed -> OVERLAPPED  title="' + String(title).slice(0, 32) + '"');
        }
    }
    ['CreateWindowExA', 'CreateWindowExW'].forEach(function(fnName) {
        var isW = fnName.charAt(fnName.length - 1) === 'W';
        try {
            Interceptor.attach(Module.getGlobalExportByName(fnName), {
                onEnter: function(args) { forceWindowed(args, isW); }
            });
        } catch(e) {}
    });

    logMsg('WINDOWED', 'ChangeDisplaySettings + CreateWindowEx (WS_POPUP strip) hooks installed');
})();
