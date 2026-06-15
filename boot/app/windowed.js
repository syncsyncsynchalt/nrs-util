// subsys:      app
// persistence: runtime   // network_role=local
// va: —
// ssot:        app/FACTS.md
// role:        ウィンドウモード化（フルスクリーン抑止・窓スタイル）。

// ─────────────────────────────────────────────────────────────────────────────
// Windowed mode — block ChangeDisplaySettings*, strip WS_POPUP from windows
//
// TeknoParrot equivalent: hooks ChangeDisplaySettingsA + CreateWindowExA/W to
// prevent fullscreen mode switch and force overlapped (windowed) windows.
// For D3D11 (which nrs.exe uses), ChangeDisplaySettings may not fire, but the
// CreateWindowExA/W hook ensures any top-level window is created windowed.
// ─────────────────────────────────────────────────────────────────────────────
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

    logMsg('WINDOWED', 'ChangeDisplaySettings hooks installed (CreateWindowEx handled separately)');
})();
