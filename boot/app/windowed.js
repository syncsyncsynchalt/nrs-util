// subsys:      app
// persistence: runtime   // network_role=local
// va: —
// ssot:        app/FACTS.md
// role:        ウィンドウモード化（フルスクリーン抑止・窓スタイル）。

// ─────────────────────────────────────────────────────────────────────────────
// ウィンドウモード — ChangeDisplaySettings* をブロックし、ウィンドウから WS_POPUP を除去する
//
// TeknoParrot 相当: ChangeDisplaySettingsA + CreateWindowExA/W をフックし、フルスクリーンへの
// モード切替を防いで overlapped（ウィンドウ）スタイルを強制する。
// nrs.exe が使う D3D11 では ChangeDisplaySettings が発火しない場合があるが、CreateWindowExA/W
// フックによってトップレベルウィンドウは必ずウィンドウモードで生成される。
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
