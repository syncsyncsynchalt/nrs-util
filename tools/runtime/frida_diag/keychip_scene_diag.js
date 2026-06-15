
// ─────────────────────────────────────────────────────────────────────────────
// DIAGNOSTIC: keychip 0949 scene — presence timing + scene-activation source.
//
// Screenshot proved the live screen shows "Error 0949 Keychip Not Found" even with all
// device/scene satisfies active and FUN_006f2730(scene renderer)/FUN_0098A5F0(ERR_DISPLAY)
// never firing. The keychip error is scene-type 0x66 → scene-ID 0x3b5 (=949), built by the
// autoscene builder FUN_00489130. keychip presence = FUN_0096c5d0() = (ctx+4 && ctx+8).
//
// This logs (a) FUN_0096c5d0 return over time — does keychip presence FLICKER to 0? and
// (b) the first few times the autoscene builds the keychip scene (param_2+0x10 == 0x66),
// with a backtrace → the scene-activation source. Logging only.
// ─────────────────────────────────────────────────────────────────────────────
(function diagKeychipScene() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'diagKeychipScene: nrs.exe not found'); return; }

    var ctxPtr = nrsBase.add(0x8CF000);   // PTR_DAT_00ccf000

    // (a) keychip presence FUN_0096c5d0 (RVA 0x56c5d0): log transitions of its result.
    var lastPres = -1, presCalls = 0;
    try {
        Interceptor.attach(nrsBase.add(0x56C5D0), {
            onLeave: function(ret) {
                presCalls++;
                var r = ret.toInt32();
                if (r !== lastPres) {
                    var c4 = -1, c8 = -1;
                    try { var c = ctxPtr.readPointer(); if (!c.isNull()) { c4 = c.add(4).readU32(); c8 = c.add(8).readU32(); } } catch(e) {}
                    logMsg('KCPRES', 'FUN_0096c5d0 present ' + lastPres + '→' + r + ' (ctx+4=' + c4 + ' ctx+8=' + c8 + ') #' + presCalls);
                    lastPres = r;
                }
            }
        });
        logMsg('INIT_KCPRES', 'keychip presence FUN_0096c5d0 transition tracer hooked');
    } catch(e) { logMsg('WARN', 'diagKeychipScene 0x56C5D0: ' + e); }

    // (b) autoscene builder FUN_00489130 (RVA 0x89130): when scene-type == 0x66 (keychip),
    //     log a backtrace (first few) to locate what activated the keychip error scene.
    var kcSceneLogged = 0;
    try {
        Interceptor.attach(nrsBase.add(0x89130), {
            onEnter: function(args) {
                try {
                    var p2 = args[1];
                    if (p2.isNull()) return;
                    var type = p2.add(0x10).readU32();
                    if (type === 0x66 && kcSceneLogged < 4) {
                        kcSceneLogged++;
                        var bt = '';
                        try {
                            bt = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0, 10)
                                 .map(function(f){ var m = Process.findModuleByAddress(f);
                                     return m ? m.name + '+0x' + f.sub(m.base).toString(16) : '0x'+f.toString(16); }).join(' <- ');
                        } catch(e) {}
                        logMsg('KCSCENE', 'autoscene type=0x66 (keychip 0949) #' + kcSceneLogged + ' bt=[' + bt + ']');
                    }
                } catch(e) {}
            }
        });
        logMsg('INIT_KCSCENE', 'autoscene FUN_00489130 keychip-scene(type 0x66) tracer hooked');
    } catch(e) { logMsg('WARN', 'diagKeychipScene 0x89130: ' + e); }
})();
