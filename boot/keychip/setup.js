// subsys:      keychip
// persistence: runtime   // network_role=local
// va: —
// ssot:        keychip/FACTS.md
// role:        keychipSM setup を駆動・補助（DAT_016014a2 ラッチ等を satisfy 維持）。runtime

// ─────────────────────────────────────────────────────────────────────────────
// TP-aligned fix: keep the keychip PRESENT (match TeknoParrot), no suppression.
//
// Findings (run8/9/10 + live reads):
//  - The keychip context IS genuinely authenticated: amDongleSetupKeychip populates
//    ctx+4 / ctx+8 / ctx+0x10 = 1 early, and amDongleUpdate (FUN_00970fc0) runs with
//    ret=0, ctx+8=1 stable, MAC/SSD verify correctly bypassed (no "Verify NG").
//  - BUT DAT_016014a2 (keychip-present flag) is a ONE-WAY LATCH: FUN_00459460 sets it
//    to 0 if amDongleUpdate returns non-zero even once (a transient during the boot
//    window), and there is no path that restores it to 1 afterwards. Once a2=0,
//    FUN_006f0a80 reads a2==0 and latches amlib errCode 1, which the scene system turns
//    into the sticky "Error 0949 Keychip Not Found" (and, with the descriptor emptied,
//    the on-screen "Error 1000"). Live: ctx+4/+8=1 (present) yet a2=0 (latched).
//
// TeknoParrot keeps the keychip present from boot, so this transient drop never
// happens and the error never fires. We replicate that END STATE faithfully: whenever
// the keychip is GENUINELY present (ctx+4 != 0 && ctx+8 != 0 — exactly what the
// canonical presence primitive FUN_0096c5d0 checks), hold DAT_016014a2 = 1.
//
// This is satisfy, not suppress: we only assert "present" when the keychip context is
// genuinely authenticated; we do NOT touch any errCode store or error-display code.
// Applied at FUN_006f0a80.onEnter — the exact consumer that latches errCode 1 — so the
// flag is correct *before* it is read, and the error is never raised in the first place.
//   FUN_006f0a80: ... CMP [0x016014a2],0 ; JZ latch_error ...   (RVA 0x2f0a92)
// Runs on the game main thread (this is a native game fn), every call, so it also
// overrides the one-way latch continuously.
// ─────────────────────────────────────────────────────────────────────────────
(function holdKeychipPresent() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'holdKeychipPresent: nrs.exe not found'); return; }

    var a2 = va(0x16014A2);          // DAT_016014a2 keychip-present flag
    var ctxPtr = va(0xCCF000);       // PTR_DAT_00ccf000 keychip context pointer

    function genuinePresent() {
        try {
            var c = ctxPtr.readPointer();
            if (c.isNull()) return false;
            // ctx+4 && ctx+8 — same test as FUN_0096c5d0 (keychip-present primitive).
            return c.add(0x4).readU32() !== 0 && c.add(0x8).readU32() !== 0;
        } catch(e) { return false; }
    }

    var forced = 0;
    try {
        Interceptor.attach(va(0x6F0A80), {   // FUN_006f0a80 (errCode-1 latcher)
            onEnter: function() {
                try {
                    if (genuinePresent() && a2.readU8() === 0) {
                        a2.writeU8(1);                 // reflect genuine keychip presence
                        forced++;
                        if (forced <= 5 || forced % 2000 === 0) {
                            logMsg('KCHOLD', 'keychip genuinely present (ctx+4/+8!=0); held DAT_016014a2=1 (#' + forced + ')');
                        }
                    }
                } catch(e) {}
            }
        });
        logMsg('INIT_KCHOLD', 'holdKeychipPresent armed at FUN_006f0a80 (a2=1 when keychip genuinely present)');
    } catch(e) { logMsg('WARN', 'holdKeychipPresent attach 0x2F0A80: ' + e); }
})();
