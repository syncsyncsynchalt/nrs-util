// subsys:      mxkeychip
// persistence: runtime   // network_role=local
// va: —
// ssot:        mxkeychip/FACTS.md
// role:        keychipSM setup を駆動・補助（DAT_016014a2 ラッチ等を satisfy 維持）。runtime

// ─────────────────────────────────────────────────────────────────────────────
// Hold DAT_016014a2 (keychip-present flag) = 1 whenever the keychip context is
// genuinely authenticated — matches TeknoParrot's "present from boot" end state.
//
// The flag is a ONE-WAY LATCH: FUN_00459460 clears it to 0 if amDongleUpdate
// (FUN_00970fc0) ever returns non-zero (a transient during the boot window), with no
// path back to 1. Once a2=0, FUN_006f0a80 reads a2==0 and latches amlib errCode 1 →
// sticky "Error 0949 Keychip Not Found" (and "Error 1000" with the descriptor empty).
// The context is in fact authenticated (ctx+4/+8/+0x10=1, amDongleUpdate ret=0,
// MAC/SSD verify pass) — only the latch is wrong.
//
// Satisfy, not suppress: at FUN_006f0a80.onEnter (the consumer that latches errCode 1)
// re-assert a2=1 when the keychip is genuinely present (ctx+4 && ctx+8 — the test
// FUN_0096c5d0 uses), so the flag is correct before it is read. Runs every call on the
// game main thread, so it also overrides the one-way latch continuously. No errCode
// store or error-display code is touched.
//   FUN_006f0a80: CMP [0x016014a2],0 ; JZ latch_error
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
