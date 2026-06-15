
// ─────────────────────────────────────────────────────────────────────────────
// amDongleUpdate diagnostic — the ongoing keychip auth that flickers a2 to 0.
//
// Finding (run8/9): the keychip context is fully populated early (ctx+4/+8/+0x10=1,
// a2=1), but later a2 → 0. Culprit: FUN_00970fc0 (amDongleUpdate, RVA 0x570fc0), the
// per-frame keychip re-validation called by FUN_00459460. It returns non-zero when
//   ctx+4==0 || ctx+8==0  → -0xc       (keychip data lost)
// and its case-8 MAC/SSD verify clears ctx+8=0 on mismatch ("Verify MAC/SSD NG!!!").
// The verify only runs when (ctx+0x4c==0 && ctx+0x18==0); if a keychip command
// (FUN_0096c6c0/c8d0/c920/dbc0/…) returns non-zero, ctx+0x4c!=0 → verify SKIPPED
// (the intended DS28CN01 bypass). So we need to see which case fails and whether the
// verify runs. This logs the SM each time ctx+8 or the return value changes.
// Logging only.
// ─────────────────────────────────────────────────────────────────────────────
(function diagDongleUpdate() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'diagDongleUpdate: nrs.exe not found'); return; }

    function C() {
        try { var c = nrsBase.add(0x8CF000).readPointer(); return c.isNull() ? null : c; }
        catch(e) { return null; }
    }
    function snap(c) {
        try {
            return 'sub=' + c.add(0x2c).readU32() + ' case=' + c.add(0x3c).readU32() +
                   ' type=0x' + c.add(0x5a).readU8().toString(16) +
                   ' f4=' + c.add(0x4).readU32() + ' f8=' + c.add(0x8).readU32() +
                   ' f10=' + c.add(0x10).readU32() +
                   ' err=' + c.add(0x44).readS32() +
                   ' f4c=' + c.add(0x4c).readU32() + ' f18=' + c.add(0x18).readU32() +
                   ' f1c=' + c.add(0x1c).readU32() + ' f20=' + c.add(0x20).readU32() +
                   ' f24=' + c.add(0x24).readU32();
        } catch(e) { return 'snap err: ' + e; }
    }

    var calls = 0, lastF8 = -1, lastRet = 999, lastErr = 999;
    try {
        Interceptor.attach(nrsBase.add(0x570FC0), {   // FUN_00970fc0 amDongleUpdate
            onLeave: function(ret) {
                calls++;
                var c = C();
                if (!c) return;
                var f8 = -1, err = 0;
                try { f8 = c.add(0x8).readU32(); err = c.add(0x44).readS32(); } catch(e) { return; }
                var r = ret.toInt32();
                // Log first 20 calls, and any time f8 / ret / err changes (the failure event).
                if (calls <= 20 || f8 !== lastF8 || r !== lastRet || err !== lastErr) {
                    logMsg('DONGLEUPD', '#' + calls + ' ret=' + r + ' [' + snap(c) + ']');
                    lastF8 = f8; lastRet = r; lastErr = err;
                }
            }
        });
        logMsg('INIT_DONGLEUPD', 'amDongleUpdate (FUN_00970fc0) diagnostic hooked');
    } catch(e) { logMsg('WARN', 'diagDongleUpdate attach 0x570FC0: ' + e); }

    // Also flag the exact "Verify NG" path by watching ctx+8 transition 1→0.
    // (Covered by the snap above; the case-8 verify is the only writer of ctx+8=0.)
})();
