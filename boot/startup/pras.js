// subsys:      startup
// persistence: persistent   // network_role=serve
// va: 0x701280
// ssot:        startup/FACTS.md
// role:        P-ras billing-ready を true 強制（FUN_00701280, state7, FreePlay）。永続

// ─────────────────────────────────────────────────────────────────────────────
// TEST: P-ras init done — last SYSTEM STARTUP gate before boot completes.
//
// Screenshot shows boot at "INITIALIZING P-ras ..." (FUN_0089a010 state-7, after all
// device + ALL.Net checks). state-7 waits for FUN_00701280() != 0:
//   FUN_00701280 (RVA 0x301280): return (DAT_0210b611 != 0 || DAT_0210b610 == 0)
//   DAT_0210b610 = billing enabled (alpbExInitialize sets it 1);
//   DAT_0210b611 = billing "ready". With billing enabled (b610=1) and b611=0, P-ras waits.
// TeknoParrot runs FreePlay/offline (billing effectively off), so P-ras init completes.
// We reproduce that: force FUN_00701280 → true so state-7 advances to state-8 (done) and
// SYSTEM STARTUP finishes → boot proceeds to ATTRACT. PERSISTENT (patchCode): FUN_00701280
// is `bool(void)` returning AL, so `mov al,1; ret` (B0 01 C3) makes P-ras always-ready.
// Verified: this advanced FUN_0089a010 state7→8→10(DONE) → game booted to attract.
// ─────────────────────────────────────────────────────────────────────────────
(function satisfyPras() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'satisfyPras: nrs.exe not found'); return; }

    var code = [0xB0, 0x01, 0xC3];   // mov al,1 ; ret
    try {
        var t = va(0x701280);   // FUN_00701280 (P-ras / billing-ready)
        Memory.patchCode(t, code.length, function(c) { c.writeByteArray(code); });
        var ok = true;
        for (var i = 0; i < code.length; i++) if (t.add(i).readU8() !== code[i]) { ok = false; break; }
        logMsg('PRAS', 'FUN_00701280 → mov al,1; ret (P-ras always done, patchCode persistent) verify=' + ok);
    } catch(e) { logMsg('WARN', 'satisfyPras patchCode 0x301280: ' + e); }
    logMsg('INIT_PRAS', 'P-ras init forced done (FreePlay/offline). SYSTEM STARTUP completes → attract.');
})();
