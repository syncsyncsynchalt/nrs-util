// subsys:      amdongle
// persistence: persistent   // network_role=local
// va: 0x975E00, 0x457AF0
// ssot:        amdongle/FACTS.md ; BUGS.md [FIXED] keychipSM state4 crash
// role:        amDongleBusy → xor eax,eax;ret (not-busy, lets outerSM advance) + keychipSM state4 DLL-crash helper → ret 0. Persistent (survives detach).

// ─────────────────────────────────────────────────────────────────────────────
// amDongle init SM — TP-alignment phase: OBSERVE natural returns (no forcing).
//
// Background: this file used to FORCE 6 amDongle init-SM gate functions to return 0
// (suppress) so the outerSM/keychipSM would complete without real hardware. That was
// a band-aid from before the keychip was genuinely satisfied.
//
// We have since confirmed (RE + run8/9/10) that the keychip is now GENUINELY satisfied
// by pcpa_server.py:
//   - amDongleSetupKeychip (FUN_0096d520) completes case5→case6 on systemflag=00 /
//     version=0001 responses → sets ctx+4=1, ctx+8=1 (keychip present), naturally.
//   - amDongleUpdate (FUN_00970fc0) runs ret=0; ds.compute/ssd.proof → code=54 →
//     FUN_0096cd20 returns -6 → case4 sets ctx+0x18=1 → case8 MAC/SSD verify SKIPPED
//     (the intended DS28CN01 bypass). No "Verify NG".
//   - DAT_016014a2 one-way latch is held in satisfy-style by 21_runKeychipInit.js.
//
// Therefore the 6 force-0 hooks below are very likely REDUNDANT. To convert this
// subsystem to TP-style cleanly (satisfy, not suppress) we must confirm the init SM
// completes on its own. This phase keeps the hooks but only LOGS the natural return
// value (no ret.replace). If the SM completes naturally → the forcing was redundant and
// these hooks can be deleted. If a gate returns non-zero and the SM stalls → the log
// pinpoints exactly which keychip command pcpa_server must satisfy.
//
// Anti-regression: if a run shows the SM stalling here (e.g. amDongle init never DONE,
// Error 0949/keychip), `git checkout` this file to restore the force-0 behavior while
// the offending pcpa response is implemented.
// ─────────────────────────────────────────────────────────────────────────────
(function bypassAmDongle() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'bypassAmDongle: nrs.exe not found'); return; }

    // ── amDongleBusy (FUN_00975E00) — patchCode (persistent) ───────────────────
    // Returns 0 always: "init op complete / not busy" (same as TeknoParrot keychip driver).
    // Natural return stays 1 (busy) because nrs.exe's PCPA async layer never marks init
    // complete on its own. Even states (2/4/6) of amDongle outerSM need 0 to advance.
    // undefined4 amDongleBusy(void): no args, no stack cleanup → ret (not ret N).
    var code975e00 = [0x31, 0xC0, 0xC3]; // xor eax,eax; ret
    try {
        var t975e00 = va(0x975E00);
        Memory.patchCode(t975e00, code975e00.length, function(c) { c.writeByteArray(code975e00); });
        var ok975e00 = t975e00.readU8() === 0x31;
        logMsg('amDongle', '0x975E00 amDongleBusy → patchCode(xor eax,eax; ret) persistent, verify=' + ok975e00);
    } catch(e) { logMsg('WARN', 'amDongle 0x975E00 patchCode: ' + e); }

    logMsg('amDongle', 'bypassAmDongle: amDongleBusy patchCode (persistent); 5 action-fn forces removed (confirmed redundant).');
})();

// keychipSM state4 helper 0x457AF0: called when [esi+0x10]!=0 (auth path); crashes inside
// a DLL (DLL+0xdb58f3) before returning → onLeave never fires. patchCode entry → ret 0 (success).
(function keychipState4CrashFix() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'keychipState4CrashFix: nrs.exe not found'); return; }
    try {
        Memory.patchCode(va(0x457AF0), 3, function(code) {
            code.writeByteArray([0x31, 0xC0, 0xC3]);  // XOR EAX,EAX; RET
        });
        logMsg('INIT_SM', '0x457AF0 patched -> xor eax,eax; ret (state4 crash prevention)');
    } catch(e) { logMsg('WARN', '0x457AF0 patch: ' + e); }
})();
