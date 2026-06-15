// subsys:      devices
// persistence: persistent   // network_role=local
// va: —
// ssot:        devices/FACTS.md
// role:        ストレージ presence を満たす（Game Program on Storage 系エラー回避）。

// ─────────────────────────────────────────────────────────────────────────────
// Storage / startup-mode — report game present (non-DVD mode) (TP-equivalent satisfy).
//
// After Network type is satisfied, the amlib init SM FUN_0089a010 reaches state-5 and
// errors: errCode 0xc (12) → errNo 913 "Game Program Not Found on Storage Device".
// Live diag: state 5→9, errCode 0xc.
//
// state-5 sub-1: cVar3 = FUN_004fda50(); if (cVar3 != 0) { param+0x1c = 0xc; → error }
//   FUN_004fda50 (RVA 0xfda50): return (DAT_01696ad8 == 1 || DAT_01696ad8 == 2)
//   DAT_01696ad8 = "startup mode" (FUN_0072bea0 logs "startup mode : <n>"); 1/2 = DVD/
//   storage-boot variants where the game program is expected on a separate storage device.
// We run nrs.exe directly (no DVD/HDD game image), so the DVD-mode storage probe fails.
// TeknoParrot launches with the game present, so this check passes. We reproduce that:
// FUN_004fda50 → 0 (= "not DVD-boot mode" / game-on-storage OK) so state-5 passes to state-6.
//
// FUN_004fda50 is a shared "is-DVD-boot-mode" predicate (7 call sites: FUN_00701800,
// FUN_0072af40, FUN_0089a010 state5, FUN_0089e240). Returning 0 everywhere = "non-DVD
// standalone", which is consistent with how we actually run. patchCode (cdecl/no-arg).
// If a DVD-mode-specific path is ever needed this must be revisited.
// ─────────────────────────────────────────────────────────────────────────────
(function emulateStorage() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'emulateStorage: nrs.exe not found'); return; }

    var sva  = 0x4FDA50;                 // FUN_004fda50 (is-DVD-boot-mode predicate)
    var code = [0x31, 0xC0, 0xC3];       // xor eax,eax ; ret  → not DVD mode / storage OK
    try {
        var target = va(sva);
        Memory.patchCode(target, code.length, function(c) { c.writeByteArray(code); });
        var ok = true;
        for (var i = 0; i < code.length; i++) if (target.add(i).readU8() !== code[i]) { ok = false; break; }
        logMsg('STORAGE', 'FUN_004fda50 → xor eax,eax; ret (non-DVD/storage OK) verify=' + ok);
    } catch(e) { logMsg('WARN', 'emulateStorage patchCode 0xfda50: ' + e); }

    logMsg('INIT_STORAGE', 'Storage: game-on-storage OK (TP-equivalent). errNo 913 should not arm.');
})();
