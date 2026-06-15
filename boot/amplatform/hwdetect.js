// subsys:      amplatform
// persistence: persistent   // network_role=local
// va: 0x891B20
// ssot:        amplatform/FACTS.md
// role:        HW type dispatcher 0x491B20 → mov eax,1; ret 4（SEH 例外回避、Error 0901）。永続

// ─────────────────────────────────────────────────────────────────────────────
// Error 0901 fix: patchCode hardware type dispatcher (0x491B20) to return 1.
//
// Root cause chain:
//   0x30292B -> 0x4927F0 (hw enum, polls types 0-7)
//            -> 0x492710 (per-type wrapper, installs SEH)
//            -> 0x491B20 (dispatcher: jmp table for hw types 0-7)
//            -> 0x5F0600 etc. (hw-specific fns, return -1 = no hardware)
//   When hw fn returns -1, 0x491B20 throws C++ exception
//   -> caught by SEH at 0x491AA9 -> Error 0901 "Wrong Platform"
//
// Fix: patchCode 0x491B20 -> mov eax,1; ret 4
//   0x492710 sees eax=1, takes je-to-xor-al-al path, returns al=0 (success).
//   0x4927F0 exits the loop for all 8 hw types cleanly. No exception thrown.
//   Caller at 0x30292B ignores 0x4927F0's return value, so no further effect.
// ─────────────────────────────────────────────────────────────────────────────
(function patchHwDetection() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'patchHwDetection: nrs.exe not found'); return; }

    // patchCode 0x491B20: return 1 immediately (stdcall, 1 arg on stack -> ret 4)
    // Replaces SEH prolog + hw jump table with a trivial success stub.
    try {
        var code = [
            0xB8, 0x01, 0x00, 0x00, 0x00,   // mov eax, 1
            0xC2, 0x04, 0x00,                // ret 4
        ];
        Memory.patchCode(va(0x891B20), code.length, function(c) {
            c.writeByteArray(code);
        });
        logMsg('INIT_HWDET', '0x491B20 patchCode(ret1): hw detection bypass installed');
    } catch(e) { logMsg('WARN', 'patchHwDetection 0x491B20: ' + e); }
})();
