// subsys:      devices
// persistence: persistent   // network_role=local
// va: 0x8B3B00, 0x8B3B40
// ssot:        devices/FACTS.md
// role:        Touch Panel presence: resp=1/err=0（dev 0x22, Error 5501, state3）。永続

// ─────────────────────────────────────────────────────────────────────────────
// Touch Panel — report PRESENT & HEALTHY (TP-equivalent satisfy).
//
// After USB I/O board is satisfied, the amlib init SM FUN_0089a010 advances to state-3
// ("Touch Panel" device, device-list type 0x22) and errors: errCode 0x16 (22) →
// errNo 5501 "Touch Panel Not Found" (desc+0x04 = _DAT_016f5af4 = 1, confirmed live).
//
// State-3 mirrors the IC-card state-2 pattern:
//   sub 2 : advance when (FUN_008b3b00()!=0 || FUN_008b3b40()!=0)   ← "device responded"
//   sub100: if FUN_008b3b40()!=0 → errCode 0x16 + error state 9     ← "touch error"
//   FUN_008b3b00 (RVA 0x4b3b00) = *(touchdev+0x18) status byte
//   FUN_008b3b40 (RVA 0x4b3b40) = 1 if *touchdev uninitialised, else *(touchdev+0x1c)!=0
// Healthy present touch panel ⇒
//   FUN_008b3b00 → 1  (responded → sub 2 advances)
//   FUN_008b3b40 → 0  (no touch error → sub100 passes → state 4)
// (micetools ser_maitouch.c is the touch-board reference; NRS does not use the
//  touch panel for play, so reporting healthy-present is sufficient for attract.)
//
// patchCode (persistent), same satisfy idiom as 23_emulateCardReader.
// ─────────────────────────────────────────────────────────────────────────────
(function emulateTouchPanel() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'emulateTouchPanel: nrs.exe not found'); return; }

    [
        { name: 'FUN_008b3b00 (touch status)',  va: 0x8B3B00, code: [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3] }, // mov eax,1; ret (responded)
        { name: 'FUN_008b3b40 (touch error)',   va: 0x8B3B40, code: [0x31, 0xC0, 0xC3] },                  // xor eax,eax; ret (no error)
    ].forEach(function(e) {
        try {
            var target = va(e.va);
            Memory.patchCode(target, e.code.length, function(c) { c.writeByteArray(e.code); });
            var ok = true;
            for (var i = 0; i < e.code.length; i++) {
                if (target.add(i).readU8() !== e.code[i]) { ok = false; break; }
            }
            logMsg('TOUCH', e.name + ' patched (' + e.code.length + 'b) verify=' + ok);
        } catch(ex) { logMsg('WARN', 'emulateTouchPanel patchCode ' + e.name + ': ' + ex); }
    });

    logMsg('INIT_TOUCH', 'Touch Panel: responded=1, error=0 (healthy present, TP-equivalent). state-3 should PASS.');
})();
