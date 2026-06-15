// subsys:      devices
// persistence: persistent   // network_role=serve
// va: 0x4F6310, 0x4F6330
// ssot:        devices/FACTS.md
// role:        IC Card R/W presence: ready=1/err=0（dev 0x21, Error 5101, SYSTEM STARTUP state2）。永続

// ─────────────────────────────────────────────────────────────────────────────
// IC Card R/W (aime card reader) — report device HEALTHY (TP-equivalent satisfy).
//
// After keychip/region/billing are satisfied, boot advances to the amlib init SM
// FUN_0089a010 ("INITIALIZING"). Its state-2 step prints "  CHECKING IC CARD R/W ..."
// and probes the card-reader device-status word via:
//   FUN_004f6310 (RVA 0xf6310) → returns bit1 of *(cardrw_status)   (= *FUN_004f3e30()+? )
//   FUN_004f6330 (RVA 0xf6330) → returns bit4 of *(cardrw_status)   (bit4 = "R/W error")
// FUN_004f3e30 locates the device object (type 0x21/0x21 in the amlib device list)
// and returns &status. On a PC with no real Sega card reader, bit4 is set → state-2
// sets amlib errCode 0x17 (23) and jumps to error state 9 → the scene system shows
// "Error 5101 IC Card R/W Not Found" (sticky, every frame). Confirmed live in
// frida-20260612-034633: ERRCODE latched 23 (0x17) + ERR1000 errNo=5101.
//
// TeknoParrot provides an (emulated) aime/felica reader, so this probe reports a
// healthy reader (no R/W error) and the boot proceeds to attract. We reproduce that
// END STATE: the IC-card-R/W presence predicates report "no error" (healthy device),
// exactly what a present reader yields. This is satisfy (assert the device's healthy
// state, like 21_runKeychipInit holds keychip-present and 11 emulates RingEdge devices),
// not error-display suppression.
//
// CORRECT satisfy (verified via 24_diagAmlibInit, run bbxfxhtsq): the init SM
// FUN_0089a010 state-2 ("CHECKING IC CARD R/W") has two sub-steps:
//   sub 2 : advance ONLY when (FUN_004f6310()!=0 || FUN_004f6330()!=0)  ← "reader responded"
//   sub100: if FUN_004f6330()!=0 → errCode 0x17 + error state 9        ← "R/W error"
// So a HEALTHY present reader needs:
//   FUN_004f6310 (bit1 = ready/present) → 1   (so sub 2 advances: reader responded)
//   FUN_004f6330 (bit4 = R/W error)     → 0   (so sub100 sees no error → state 3)
// Returning 0 from BOTH (first attempt) hung the SM at state-2 sub-2 forever (the
// advance condition never became true) — that merely hid 5101 by never reaching sub100,
// and the downstream "USB Device 951" was a consequence of the init SM never completing.
// Returning 1/0 lets state 2 genuinely PASS, matching TP's present aime reader.
//
// patchCode (persistent). Card READ operations (player tapping a card) are a separate
// path not exercised in attract; full reader emulation only needed if real card I/O is.
// ─────────────────────────────────────────────────────────────────────────────
(function emulateCardReader() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'emulateCardReader: nrs.exe not found'); return; }

    [
        { name: 'FUN_004f6310 (cardrw ready bit1)',    va: 0x4F6310, code: [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3] }, // mov eax,1; ret (ready)
        { name: 'FUN_004f6330 (cardrw R/W-error bit4)', va: 0x4F6330, code: [0x31, 0xC0, 0xC3] },                  // xor eax,eax; ret (no error)
    ].forEach(function(e) {
        try {
            var target = va(e.va);
            Memory.patchCode(target, e.code.length, function(c) { c.writeByteArray(e.code); });
            var ok = true;
            for (var i = 0; i < e.code.length; i++) {
                if (target.add(i).readU8() !== e.code[i]) { ok = false; break; }
            }
            logMsg('CARDRW', e.name + ' patched (' + e.code.length + 'b) verify=' + ok);
        } catch(ex) { logMsg('WARN', 'emulateCardReader patchCode ' + e.name + ': ' + ex); }
    });

    logMsg('INIT_CARDRW', 'IC Card R/W: ready=1, R/W-error=0 (healthy present reader, TP-equivalent). state-2 should PASS.');
})();
