// subsys:      startup
// persistence: persistent   // network_role=local
// va: 0x72B3A0
// ssot:        startup/FACTS.md
// role:        EXTEND IMAGE install を done+skip に（FUN_0072b3a0, state5。暗号データは attract 不要）。永続

// ─────────────────────────────────────────────────────────────────────────────
// TEST: force EXTEND IMAGE install "done" — does boot proceed past state-5, or is the
// encrypted game-data a hard wall?
//
// Screenshot of the live boot shows the amlib SYSTEM STARTUP sequence:
//   CHECKING IC CARD R/W ... OK   (23)
//   CHECKING TOUCH PANEL ... OK   (26)
//   CHECKING NETWORK ... OK       (27)
//   CHECKING EXTEND IMAGE ... NG → INSTALLING EXTEND IMAGE ... WAITING → "Error 0949"
// So 0949 is the EXTEND IMAGE (game-data) install failing, not a keychip-presence problem
// (FUN_0096c5d0 presence is stably 1). State-5 sub-3 (FUN_0089a010):
//   uVar5 = FUN_0072b3a0();  if (3 < uVar5) { *(param+0x1c)=local_48; sub=100 }
//   FUN_0072b3a0 (RVA 0x32b3a0) maps install-SM state → 1..4; 4 = "done" (case 0xc),
//   and writes the result code to *ESI (caller's local_48; 0 = success → state-6).
// Confirmed: forcing install DONE advanced the boot past state-5 (the encrypted game-data
// is not needed for attract). PERSISTENT (patchCode): replace FUN_0072b3a0 with a stub that
// returns 4 ("done", case 0xc) and writes 0 ("success") to *ESI (the caller's local_48 =
// install result), guarded by ESI != 0 so other callers are safe:
//   31 C0        xor eax,eax        ; eax = 0
//   85 F6        test esi,esi
//   74 02        jz +2 (skip store)
//   89 06        mov [esi],eax      ; *ESI = 0 (success)
//   B0 04        mov al,4           ; return 4 (= "done", > 3 → state-5 advances)
//   C3           ret
// (FUN_0072b3a0 is __fastcall(param_1, param_2*) with extra output ptrs in ESI/EDI; the
//  state-5 caller passes ESI = &local_48 and reads it as the install result → must be 0.)
// ─────────────────────────────────────────────────────────────────────────────
(function emulateExtendImage() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'emulateExtendImage: nrs.exe not found'); return; }

    var code = [0x31,0xC0, 0x85,0xF6, 0x74,0x02, 0x89,0x06, 0xB0,0x04, 0xC3];  // see header
    try {
        var t = va(0x72B3A0);   // FUN_0072b3a0 (extend-image install status)
        Memory.patchCode(t, code.length, function(c) { c.writeByteArray(code); });
        var ok = true;
        for (var i = 0; i < code.length; i++) if (t.add(i).readU8() !== code[i]) { ok = false; break; }
        logMsg('EXTIMG', 'FUN_0072b3a0 → ret 4 + *ESI=0 (install done, patchCode persistent) verify=' + ok);
    } catch(e) { logMsg('WARN', 'emulateExtendImage patchCode 0x32b3a0: ' + e); }
    logMsg('INIT_EXTIMG', 'EXTEND IMAGE install reports done (state-5 passes; game-data not needed for attract).');
})();
