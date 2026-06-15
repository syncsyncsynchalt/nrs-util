// subsys:      allnet
// persistence: persistent   // network_role=serve
// va: 0xA065C0
// ssot:        allnet/FACTS.md
// role:        alpbEx ALL.Net Plus Billing を offline idle(=5) に（alpbExGetExecStatus, Error 1000）。将来は実 billing へ(serve)

// ─────────────────────────────────────────────────────────────────────────────
// ALL.net Plus Billing (alpbEx) bypass — fixes Error 1000 (amlib errCode 0x15)
//
// Root cause (see BUGS.md [OPEN] Error 1000): the application scene shows
// "Error 1000 Unknown Application Error" because amlib master errCode 0x15 (21) is
// raised by FUN_007000c0 (alpbEx_billing_poll). That poll calls
//   alpbExGetExecStatus()  = FUN_00a065c0 (RVA 0x6065c0)
// which returns -2 ("Not initialized", per ..\src\alpb_ex.cpp) because there is no
// real ALL.Net billing server in our standalone bypass. The poll's switch has no
// case for -2 → default branch → DAT_016f5af0 = 0x15 → captured into the scene
// error descriptor (display 1000). region/dongle/platform/PCPA are all handled, but
// the ALL.net Plus Billing subsystem was not — this is the remaining gap.
//
// TeknoParrot avoids this by running offline/FreePlay with its network/billing layer
// stubbed so alpbEx never errors (docs/teknoparrot.md). We reproduce that observable
// behavior: force alpbExGetExecStatus to report status 5.
//
// Why 5? It is a no-op "transitional/idle" status across ALL THREE callers:
//   - FUN_007000c0  (poll):            case 5 → break (no accounting, no error)
//   - FUN_00700380  (credit executor): 4<5 && 5<7 → returns immediately, no credit
//                                        ops, no network (alpbExStartCredit/EndCredit
//                                        are never reached)
//   - FUN_00700c00  (debug BILLING INFO dump): value only printed, and that block is
//                                        gated by DAT_0210b612 (init-success) which is
//                                        0 here, so it is skipped entirely
// → no ALL.Net traffic, no accounting, and errCode 0x15 is never set.
//
// patchCode (PERSISTENT after Frida detach) per project convention. Full-function
// replacement returning a constant: cdecl/no-args, eax = retval.
//   B8 05 00 00 00   mov eax, 5
//   C3               ret
//
// NOTE: this forces billing to "idle/operating" forever. Correct for attract/
// standalone boot. If real coin/credit accounting is ever needed, this must be
// revisited (the game would never actually start/close a credit transaction).
// ─────────────────────────────────────────────────────────────────────────────
(function patchBilling() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'patchBilling: nrs.exe not found'); return; }

    var sva  = 0xA065C0;                       // alpbExGetExecStatus
    var code = [0xB8, 0x05, 0x00, 0x00, 0x00, 0xC3];  // mov eax,5 ; ret
    try {
        var target = va(sva);
        Memory.patchCode(target, code.length, function(c) {
            c.writeByteArray(code);
        });
        // Verify the write actually landed (QuickJS-safe pattern: re-read bytes).
        var ok = true;
        for (var i = 0; i < code.length; i++) {
            if (target.add(i).readU8() !== code[i]) { ok = false; break; }
        }
        logMsg('PATCH', 'alpbExGetExecStatus (0xA065C0) → mov eax,5; ret (patchCode persistent) verify=' + ok);
    } catch(e) { logMsg('WARN', 'patchBilling 0x6065c0 patchCode: ' + e); }
})();
