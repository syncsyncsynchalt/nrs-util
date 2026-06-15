// subsys:      amnet
// persistence: persistent   // network_role=serve
// va: 0x6FF18A, 0x6FF1AC, 0x6FF1B3
// ssot:        amnet/FACTS.md
// role:        FUN_006ff140 の LAN フラグ初期化 0→1 強制（Error 8005 WAN 抑止、SYSTEM STARTUP state4）。永続

// ─────────────────────────────────────────────────────────────────────────────
// Network type — report correctly-configured LAN (TP-equivalent satisfy, PERSISTENT).
//
// amlib init SM FUN_0089a010 state-4 errors errCode 0x14 → errNo 8005
// "Network type error (WAN)". Live diag (24): devMgr+0x1ec=0, so the gate-mask bit is
// purely DAT_0210b50c==0 (and b50b). These flags are computed by FUN_006ff140 from three
// DNS-resolved address slots; b50c=1 only if two resolved IPs MATCH (LAN). Standalone has
// no matching WAN resolution → b50c=0 → WAN error. TeknoParrot presents a configured LAN.
//
// PERSISTENT fix (survives Frida detach — the earlier Interceptor version reverted):
// FUN_006ff140 does `DAT_0210b50a/b/c = 0;` then conditionally `= 1`. Patch the three
// "init to 0" immediates to 1, so the flags are LAN-OK unconditionally (the function only
// ever writes 1 afterwards, never 0). The original resolution/inet_ntoa logic is preserved.
//   006ff184  MOV byte [0x0210b50a],0  → imm @ RVA 0x2ff18a
//   006ff1a6  MOV byte [0x0210b50b],0  → imm @ RVA 0x2ff1ac
//   006ff1ad  MOV byte [0x0210b50c],0  → imm @ RVA 0x2ff1b3
// This is satisfy (assert the configured-LAN end state, like TP), not error suppression.
// ─────────────────────────────────────────────────────────────────────────────
(function emulateNetworkType() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'emulateNetworkType: nrs.exe not found'); return; }

    var sites = [
        { name: 'b50a init0→1', va: 0x6FF18A },
        { name: 'b50b init0→1', va: 0x6FF1AC },
        { name: 'b50c init0→1', va: 0x6FF1B3 },
    ];
    sites.forEach(function(s) {
        try {
            var t = va(s.va);
            var before = t.readU8();
            Memory.patchCode(t, 1, function(c) { c.writeByteArray([0x01]); });
            var after = t.readU8();
            logMsg('NETTYPE', s.name + ' (was ' + before + ' now ' + after + ') @va 0x' + s.va.toString(16) +
                   (before === 0 ? '' : ' [WARN: expected 0]'));
        } catch(e) { logMsg('WARN', 'emulateNetworkType patch ' + s.name + ': ' + e); }
    });
    logMsg('INIT_NETTYPE', 'FUN_006ff140 flag-init 0→1 (LAN-OK, patchCode persistent); errNo 8005 should not arm');
})();
