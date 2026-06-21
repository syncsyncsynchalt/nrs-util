// subsys:      mxkeychip
// persistence: runtime   // network_role=local
// va: 0x459109 (errCode=4 store FUN_00458fd0), 0x45A846 (errCode=4 store FUN_0045a7f0), 0x16014C4, 0x1601744, 0x1601989
// ssot:        mxkeychip/FACTS.md
// role:        Error 0903(region) を TeknoParrot 方式=チェック無力化で恒久解消（amlib region setter の
//              errCode=4 ストア2箇所を NOP）。PcbRegion=JAPAN(01) data-write は anti-tamper(FUN_0048f9c0)の
//              region-index 整合用に維持。NOP/DAT書込=永続(patchCode/data) / watchdog・診断=runtime(他コード safety-net)

// ─────────────────────────────────────────────────────────────────────────────
// Error 0903 (region) fix — TP-style: neutralize the region checks rather than
// supply real keychip cert data. Four layers, all persistent (patchCode / data):
//   1. NOP the jne jumps out of the outer keychip-region SM (0x986A66/74/92).
//   2. jl→jmp the isrelease SM error-display branches (0x97588A/5F/A1F).
//   3. NOP the amlib region setter's errCode=4 store (0x459109/0x45A846).
//   4. Force region=JAPAN via data write + watchdog clearing master errCode.
// ─────────────────────────────────────────────────────────────────────────────
(function patchRegionCheck() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'patchRegionCheck: nrs.exe not found'); return; }

    // NOP the jne jumps to Error 09xx from the outer keychip-region SM (kills the jump
    // regardless of what the check returns):
    //   0x986A66: 0F 85 E3 00 00 00  jne 0x986B4F  -> Error 0x381
    //   0x986A74: 0F 85 04 01 00 00  jne 0x986B7E  -> Error 0x387 (0903 Wrong Region)
    //   0x986A92: 0F 85 15 01 00 00  jne 0x986BAD  -> Error 0x38D
    var nop6 = [0x90,0x90,0x90,0x90,0x90,0x90];
    [
        { name: '0x986A66 jne->0x381',  va: 0x986A66, code: nop6 },
        { name: '0x986A74 jne->0x387',  va: 0x986A74, code: nop6 },
        { name: '0x986A92 jne->0x38D',  va: 0x986A92, code: nop6 },
    ].forEach(function(e) {
        try {
            Memory.patchCode(va(e.va), e.code.length, function(c) {
                c.writeByteArray(e.code);
            });
            logMsg('INIT_REGION', e.name + ' NOP6 patched');
        } catch(ex) { logMsg('WARN', 'patchRegionCheck NOP ' + e.name + ': ' + ex); }
    });
    logMsg('INIT_REGION', 'region jump NOP patches installed (3 jumps)');

    // ── isrelease SM sub-state error display bypass ─────────────────────
    // The isrelease SM (FUN_00975830 area) has 3 sub-state handlers that call error
    // display when [0x1286FEC] >= 1 after sync PCPA exchange:
    //   RVA 0x57588A: jl → Error 0x2EB (747, "Wrong Region" variant)
    //   RVA 0x57595F: jl → Error 0x31E (798, "Wrong Region" variant)
    //   RVA 0x575A1F: jl → Error 0x387 (903, "Wrong Region")
    // All three: cmp [0x1286FEC], 1; jl skip_error; push errCode; call 0x98A5F0
    // When pcpaSend/pcpaRecv hooks are not active, the real exchange sets [0x1286FEC]
    // to a non-zero result → Error 0903 displays (persistent Win32 window).
    // Change jl (7C 17) → jmp (EB 17) at each site (patchCode, persistent): jmp always
    // skips the error display regardless of [0x1286FEC] value.
    [
        { name: '0x97588A jl->jmp (err747)', va: 0x97588A },
        { name: '0x97595F jl->jmp (err798)', va: 0x97595F },
        { name: '0x975A1F jl->jmp (err903)', va: 0x975A1F },
    ].forEach(function(e) {
        try {
            Memory.patchCode(va(e.va), 2, function(c) {
                c.writeByteArray([0xEB, 0x17]); // jl → jmp: always skip error display
            });
            logMsg('INIT_REGION', e.name + ' patched (patchCode persistent)');
        } catch(ex) { logMsg('WARN', 'patchCode ' + e.name + ': ' + ex); }
    });

    // ── amlib init region setter の errCode=4 ストアを NOP 化（TP 方式＝チェック無力化）──
    // region ゲートは FUN_00458fd0 / FUN_0045a7f0 の2関数:
    //   if ((DAT_016014c4 & (DAT_016014a2 ? DAT_01601989 : 0) & 5) == 0)
    //       if (DAT_016f5af0 == 0) DAT_016f5af0 = 4;   // → on-screen Error 0903
    //   PcbRegion(DAT_016014c4) はバイナリ内に writer が無く（全 xref READ）、本構成では 0 のまま
    //   → ゲート FAIL 不可避。下の forceRegion で 01 を data-write するが、458fd0 がその着弾より前に
    //   走ると errCode 4 を display struct(DAT_016f5a80)へ snapshot して固着しうる（timing-fragile）。
    //   そこでストア `MOV [0x016f5af0],4`（C7 05 + addr4 + imm4 = 10B）自体を NOP 化する。呼び出し元
    //   (FUN_006c3730/FUN_00643de0) は戻り値を捨てるので、制御フロー・戻り値とも不変。patchCode=永続。
    //   0x459109: FUN_00458fd0 の errCode=4 ストア（早期に走る本命の latcher）
    //   0x45A846: FUN_0045a7f0 の errCode=4 ストア（同一 errCode・防御的に併せて潰す）
    var nop10 = [0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90];
    [
        { name: '0x459109 errCode=4 store (FUN_00458fd0)', va: 0x459109 },
        { name: '0x45A846 errCode=4 store (FUN_0045a7f0)', va: 0x45A846 },
    ].forEach(function(e) {
        try {
            var t = va(e.va);
            Memory.patchCode(t, 10, function(c) { c.writeByteArray(nop10); });
            var ok = true;
            for (var i = 0; i < 10; i++) if (t.add(i).readU8() !== 0x90) { ok = false; break; }
            logMsg('INIT_REGION', e.name + ' → NOP10 (errCode 4 latch killed, TP-style) verify=' + ok);
        } catch(ex) { logMsg('WARN', 'patchCode region setter ' + e.name + ': ' + ex); }
    });

    // Log-only: error display 0x98A5F0, with errCode + backtrace (reveals any call site
    // the patches above miss).
    try {
        Interceptor.attach(va(0x98A5F0), {
            onEnter: function(args) {
                var errCode = 0, bt = '';
                try { errCode = this.context.esp.add(4).readU32(); } catch(e) {}
                try {
                    bt = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0,5)
                             .map(function(f){ return '0x'+f.toString(16); }).join('<-');
                } catch(e) {}
                logMsg('ERR_DISPLAY', 'errCode=0x' + errCode.toString(16) + '(' + errCode + ') bt=' + bt);
            }
        });
        logMsg('INIT_REGION', '0x98A5F0 (error display) hooked for diag');
    } catch(e) { logMsg('WARN', 'hook 0x58A5F0: ' + e); }

    // ── forceRegion: data-write the region operands to JAPAN, + diag hooks ──────
    // Backstop for the NOP10 above: force the gate operands so the check also passes.
    // DAT_016014c4 (PcbRegion) has no writer in the binary → stays 0; a Frida data
    // write persists post-detach. Operands (static_VA):
    //   0x16014C4 game/PCB region · 0x1601744 cached region · 0x1601989 dongle region
    //   0x16014A2 gate            · 0x16F5AF0 master errCode
    function forceRegion() {
        try {
            va(0x16014C4).writeU8(0x01);   // DAT_016014c4 = JAPAN (game/PCB region)
            va(0x1601744).writeU8(0x01);   // DAT_01601744 = JAPAN (== check vs c4)
            va(0x1601989).writeU8(0x01);   // DAT_01601989 = JAPAN (dongle region).
            // Forced early too: it is normally populated from pcpa keychip.appboot.region
            // only AFTER keychip setup; in the early window dongle=0 → (c4 & 0 & 5)==0 →
            // errCode 4 → a STICKY "Error 0903 Wrong Region" SCENE that surfaces once the
            // overlying device scenes are cleared. Holding it 0x01 closes that gap.
        } catch(e) {}
    }
    forceRegion();   // immediate; the data write also persists post-detach
    function logRegion(tag) {
        try {
            var gameR   = va(0x16014C4).readU8();
            var dongleR = va(0x1601989).readU8();
            var gate    = va(0x16014A2).readU8();
            var eff     = gate ? dongleR : 0;
            var anded   = gameR & eff & 5;
            var err     = va(0x16F5AF0).readU32();
            logMsg('REGION_CHK', tag + ' game=0x' + gameR.toString(16) +
                   ' dongle=0x' + dongleR.toString(16) + ' gate=' + gate +
                   ' (game&eff&5)=0x' + anded.toString(16) +
                   ' -> ' + (anded !== 0 ? 'PASS' : 'FAIL') + ' errCode=' + err);
        } catch(e) { logMsg('WARN', 'logRegion ' + tag + ': ' + e); }
    }
    var diag458fd0 = 0;
    try {
        Interceptor.attach(va(0x458FD0), {
            onEnter: function() { forceRegion(); },
            onLeave: function() { if (diag458fd0++ < 3) logRegion('458fd0#' + diag458fd0); }
        });
        logMsg('INIT_REGION', '0x458FD0 (amlib region check 1) hooked: force+log');
    } catch(e) { logMsg('WARN', 'hook 0x458FD0: ' + e); }
    var diag45a7f0 = 0;
    try {
        Interceptor.attach(va(0x45A7F0), {
            onEnter: function() { forceRegion(); },
            onLeave: function() { if (diag45a7f0++ < 5) logRegion('45a7f0#' + diag45a7f0); }
        });
        logMsg('INIT_REGION', '0x45A7F0 (amlib region check 2) hooked: force+log');
    } catch(e) { logMsg('WARN', 'hook 0x45A7F0: ' + e); }

    // ── Watchdog: keep region forced + CLEAR master errCode DAT_016f5af0 ──────────
    // Safety-net for the errCode setters NOT neutralized above (0xa board-table /
    // 0x14 network etc.) + keeps forceRegion applied. DAT_016f5af0 is the amlib init
    // errCode (field of struct DAT_016f5a80, init FUN_006c35c0); init checks set it on
    // hw/platform absence:
    //   2/3/7=platform(amPlatformGetPlatformId!="AAL"), 4=region, 6=amStorage,
    //   10=board-table, 0xb/0xd/0xe/0x14-0x18=other device/config checks.
    // Several fail in the pure-Frida bypass (we return "RingEdge" not "AAL", no real
    // board table) → first failure latches a code → on-screen Error 09xx. The display
    // reads it via the struct pointer (not patchable by name), so clear it each tick
    // (data write persists post-detach). Log each distinct code.
    var lastErrCode = 0;
    setInterval(function() {
        forceRegion();
        try {
            var e = va(0x16F5AF0).readU32();
            if (e !== 0) {
                if (e !== lastErrCode) {
                    logMsg('ERRCODE', 'DAT_016f5af0 latched ' + e + ' (0x' + e.toString(16) + ') -> cleared');
                    lastErrCode = e;
                }
                va(0x16F5AF0).writeU32(0);   // clear all amlib init errors (hw-absence artifacts)
            }
        } catch(ex) {}
    }, 250);
})();
