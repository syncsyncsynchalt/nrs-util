// subsys:      mxkeychip
// persistence: runtime   // network_role=local
// va: 0x459109 (errCode=4 store FUN_00458fd0), 0x45A846 (errCode=4 store FUN_0045a7f0), 0x16014C4, 0x1601744, 0x1601989
// ssot:        mxkeychip/FACTS.md
// role:        Error 0903(region) を TeknoParrot 方式=チェック無力化で恒久解消（amlib region setter の
//              errCode=4 ストア2箇所を NOP）。PcbRegion=JAPAN(01) data-write は anti-tamper(FUN_0048f9c0)の
//              region-index 整合用に維持。NOP/DAT書込=永続(patchCode/data) / watchdog・診断=runtime(他コード safety-net)

// ─────────────────────────────────────────────────────────────────────────────
// Error 0903 fix: patchCode region check functions to return 0 (success).
//
// Root cause: after hw detection bypass, game reaches keychip region validation.
//   0x986A5F: call 0x587CA0 (check 1) → Error 0x381 if non-zero
//   0x986A6D: call 0x588810 (check 2) → Error 0x387 (0903 "Wrong Region") if non-zero
//   0x986A8B: call 0x589020 (check 3) → Error at 0x986BAD if non-zero
// Each function validates keychip region data vs expected region.
// Without real keychip, region cert data is invalid → all three fail.
// Fix: patchCode each to return 0 immediately.
// ─────────────────────────────────────────────────────────────────────────────
(function patchRegionCheck() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'patchRegionCheck: nrs.exe not found'); return; }

    // NOP out the jne/jnz jumps that lead to Error 09xx from the outer SM function.
    // More reliable than patching callee functions: directly kills the jump regardless
    // of what the check returns.
    //   0x986A66: 0F 85 E3 00 00 00  jne 0x986B4F  -> Error 0x381
    //   0x986A74: 0F 85 04 01 00 00  jne 0x986B7E  -> Error 0x387 (0903 Wrong Region)
    //   0x986A92: 0F 85 15 01 00 00  jne 0x986BAD  -> Error 0x38D
    //   0x986AD8: 74 C6              je  0x986AA0  -> re-poll loop (turn into unconditional fall)
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

    // ── FIX: isrelease SM sub-state error display bypass ─────────────────────
    // Root cause: isrelease SM (FUN_00975830 area) has 3 sub-state handlers that
    // call error display when [0x1286FEC] >= 1 after sync PCPA exchange:
    //   RVA 0x57588A: jl → Error 0x2EB (747, "Wrong Region" variant)
    //   RVA 0x57595F: jl → Error 0x31E (798, "Wrong Region" variant)
    //   RVA 0x575A1F: jl → Error 0x387 (903, "Wrong Region")
    // All three: cmp [0x1286FEC], 1; jl skip_error; push errCode; call 0x98A5F0
    // After Frida detach, pcpaSend/pcpaRecv hooks revert; real exchange sets
    // [0x1286FEC] to a non-zero result → Error 0903 displays (persistent Win32 window).
    // Fix: change jl (7C 17) → jmp (EB 17) at each site (patchCode, persistent).
    // jmp always skips the error display regardless of [0x1286FEC] value.
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

    // ── FIX (TeknoParrot 方式 = チェック無力化): amlib init region setter を直接潰す ──────────
    // 真因(Ghidra 確定): region ゲートは2関数 FUN_00458fd0 / FUN_0045a7f0 にあり、両方とも
    //   bVar = DAT_016014a2 ? DAT_01601989 : 0;            // dongleRegion (gate付き)
    //   if ((DAT_016014c4 & bVar & 5) == 0) { ...; if (DAT_016f5af0==0) DAT_016f5af0 = 4; }
    //   ＝ JAPAN(01) を通すには PcbRegion(DAT_016014c4) & dongleRegion(DAT_01601989) 両方に bit0 必要。
    //   dongleRegion は pcpa appboot.region=01 で満たせるが、PcbRegion(DAT_016014c4) は
    //   **バイナリ内に writer が無い**（全 xref READ）。本来 game.bat の mxGetHwInfo/基板コンフィグが
    //   供給する基板値で、その検査ごとバイパスした本構成では 0 のまま → ゲート FAIL は不可避。
    //   data-write で 01 を強制しても、FUN_00458fd0 が amlib init 初期に forceRegion 着弾前に走って
    //   errCode 4 を display struct(DAT_016f5a80)へ snapshot → watchdog が master をクリアしても画面に
    //   Error 0903 が固着する（timing-fragile）。
    // 解法: TeknoParrot と同じく「データを正す」のでなく「チェックを無力化」する。errCode 4 の
    //   `MOV dword ptr [0x016f5af0],4`（C7 05 + addr4 + imm4 = 10B）を NOP 化。両 setter とも先行の
    //   `if (DAT_016f5af0==0)` ガード直後の単純ストアで、呼び出し元 FUN_00643de0(45a7f0)/FUN_006c3730(458fd0)
    //   は戻り値を捨てる（xref/decompile 確認済）ため、ストアを消すだけで region error は二度と latch せず
    //   制御フロー・戻り値も不変。patchCode なので detach 後も永続。
    //   0x059109: FUN_00458fd0 の errCode=4 ストア（早期に走る本命の latcher）
    //   0x05A846: FUN_0045a7f0 の errCode=4 ストア（同一 errCode・防御的に併せて潰す）
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

    // Hook error display function 0x58A5F0 to log every call with error code + backtrace.
    // This tells us the REAL call site even if our patches miss it.
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
        logMsg('INIT_REGION', '0x58A5F0 (error display) hooked for diag');
    } catch(e) { logMsg('WARN', 'hook 0x58A5F0: ' + e); }

    // ── FIX + diag: amlib region check (FUN_00458fd0 / FUN_0045a7f0) ────────────
    // Region check: (DAT_016014c4 & dongleRegion & 5) == 0 → "Region error" →
    // DAT_016f5af0=4 (master errCode → on-screen Error 0903). NOT covered by the
    // NOP/jmp patches above. Diagnostics (20260611) proved the failing operand:
    //   game=DAT_016014c4=0x00  dongle=DAT_01601989=0x01(JAPAN, our pcpa region=01)
    //   gate=DAT_016014a2=1   → (0 & 1 & 5)=0 → FAIL regardless of dongle value.
    // DAT_016014c4 (PcbRegion; TeknoParrot=JAPAN) has NO writer in the binary — it
    // stays 0. Fix: force it to 0x01 (JAPAN). A Frida DATA write PERSISTS after
    // detach (only Interceptor hooks revert), so this is a permanent fix.
    //   DAT_016014c4 (game/PCB region) static 0x16014C4 → RVA 0x12014C4
    //   DAT_01601744 (cached region)   static 0x1601744 → RVA 0x1201744
    //   DAT_01601989 (dongle region)   static 0x1601989 → RVA 0x1201989
    //   DAT_016014a2 (gate)            static 0x16014A2 → RVA 0x12014A2
    //   DAT_016f5af0 (master errCode)  static 0x16F5AF0 → RVA 0x12F5AF0
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
        logMsg('INIT_REGION', '0x58FD0 (amlib region check 1) hooked: force+log');
    } catch(e) { logMsg('WARN', 'hook 0x58FD0: ' + e); }
    var diag45a7f0 = 0;
    try {
        Interceptor.attach(va(0x45A7F0), {
            onEnter: function() { forceRegion(); },
            onLeave: function() { if (diag45a7f0++ < 5) logRegion('45a7f0#' + diag45a7f0); }
        });
        logMsg('INIT_REGION', '0x5A7F0 (amlib region check 2) hooked: force+log');
    } catch(e) { logMsg('WARN', 'hook 0x5A7F0: ' + e); }

    // ── Watchdog: keep region forced + CLEAR amlib error state DAT_016f5af0 ──────
    // NOTE: region(errCode 4) は上の setter NOP（TP 方式）で恒久解消済。この watchdog はもはや
    //   region のためではなく、まだ check-neutralization 化していない他コード（0xa board-table /
    //   0x14 network 等）の master errCode を毎 tick クリアする safety-net + forceRegion 維持用。
    //   将来はこれら setter も個別に NOP 化して watchdog 依存を外すのが望ましい（FUN_0089a010 等は
    //   load-bearing なので要慎重）。
    // DAT_016f5af0 is the amlib init error code (field of struct DAT_016f5a80, init
    // by FUN_006c35c0). MANY init checks set it on hardware/platform absence:
    //   2/3/7=platform(amPlatformGetPlatformId!="AAL"), 4=region, 6=amStorage,
    //   10=board-table, 0xb/0xd/0xe/0x14-0x18=other device/config checks.
    // On real RingEdge all pass → stays 0. In our pure-Frida bypass several fail
    // (we return "RingEdge" not "AAL", no real board table, etc.), so the first
    // failing check latches a code → on-screen Error 09xx after detach.
    // The display reads the code via the DAT_016f5a80 struct pointer (not visible as
    // DAT_016f5af0 in decompiled C, so it can't be patched by name). Fix: clear the
    // code each tick (data write → persists post-detach). Log each distinct code.
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
