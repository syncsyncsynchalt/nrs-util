// subsys:      mxgfetcher
// persistence: runtime   // network_role=local
// va: 0x97718E, 0x9771CB, 0x457FE0, 0x9746C0, 0x974760, 0x9747A0, 0x975140, 0x6FF980, 0x6FF650, 0x9744F0, 0x975857, 0x98ADC0, 0x458271
// ssot:        mxgfetcher/FACTS.md ; BUGS.md [FIXED] get_status recv / Error 0903
// role:        get_status/amGfetcher init-flag force + HLSM state7→8 + parser/SM patchCodes + 0x98ADC0 recv-completion fix. Mixed; runtime Interceptors → reverts on detach. Pairs with amgfetcher/recv.js.

// ─────────────────────────────────────────────────────────────────────────────
// amGfetcher SM diagnostic + force
//
// Root cause: set_auth_params SM loops forever because:
//   1. [0x01287038] = amGfetcher "init done" flag; SM returns -6 if < 1
//   2. When >=1, sends request but return ESI must != EBX for success path
//
// Fix:
//   A) Force [0x01287038]=1 before the CMP at RVA 0x57718E
//   B) Hook SM function return (RVA 0x577176) to log return value
// ─────────────────────────────────────────────────────────────────────────────
(function patchAmGfetcher() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'patchAmGfetcher: nrs.exe not found'); return; }

    // 0x1287038 is the amGfetcher init flag (static VA). va() handles ASLR relocation.
    var initFlagAddr = va(0x1287038);
    logMsg('INIT_GFETCH', 'initFlagAddr=' + initFlagAddr + ' val=' + initFlagAddr.readU32());

    // Hook CMP [0x01287038], 1 at RVA 0x57718E — log + force the flag to 1.
    // NOTE: Frida can't intercept mid-function; skip if it fails.
    var smLogged = false;
    try {
        Interceptor.attach(va(0x97718E), {
            onEnter: function(args) {
                var val = initFlagAddr.readU32();
                var edi = this.context.edi.toInt32();
                var ebx = this.context.ebx.toInt32();
                if (!smLogged) {
                    logMsg('GFETCH_SM', '[initFlag]=' + val + ' EDI=' + edi + ' EBX=' + ebx);
                    smLogged = true;
                }
                initFlagAddr.writeU32(1);
            }
        });
        logMsg('INIT_GFETCH', 'RVA 0x57718E hooked (amGfetcher init flag force+log)');
    } catch(e) { logMsg('WARN', 'patchAmGfetcher CMP hook 0x57718E: ' + e); }

    // Hook the second CMP [0x01287038],1 at RVA 0x5771CB — same force
    var smLogged2 = false;
    try {
        Interceptor.attach(va(0x9771CB), {
            onEnter: function(args) {
                var val = initFlagAddr.readU32();
                var esi = this.context.esi.toInt32();
                var ebx = this.context.ebx.toInt32();
                if (!smLogged2) {
                    logMsg('GFETCH_SM2', '[initFlag]=' + val + ' ESI=' + esi + ' EBX=' + ebx);
                    smLogged2 = true;
                }
                initFlagAddr.writeU32(1);
            }
        });
        logMsg('INIT_GFETCH', 'RVA 0x5771CB hooked (amGfetcher 2nd flag force+log)');
    } catch(e) { logMsg('WARN', 'patchAmGfetcher 2nd CMP hook: ' + e); }

    logMsg('INIT_GFETCH', 'amGfetcher SM diagnostic+force installed');

    // Shared boot-complete flag: set when HLSM detects state-9→0 transition.
    // Used by FUN_6FF980 patch to switch from "boot" (return 1) to "attract" (return 0).
    var bootDone = 0;

    // ── Diagnostic: FUN_00457FE0 (high-level SM) ──────────────────────────────
    // Logs every state transition; also every 500 ticks for heartbeat.
    var hlsmCount = 0;
    var hlsmLastState = -1;
    try {
        Interceptor.attach(va(0x457FE0), {
            onEnter: function(args) {
                this.p1 = args[0];
                // State-machine forced transitions (applied before function body runs):
                //   param_1[0x14] = current state (prev tick value, first-switch not yet run)
                //   param_1[0x18] = next state (what first-switch will set 0x14 to this tick)
                // We target param_1[0x18] so we act on the state that WILL execute this tick.
                try {
                    var nextSt0 = this.p1.add(0x18).readU32();
                    var tcpBsy  = this.p1.add(3).readU8();
                    // Force state7 → state8: case=7 runs param_1[1]=1 side effects that
                    // crash when P-ras state isn't fully set up. Bypassing case=7 entirely
                    // (writing next=8 before first-switch runs) is the safe path.
                    // This Interceptor.attach reverts on detach — acceptable for now.
                    if (nextSt0 === 7 && tcpBsy === 0) {
                        this.p1.add(0x18).writeU32(8);
                    }
                    // State 4: do NOT force isrelease=1.
                    // Path A (FUN_004573E0=1 AND isrelease=1) → auth-exit (WRONG for game mode).
                    // Path B (FUN_004573E0=0 OR isrelease!=1) → state 5 → get_status → game mode.
                    // Without real keychip, FUN_004573E0 returns 0 naturally → path B is correct.
                } catch(e) {}
            },
            onLeave: function(ret) {
                hlsmCount++;
                try {
                    var state    = this.p1.add(0x14).readU32();
                    var nextSt   = this.p1.add(0x18).readU32();
                    var tcpBusy  = this.p1.add(3).readU8();
                    var statInt  = this.p1.add(0xb4).readS32();
                    var result   = this.p1.add(4).readS32();
                    var released = this.p1.add(2).readU8();   // param_1[2]: auth-done flag
                    var isrelRes = this.p1.add(0x24).readS32(); // param_1+0x24: isrelease result
                    var changed  = (state !== hlsmLastState);
                    // Detect state-9 success (next=0): boot sequence complete.
                    // FUN_006FF980 is patchCode'd to always return 1; NOP at 0x458271
                    // (applied in GETSTATUS_FIX) prevents state=0 from re-booting.
                    if (state === 9 && nextSt === 0 && !bootDone) {
                        bootDone = 1;
                        logMsg('HLSM', 'BOOT_DONE: state-9 set next=0, attract mode armed');
                    }
                    if (changed || state === 4 || state >= 6 || hlsmCount <= 10 || hlsmCount % 500 === 0) {
                        hlsmLastState = state;
                        logMsg('HLSM', '#' + hlsmCount + ' state=' + state + ' next=' + nextSt +
                               ' busy=' + tcpBusy + ' statusInt=' + statInt + ' result=' + result +
                               ' released=' + released + ' isrelRes=' + isrelRes +
                               (changed ? ' [TRANSITION]' : '') +
                               (bootDone ? ' [ATTRACT]' : ''));
                    }
                } catch(e) { logMsg('HLSM', 'read err: ' + e); }
            }
        });
        logMsg('INIT_DIAG', 'FUN_00457FE0 (high-level SM) hooked');
    } catch(e) { logMsg('WARN', 'FUN_00457FE0 hook: ' + e); }

    // ── patchCode: response parsers → always return 0 (PERSISTENT after Frida detach) ─
    // Root cause: these parsers call FUN_58AAE0 to find fields in the PCPA response buffer.
    // With our emulated responses, FUN_58AAE0 returns null → parsers return -5 (error).
    // Using patchCode (not Interceptor.replace) so the fix survives Frida detach.
    // Without this, after Frida detaches: parsers revert → pcpaSetSendPacket returns 0 →
    // [0x1286FEC] check → Error 0903 "Wrong Region" displayed in attract mode.
    //
    // Bytes: xor eax, eax (33 C0) + ret (C3) = 3 bytes → cdecl, return 0.
    var retZero3 = [0x33, 0xC0, 0xC3];
    [
        { name: 'FUN_009746C0 (resume parser)',       va: 0x9746C0 },
        { name: 'FUN_00974760 (isrelease case5)',     va: 0x974760 },
        { name: 'FUN_009747A0 (isrelease case10)',    va: 0x9747A0 },
        { name: 'FUN_00975140 (result= checker)',     va: 0x975140 },
    ].forEach(function(e) {
        try {
            Memory.patchCode(va(e.va), retZero3.length, function(c) {
                c.writeByteArray(retZero3);
            });
            logMsg('PATCH', e.name + ' → xor eax,eax; ret (patchCode, persistent)');
        } catch(ex) { logMsg('WARN', e.name + ' patchCode: ' + ex); }
    });

    // FUN_004573E0: NOT patched.
    // State4 path-A (FUN_004573E0=1 AND isrelease=1) → sets released=1 → foreground.next=1 → EXIT.
    // State4 path-B (FUN_004573E0=0 OR isrelease!=1) → state5 → get_status → game mode.
    // Without keychip, FUN_004573E0 returns 0 naturally → path-B → game mode. Correct!
    logMsg('PATCH', 'FUN_004573E0 not patched: natural 0 = state4 path-B = game mode');

    // ── patchCode: FUN_006FF980 (HLSM state-0 gate) → always return 1 (persistent) ─
    // hlsm_region_check() checks DAT_0210aed0/aed2/aed4 flags (0 without hardware).
    // Must return 1 for state=0 condition-A to fire on initial boot (ctx.next=1).
    // After initial boot: NOP at 0x458271 (applied in GETSTATUS_FIX, state=5→6) blocks
    // the ctx.next=1 write → state=0 stays in attract regardless of return value.
    // uint hlsm_region_check(void): no args → ret (C3). mov eax,1; ret = 6 bytes.
    try {
        Memory.patchCode(va(0x6FF980), 6, function(c) {
            c.writeByteArray([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]); // mov eax,1; ret
        });
        var ok980 = va(0x6FF980).readU8() === 0xB8;
        logMsg('PATCH', 'FUN_006FF980 → patchCode(mov eax,1; ret) persistent, verify=' + ok980);
    } catch(e) { logMsg('WARN', '0x2FF980 patchCode: ' + e); }

    // ── patchCode: FUN_006FF650 (state-7 advance check) → always return 1 (persistent) ─
    // state=7 case calls this after counter reaches DAT_00c91568 (float threshold,
    // >10,000 ticks ≈ minutes). Returns non-zero → advance to state=8.
    // param_1[0x12d]=0 naturally (hardware flags 0 → state=0 default skips write).
    // The HLSM onEnter direct-write (next=8 before case=7 runs) is the primary bypass:
    // state=6 → case=8 via the first-switch, skipping case=7 body so param_1[1] stays 0.
    // This patchCode covers the path where the counter naturally expires post-detach.
    // uint fn(void): no args → ret (C3). mov eax,1; ret = 6 bytes.
    try {
        Memory.patchCode(va(0x6FF650), 6, function(c) {
            c.writeByteArray([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]); // mov eax,1; ret
        });
        var ok650 = va(0x6FF650).readU8() === 0xB8;
        logMsg('PATCH', 'FUN_006FF650 → patchCode(mov eax,1; ret) persistent, verify=' + ok650);
    } catch(e) { logMsg('WARN', '0x2FF650 patchCode: ' + e); }

    // ── Diagnostic: FUN_00974B00 (get_status result parser) ───────────────────
    var diag974b00 = 0;
    try {
        Interceptor.attach(va(0x974B00), {
            onLeave: function(ret) {
                diag974b00++;
                if (diag974b00 <= 5 || diag974b00 % 200 === 0)
                    logMsg('DIAG_974B00', '#' + diag974b00 + ' ret=' + ret.toInt32());
            }
        });
        logMsg('INIT_DIAG', '0x974B00 hooked');
    } catch(e) { logMsg('WARN', '0x974B00: ' + e); }

    // ── Diagnostic: FUN_00974820 (status string→int) ──────────────────────────
    var diag974820 = 0;
    try {
        Interceptor.attach(va(0x974820), {
            onLeave: function(ret) {
                diag974820++;
                if (diag974820 <= 10 || diag974820 % 200 === 0)
                    logMsg('DIAG_974820', '#' + diag974820 + ' statusInt=' + ret.toInt32());
            }
        });
        logMsg('INIT_DIAG', '0x974820 hooked');
    } catch(e) { logMsg('WARN', '0x974820: ' + e); }

    // ── FIX: FUN_009744F0 (TCP SM done check) → patchCode (PERSISTENT, hang-safe) ─
    // Root cause: sub-state 8 cleanup closes the stream ([0x1286FF0]=0). The next
    // call to 9744F0 sees [0x1286FF0]=0 and returns -3 instead of [0x1287000]=0,
    // corrupting [ebp+4]=result to -3. When result=-3, the indirect table at
    // 0x45829C maps to error-counter path (0x45805F), not the advance path
    // (0x458043), so state=5 never advances to state=6. The same -3 is stored by
    // FUN_00458330 into esi[4]/esi[8] (error result) → Error 0903 path.
    // Done via patchCode (not Interceptor.replace) so it survives Frida detach.
    //
    // Hang-safe: post-detach the stream is closed ([0x1286FF0]==0) but [0x1287000]
    // may stay non-zero. A naive "return 1=pending while [0x1287000]!=0" would spin
    // 9744F0 forever → FUN_00458330 loop never exits → HLSM stall → watchdog
    // "Error 1000". So gate on the stream pointer first: if [0x1286FF0]==0 (stream
    // closed), return 0 (done) and reset sub-state. Native logic:
    //     if ([0x1286FF0] == 0)      { [0x1286FF4]=0; return 0; }  // stream closed → done
    //     if ([0x1287000] != 0)      { return 1; }                 // pending
    //     [0x1286FF4]=0; return 0;                                 // done → reset
    // ecx = &[0x1286FF0]; [ecx+0x10]=[0x1287000]; [ecx+4]=[0x1286FF4] (contiguous).
    // NOTE: no Interceptor.attach at this address (its trampoline restore on detach
    // would overwrite the patchCode). Compatible with GETSTATUS_FIX forcing [0x1287000]=0.
    // Hand-assembled (project convention: writeByteArray, not X86Writer). 30 bytes,
    // fits the 32B function frame:
    //   off  bytes            insn
    //    0   B9 <ff0Addr>     mov ecx, &[0x1286FF0]
    //    5   8B 01            mov eax, [ecx]        ; stream ptr
    //    7   85 C0            test eax, eax
    //    9   74 07            jz  +7 (->18 ret0_reset) ; stream closed → done
    //   11   8B 41 10         mov eax, [ecx+0x10]   ; r=[0x1287000]
    //   14   85 C0            test eax, eax
    //   16   75 06            jnz +6 (->24 pending)
    //   18   31 C0            xor eax, eax          ; (ret0_reset)
    //   20   89 41 04         mov [ecx+4], eax      ; [0x1286FF4] = 0
    //   23   C3               ret                   ; return 0 (done)
    //   24   B8 01 00 00 00   mov eax, 1            ; (pending)
    //   29   C3               ret                   ; return 1
    try {
        var ff0Addr = va(0x1286FF0).toUInt32();  // &[0x1286FF0]
        var le = function(a) { return [a & 0xff, (a>>>8) & 0xff, (a>>>16) & 0xff, (a>>>24) & 0xff]; };
        var code = [0xB9].concat(le(ff0Addr))
                         .concat([0x8B, 0x01, 0x85, 0xC0, 0x74, 0x07,
                                  0x8B, 0x41, 0x10, 0x85, 0xC0, 0x75, 0x06,
                                  0x31, 0xC0, 0x89, 0x41, 0x04, 0xC3,
                                  0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]);
        Memory.patchCode(va(0x9744F0), code.length, function(c) {
            c.writeByteArray(code);
        });
        logMsg('PATCH', '0x9744F0 patchCode (persistent hang-safe, ' + code.length + 'b): stream==0→ret0; else r!=0→ret1; r==0→reset+ret0');
    } catch(e) { logMsg('WARN', '0x9744F0 patchCode: ' + e); }

    // ── Diagnostic: FUN_00975A70 (get_status sender) ──────────────────────────
    var diag975a70 = 0;
    try {
        Interceptor.attach(va(0x975A70), {
            onLeave: function(ret) {
                diag975a70++;
                if (diag975a70 <= 5 || diag975a70 % 200 === 0)
                    logMsg('DIAG_975A70', '#' + diag975a70 + ' ret=' + ret.toInt32());
            }
        });
        logMsg('INIT_DIAG', '0x975A70 hooked');
    } catch(e) { logMsg('WARN', '0x975A70: ' + e); }

    // ── Diagnostic: FUN_00975320 (TCP sub-state 4 handler: response parser) ─────
    var diag975320 = 0;
    try {
        Interceptor.attach(va(0x975320), {
            onLeave: function(ret) {
                diag975320++;
                if (diag975320 <= 10 || diag975320 % 100 === 0)
                    logMsg('DIAG_975320', '#' + diag975320 + ' ret=' + ret.toInt32());
            }
        });
        logMsg('INIT_DIAG', '0x975320 (sub-state4 parser) hooked');
    } catch(e) { logMsg('WARN', '0x975320: ' + e); }

    // ── Diagnostic: FUN_00975700 (TCP SM step, called when busy=1) ──────────────
    // Called by outer HLSM every tick when tcpBusy=1 (after state-9 success).
    // If this isn't being called, the busy=1 path in the HLSM doesn't go here.
    var diag975700 = 0;
    try {
        Interceptor.attach(va(0x975700), {
            onLeave: function(ret) {
                diag975700++;
                var subState = va(0x1286FF4).readU32();
                if (diag975700 <= 10 || diag975700 % 500 === 0)
                    logMsg('DIAG_575700', '#' + diag975700 + ' subState=' + subState + ' ret=' + ret.toInt32());
            }
        });
        logMsg('INIT_DIAG', '0x975700 (TCP SM step) hooked');
    } catch(e) { logMsg('WARN', '0x975700: ' + e); }

    // ── Diagnostic: FUN_00975830 (state-9 pause request SM) ──────────────────
    // Called by state 9 handler with arg=1. Sends request=pause, checks FUN_974560.
    // Returns 0 = done (state 9 success: next=0, busy=1); non-zero = pending/error.
    // Also reads [0x1286FF0] (stream ptr) and [0x1286FF4] (stream busy flag).
    var diag975830 = 0;
    try {
        Interceptor.attach(va(0x975830), {
            onEnter: function(args) {
                this.arg0 = args[0].toInt32();
                try {
                    // 0x1286FF0 = Ghidra VA; RVA = 0x1286FF0 - 0x400000 = 0xE86FF0
                    var streamPtr  = va(0x1286FF0).readU32();
                    var streamBusy = va(0x1286FF4).readU32();
                    this.streamInfo = ' strPtr=0x' + streamPtr.toString(16) + ' strBusy=' + streamBusy;
                } catch(e) { this.streamInfo = ''; }
            },
            onLeave: function(ret) {
                diag975830++;
                if (diag975830 <= 10 || diag975830 % 200 === 0)
                    logMsg('DIAG_575830', '#' + diag975830 + ' arg=' + this.arg0 +
                           this.streamInfo + ' ret=' + ret.toInt32());
            }
        });
        logMsg('INIT_DIAG', '0x975830 (pause SM) hooked');
    } catch(e) { logMsg('WARN', '0x975830: ' + e); }

    // ── FIX: FUN_00975830 pause SM strBusy stuck ─────────────────────────────
    // Root cause: pre-HLSM init call to 975830(arg=0) does full sync pause exchange
    // and leaves [0x1286FF4]=1. State=9 handler calls 975830(arg=1) and sees
    // strBusy=1 → returns 1 (busy) forever.
    // Bytes at 0x975857: B8 01 00 00 00 (mov eax,1) C2 04 00 (ret 4) → busy path.
    // Fix: patch 0x975857 with EB 06 (jmp to 0x97585F) → bypass strBusy check,
    // always proceed to send path (0x98AB20 sync exchange). Send returns 0 →
    // state=9 handler sets next=0, tcpBusy=1 → attract mode.
    try {
        Memory.patchCode(va(0x975857), 2, function(c) {
            c.writeByteArray([0xEB, 0x06]); // jmp to 0x97585F (send path)
        });
        logMsg('PATCH', '0x975857 patched: bypass strBusy check in pause SM');
    } catch(e) { logMsg('WARN', '0x975857 patch: ' + e); }

    // ── Diagnostic: FUN_00974560 (TCP SM completion check, called from 575830) ─
    var diag974560 = 0;
    try {
        Interceptor.attach(va(0x974560), {
            onLeave: function(ret) {
                diag974560++;
                if (diag974560 <= 10 || diag974560 % 200 === 0)
                    logMsg('DIAG_574560', '#' + diag974560 + ' ret=' + ret.toInt32());
            }
        });
        logMsg('INIT_DIAG', '0x974560 (pause done-check) hooked');
    } catch(e) { logMsg('WARN', '0x974560: ' + e); }

    // ── FIX: 0x98ADC0 (PCPA recv poll) → force ret=1 after get_status recv ──
    // Root cause: port 40113 uses raw winsock recv(). 0x98DAB0 never returns 1
    // for the raw recv path → 0x98ADC0 always returns 0 → [stream+0x21C] stays 0
    // → 0x98B260 returns 0 → 0x574510 pending-path fires → SM re-sends forever.
    // Fix: after raw recv() captures a get_status response (flag set in recv hook),
    // force 0x98ADC0 to return 1 once → 0x98B260 writes [stream+0x21C]=1 → returns 1
    // → 0x574510 takes the done-path (je 0x574533) → SM advances cleanly.
    // Static analysis: 0x98ADC0 input=1 → jump table index 17 → 0x98ADD2 = ret 1.
    try {
        Interceptor.attach(va(0x98ADC0), {
            onLeave: function(r) {
                if (getStatusRecvDone) {
                    logMsg('GETSTATUS_FIX', '0x98ADC0 forced 0→1 (was ' + r.toInt32() + ')');
                    r.replace(1);
                    getStatusRecvDone = false;
                    // Force [0x1287000]=0 so replaced FUN_009744F0 returns 0 same tick.
                    try {
                        va(0x1287000).writeU32(0);  // [0x1287000] = 0
                        logMsg('GETSTATUS_FIX', '[0x1287000] forced 0 → next 9744F0 returns 0');
                    } catch(e) { logMsg('WARN', 'GETSTATUS_FIX [1287000]: ' + e); }
                    // NOTE: FUN_006FF980 NOT patched here (Interceptor.replace at same addr would
                    // overwrite patchCode on detach). Re-boot is prevented by NOP at 0x458271 below.
                    // After detach: FUN_006FF980 returns 0 naturally (hardware flags not set) so
                    // state=0 condition A is false anyway. NOP handles conditions B and C.
                    // Permanently NOP state=0 advance: patch ctx.next=1 write at 0x458271.
                    // Root cause: state=0 handler (at 0x458237) has 3 re-boot conditions:
                    //   A. FUN_006FF980()!=0 (fixed above)
                    //   B. DAT_0210B508!=0  ([0x210B508] set during init, persists after detach)
                    //   C. counter >= threshold (ctx+0x10 increments each tick; timed re-boot)
                    // All 3 converge at: 0x458271: 89 5D 18 (mov [ebp+0x18], ebx → ctx.next=1).
                    // NOP×3 prevents any condition from advancing state=0 → state=1 after detach.
                    // Applied here (state=5→6 transition) = after initial boot, before attract.
                    try {
                        Memory.patchCode(va(0x458271), 3, function(c) {
                            c.writeByteArray([0x90, 0x90, 0x90]); // NOP: block ctx.next=1
                        });
                        logMsg('GETSTATUS_FIX', '0x458271 NOP×3 → state=0 advance blocked (DAT_210B508 + counter-timeout fix)');
                    } catch(e) { logMsg('WARN', 'GETSTATUS_FIX patchCode 458271: ' + e); }
                }
            }
        });
        logMsg('PATCH', '0x98ADC0 onLeave hooked (get_status recv completion fix)');
    } catch(e) { logMsg('WARN', '0x98ADC0 hook: ' + e); }
})();
