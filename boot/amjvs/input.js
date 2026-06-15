// subsys:      amjvs
// persistence: runtime
// va: 0x988360 (amJvspAckSwInput), 0x9884F0 (amJvspGetCoinCount)
// ssot:        FACTS.md §injectJvsInput ; BUGS.md [NOTE] amJvspAckSwInput -11
// role:        Inject SERVICE/START via outPtr in amJvspAckSwInput onLeave + a coin via amJvspGetCoinCount; periodic JVS_DIAG. Interceptor-based → reverts on detach.
//
// Phase sequence: wait WAIT_BEFORE_SVC P1 calls → SERVICE (5 frames) → wait → START (5 frames).
// The persistent 0x5883D3 return-fix lives in amjvs/state.js; the JVS-state watchdog in amjvs/watchdog.js.
(function injectJvsInput() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'JVS input: nrs.exe not found'); return; }

    var VA_ackSwInput   = 0x988360;  // amJvspAckSwInput
    var VA_getCoinCount = 0x9884F0;  // amJvspGetCoinCount
    var VA_node0        = 0x16B7860; // node[0] base
    var VA_devId1       = 0x16B8668; // player1 device ID global
    var VA_devId2       = 0x16B866C; // player2 device ID global
    var VA_errState     = 0x16B8670; // JVS error state
    var VA_jvsInitFlag  = 0x16B7858; // read by JVS_DIAG below
    var VA_jvsNodeCount = 0x16B785C; // read by JVS_DIAG below

    // Phase: 0=diagnose+wait, 1=service, 2=pause, 3=start, 4=done
    var phase      = 0;
    var callCount  = 0;  // P1 (panel=0) calls only
    var totalCalls = 0;  // all panels
    var phaseCount = 0;
    var SERVICE_FRAMES = 5;
    var START_FRAMES   = 5;
    var WAIT_BEFORE_SVC  = 20;   // ~40s at 0.5Hz init rate
    var WAIT_BEFORE_START = 15;  // ~30s after service before START

    var coinBaseline = null;
    var coinCounter  = null;

    // --- amJvspAckSwInput hook ---
    try {
        Interceptor.attach(va(VA_ackSwInput), {
            onEnter: function(args) {
                this.panel  = args[2].toInt32();
                this.outPtr = args[4];
                this.buf    = args[0];  // report_buf = node+4
            },
            onLeave: function(ret) {
                var origRet = ret.toInt32();
                // -11 override is handled by patchCode at 0x5883D3 (amjvs/state.js);
                // origRet here should be 0 on GetReport failure.
                totalCalls++;
                if (totalCalls <= 10) {
                    logMsg('JVS_CALL', 'call#' + totalCalls + ' panel=0x' +
                           (this.panel >>> 0).toString(16) + ' origRet=' + origRet);
                }
                if (this.panel !== 0) return;  // only inject for P1 (panel index 0)
                callCount++;

                if (phase === 0 && callCount >= WAIT_BEFORE_SVC) {
                    phase = 1; phaseCount = 0;
                    try {
                        var node = va(VA_node0);
                        var nodeDevId = node.readU32();
                        var p1devId   = va(VA_devId1).readU32();
                        logMsg('JVS_INPUT', 'Phase 1 START: SERVICE button | node[0]=0x' +
                               nodeDevId.toString(16) + ' devId1=0x' + p1devId.toString(16));
                        if (nodeDevId !== p1devId) {
                            va(VA_devId1).writeU32(nodeDevId);
                            logMsg('JVS_INPUT', 'devId1 set to node[0]=0x' + nodeDevId.toString(16));
                        }
                    } catch(e) {}
                }
                if (phase === 1) {
                    phaseCount++;
                    if (this.outPtr && !this.outPtr.isNull()) {
                        try {
                            this.outPtr.writeU8(0x40);  // SERVICE bit (bit6)
                            if (phaseCount <= 3)
                                logMsg('JVS_INPUT', 'SERVICE injected (frame ' + phaseCount + ')');
                        } catch(e) {}
                    }
                    if (phaseCount >= SERVICE_FRAMES) {
                        phase = 2; phaseCount = 0;
                        logMsg('JVS_INPUT', 'Phase 2: pause before START');
                    }
                } else if (phase === 2) {
                    phaseCount++;
                    if (phaseCount >= WAIT_BEFORE_START) {
                        phase = 3; phaseCount = 0;
                        logMsg('JVS_INPUT', 'Phase 3: START button');
                    }
                } else if (phase === 3) {
                    phaseCount++;
                    if (this.outPtr && !this.outPtr.isNull()) {
                        try {
                            this.outPtr.writeU8(0x80);  // START bit (bit7)
                            if (phaseCount <= 3)
                                logMsg('JVS_INPUT', 'START injected (frame ' + phaseCount + ')');
                        } catch(e) {}
                    }
                    if (phaseCount >= START_FRAMES) {
                        phase = 4;
                        logMsg('JVS_INPUT', 'Phase 4: done. Monitor game state.');
                    }
                }

                if (callCount % 100 === 1 && this.buf && !this.buf.isNull()) {
                    try {
                        var b200 = hexBuf(this.buf.add(0x200), 8);
                        var b100 = hexBuf(this.buf.add(0x100), 4);
                        logMsg('JVS_INPUT', 'call=' + callCount + ' phase=' + phase +
                               ' buf+0x100=[' + b100 + '] buf+0x200=[' + b200 + ']');
                    } catch(e) {}
                }
            }
        });
        logMsg('JVS_INPUT', 'amJvspAckSwInput hook OK (va=0x988360)');
    } catch(e) { logMsg('WARN', 'amJvspAckSwInput hook: ' + e); }

    // --- amJvspGetCoinCount hook: inject 1 coin during SERVICE phase ---
    try {
        Interceptor.attach(va(VA_getCoinCount), {
            onEnter: function(args) {
                this.chute   = args[2].toInt32();
                this.outCoin = args[3];
            },
            onLeave: function(ret) {
                if (this.chute !== 1) return;  // only chute 1 (1-indexed)
                if (!this.outCoin || this.outCoin.isNull()) return;
                try {
                    var cur = this.outCoin.readU16();
                    if (coinBaseline === null) {
                        coinBaseline = cur;
                        coinCounter  = cur;
                        logMsg('JVS_INPUT', 'CoinCount baseline=' + coinBaseline);
                    }
                    if (phase >= 1 && phase <= 2 && coinCounter === coinBaseline) {
                        coinCounter = coinBaseline + 1;
                        this.outCoin.writeU16(coinCounter);
                        ret.replace(0);
                        logMsg('JVS_INPUT', 'Coin injected (baseline=' + coinBaseline + ' → ' + coinCounter + ')');
                    } else if (coinCounter !== null && coinCounter > coinBaseline) {
                        this.outCoin.writeU16(coinCounter);
                        ret.replace(0);
                    }
                } catch(e) {}
            }
        });
        logMsg('JVS_INPUT', 'amJvspGetCoinCount hook OK (va=0x9884F0)');
    } catch(e) { logMsg('WARN', 'amJvspGetCoinCount hook: ' + e); }

    // --- Periodic JVS_DIAG (every 2s) ---
    var diagTick = 0;
    setInterval(function() {
        diagTick++;
        try {
            var node    = va(VA_node0);
            var initFlg = va(VA_jvsInitFlag).readU8();
            var nodeCnt = va(VA_jvsNodeCount).readU32();
            var n640    = node.add(0x640).readU8();
            var n641    = node.add(0x641).readU8();
            var sw642   = node.add(0x642).readU8();
            var sw643   = node.add(0x643).readU8();
            var sw645   = node.add(0x645).readU8();
            var coin0   = node.add(0x648).readU16();
            var nodeId0 = node.readU32();
            var errSt   = va(VA_errState).readS32();
            logMsg('JVS_DIAG', 'tick=' + diagTick + ' phase=' + phase +
                   ' calls=' + callCount + '(p1)/' + totalCalls + '(all)' +
                   ' initFlag=' + initFlg + ' nodeCnt=' + nodeCnt +
                   ' n640=0x' + n640.toString(16) + ' n641=' + n641 +
                   ' nodeId=0x' + nodeId0.toString(16) +
                   ' sw642/643/645=0x' + sw642.toString(16) + '/0x' + sw643.toString(16) + '/0x' + sw645.toString(16) +
                   ' coin0=' + coin0 + ' err=' + errSt);
        } catch(e) { logMsg('JVS_DIAG', 'err: ' + e); }
    }, 2000);

    logMsg('JVS_INPUT', 'JVS input injection installed. Wait ' + WAIT_BEFORE_SVC +
           ' frames then SERVICE→START auto sequence begins.');
})();
