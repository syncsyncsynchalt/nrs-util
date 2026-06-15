// subsys:      amjvs
// persistence: runtime
// va: 0x16B7858 (initFlag), 0x16B785C (nodeCount), 0x16B7860 (node0; +0x640/+0x641 poll/valid), 0x16B8670 (errState), 0xCCF548 (ctx ptr)
// ssot:        FACTS.md §injectJvsInput Frida timer ; BUGS.md [FIXED] JVS watchdog setInterval
// role:        2s setInterval re-forcing JVS init/node/poll/err state every tick (game resets them) so amJvspAckSwInput keeps being polled. Frida timer → stops on detach (standalone blocker; future: replace with TeknoParrot_jvs pipe in amjvs/pipe/).
(function jvsWatchdog() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'JVS watchdog: nrs.exe not found'); return; }

    var VA_jvsInitFlag  = 0x16B7858;
    var VA_jvsNodeCount = 0x16B785C;  // node_count: game polls only if >0
    var VA_node0        = 0x16B7860;
    var VA_errState     = 0x16B8670;
    var VA_ctxGvar      = 0xCCF548;   // pointer to amJvs ctx

    var watchdogFires = 0;
    setInterval(function() {
        watchdogFires++;
        try {
            var prevInitFlg  = va(VA_jvsInitFlag).readU8();
            var prevNodeCnt  = va(VA_jvsNodeCount).readU32();
            var prevN640     = va(VA_node0).add(0x640).readU8();
            var prevErr      = va(VA_errState).readS32();
            // Always force: init flag, node count, poll state, node valid
            va(VA_jvsInitFlag).writeU8(1);
            va(VA_jvsNodeCount).writeU32(1);
            va(VA_node0).add(0x640).writeU8(1);
            va(VA_node0).add(0x641).writeU8(1);
            if (prevErr !== 0) {
                va(VA_errState).writeS32(0);
            }
            // Force JVS ctx only on first fire (ctx is heap; writing during reinit risks corruption)
            if (watchdogFires === 1) {
                try {
                    var gp = va(VA_ctxGvar);
                    var ctxAddr = gp.readU32();
                    if (ctxAddr) {
                        var ctx = ptr(ctxAddr);
                        ctx.writeU32(1);        // ctx[0] = initialized
                        ctx.add(4).writeU32(1); // ctx[4] = sense connected
                        ctx.add(8).writeU32(1); // ctx[8] = 1 node
                    }
                } catch(e) {}
            }
            if (watchdogFires === 1 || prevInitFlg === 0 || prevNodeCnt === 0 || prevN640 === 0 || prevErr !== 0) {
                logMsg('JVS_WATCHDOG', '#' + watchdogFires +
                       ' initFlag=' + prevInitFlg + '->' + 1 +
                       ' nodeCnt=' + prevNodeCnt + '->' + 1 +
                       ' n640=0x' + prevN640.toString(16) + '->1' +
                       ' err=' + prevErr + '->0');
            }
        } catch(e) { logMsg('JVS_WATCHDOG', 'err: ' + e); }
    }, 2000);
})();
