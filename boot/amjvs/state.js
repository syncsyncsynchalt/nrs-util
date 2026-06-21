// subsys:      amjvs
// persistence: persistent   // network_role=local
// va: 0x67AFA0, 0x987590, 0x9883D3, 0x16B7858, 0x16B785C, 0x16B7860, 0x16B8668, 0x16B7EA0, 0xCCF54C
// ssot:        amjvs/FACTS.md ; BUGS.md [FIXED] keychipSM state4 / JVS polling
// role:        JVS init/state forced + FUN_0067afa0/specCheck/amJvspAckSwInput-return patched so amJvspAckSwInput polling stays alive. Persistent (survives detach).

// ─────────────────────────────────────────────────────────────────────────────
// JVS bypass — patchCode (persistent) + startup state write
//
// Strategy:
//   1. Write JVS initial state directly at script load time (ASLR-safe via nrsBase)
//   2. patchCode FUN_0067afa0 (RVA 0x27afa0) → ret
//      Prevents: _memset(&jvs_initialized_flag, 0, 0xe20) + amJvspInit() fail path
//      (amJvspInit returns -4: no named pipe / COM device → errState=-101 without patch)
//
// Runtime steady state after patchCode:
//   - initFlag=1, nodeCnt=1 survive (pre-written, memset never runs)
//   - jvs_per_node_input: poll_state=1 → calls transact → fails → poll_state=0, ret=-1
//     → next frame: poll_state=0 → early return 0 → bVar1=false → errCnt=0 → errState=0
//   - jvs_per_node_output: poll_state=0 → calls specCheck; specCheck reads sub1Ptr[0];
//     sub1Ptr[0]=1 → passes naturally (or specCheck returns -3, caller ignores return)
//
// All hooks eliminated: FUN_0067afa0 + specCheck both patchCode (persistent)
// ─────────────────────────────────────────────────────────────────────────────
(function bypassJvs() {
    // ── Initial JVS state write ───────────────────────────────────────────────
    va(0x16B7858).writeU8(1);    // jvs_initialized_flag = 1
    va(0x16B785C).writeU32(1);   // jvs_node_count = 1
    va(0x16B7860).writeU32(1);   // node[0].id = 1  (= nodeCnt - 0, mirrors FUN_0067afa0 loop)
    va(0x16B8668).writeU32(1);   // jvs_p1_device_id = 1  (= nodeCnt, mirrors FUN_0067afa0)
    va(0x16B7EA0).writeU8(1);    // node[0].poll_state = 1
    va(0x16B7EA1).writeU8(1);    // node[0].node_valid = 1
    logMsg('INIT_JVS', 'initial state written: initFlag=1 nodeCnt=1 nodeId=1 p1dev=1 poll=1');

    // sub1 ctx[0] = 1: specCheck guard (reads [[0xCCF54C]][0], returns -3 if 0)
    try {
        var sub1Ptr = va(0xCCF54C).readU32();
        if (sub1Ptr) {
            ptr(sub1Ptr).writeU32(1);
            logMsg('JVS_BYPASS', 'sub1 ctx[0]=1 (ptr=0x' + sub1Ptr.toString(16) + ')');
        } else {
            logMsg('JVS_BYPASS', 'sub1 ptr null at load — specCheck hook covers this');
        }
    } catch(e) { logMsg('WARN', 'bypassJvs sub1 write: ' + e); }

    // FUN_0067afa0 (JVS reinit) → ret: memset(initFlag,0,0xe20)+amJvspInit fail path を消す。void fn(void)。
    patch(0x67AFA0, [0xC3], 'FUN_0067afa0 JVS reinit -> ret');
    // specCheck(0x987590) stdcall 2args → xor eax,eax; ret 8（[[0xCCF54C]] guard を常に成功に。5B で原命令に収まる）。
    patch(0x987590, [0x31, 0xC0, 0xC2, 0x08, 0x00], 'specCheck -> xor eax,eax; ret 8');
    logMsg('INIT_JVS', 'bypassJvs done — amJvspInit/statusFn/nodeInfoFn/specCheck hooks eliminated');
})();

// amJvspAckSwInput GetReport(-11) failure path → return 0 (not -11) so errCnt stays 0.
// 0x9883D3: MOV EAX,EDI (8B C7) → XOR EAX,EAX (33 C0). Persistent; pairs with amjvs/input.js.
(function jvsAckReturnFix() {
    patch(0x9883D3, [0x33, 0xC0], 'amJvspAckSwInput -11 path -> xor eax,eax (errCnt stays 0)');
})();
