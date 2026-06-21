// subsys:      amjvs
// persistence: persistent   // network_role=local
// va: 0x67AFA0, 0x987590, 0x9883D3, 0x16B7858, 0x16B785C, 0x16B7860, 0x16B8668, 0x16B7EA0, 0xCCF54C
// ssot:        amjvs/FACTS.md
// role:        JVS の init/状態を強制 + FUN_0067afa0/specCheck/amJvspAckSwInput の戻り値をパッチし amJvspAckSwInput のポーリングを生かし続ける。Persistent（detach 後も有効）。

// JVS バイパス: patchCode（persistent）と起動時の状態書込み
//
// 方針:
//   1. スクリプト load 時に JVS 初期状態を直接書込む（va() 経由で ASLR 非依存）
//   2. patchCode FUN_0067afa0 (0x67AFA0) → ret
//      抑止対象: _memset(&jvs_initialized_flag, 0, 0xe20) + amJvspInit() 失敗経路
//      （amJvspInit は -4 を返す。named pipe / COM デバイス無しのため、パッチ無しだと errState=-101）
//
// patchCode 後の定常状態:
//   - initFlag=1, nodeCnt=1 が残る（事前書込み済み・memset は走らない）
//   - jvs_per_node_input: poll_state=1 → transact 呼出 → 失敗 → poll_state=0, ret=-1
//     → 次フレーム: poll_state=0 → 即 return 0 → bVar1=false → errCnt=0 → errState=0
//   - jvs_per_node_output: poll_state=0 → specCheck 呼出; specCheck は sub1Ptr[0] を読む;
//     sub1Ptr[0]=1 → 自然に通過（または specCheck が -3 を返すが呼出元は戻り値を無視）
//
// FUN_0067afa0 と specCheck はどちらも patchCode（persistent）。
(function bypassJvs() {
    // JVS 初期状態の書込み
    va(0x16B7858).writeU8(1);    // jvs_initialized_flag = 1
    va(0x16B785C).writeU32(1);   // jvs_node_count = 1
    va(0x16B7860).writeU32(1);   // node[0].id = 1  (= nodeCnt - 0, FUN_0067afa0 のループと同じ)
    va(0x16B8668).writeU32(1);   // jvs_p1_device_id = 1  (= nodeCnt, FUN_0067afa0 と同じ)
    va(0x16B7EA0).writeU8(1);    // node[0].poll_state = 1
    va(0x16B7EA1).writeU8(1);    // node[0].node_valid = 1
    logMsg('INIT_JVS', 'initial state written: initFlag=1 nodeCnt=1 nodeId=1 p1dev=1 poll=1');

    // sub1 ctx[0] = 1: specCheck ガード（[[0xCCF54C]][0] を読み、0 なら -3 を返す）
    try {
        var sub1Ptr = va(0xCCF54C).readU32();
        if (sub1Ptr) {
            ptr(sub1Ptr).writeU32(1);
            logMsg('JVS_BYPASS', 'sub1 ctx[0]=1 (ptr=0x' + sub1Ptr.toString(16) + ')');
        } else {
            logMsg('JVS_BYPASS', 'sub1 ptr null at load — specCheck hook covers this'); // load 時 null は specCheck フックで救済
        }
    } catch(e) { logMsg('WARN', 'bypassJvs sub1 write: ' + e); }

    // FUN_0067afa0 (JVS reinit) → ret: memset(initFlag,0,0xe20)+amJvspInit fail path を消す。void fn(void)。
    patch(0x67AFA0, [0xC3], 'FUN_0067afa0 JVS reinit -> ret');
    // specCheck(0x987590) stdcall 2args → xor eax,eax; ret 8（[[0xCCF54C]] guard を常に成功に。5B で原命令に収まる）。
    patch(0x987590, [0x31, 0xC0, 0xC2, 0x08, 0x00], 'specCheck -> xor eax,eax; ret 8');
    logMsg('INIT_JVS', 'bypassJvs done — amJvspInit/statusFn/nodeInfoFn/specCheck handled by patchCode');
})();

// amJvspAckSwInput GetReport(-11) 失敗経路 → -11 ではなく 0 を返し errCnt を 0 に保つ。
// 0x9883D3: MOV EAX,EDI (8B C7) → XOR EAX,EAX (33 C0)。Persistent; JVS ポーリングを生かし続ける。
(function jvsAckReturnFix() {
    patch(0x9883D3, [0x33, 0xC0], 'amJvspAckSwInput -11 path -> xor eax,eax (errCnt stays 0)');
})();
