// subsys:      allnet
// persistence: persistent   // network_role=serve
// va: 0x72DCE0
// ssot:        allnet/FACTS.md
// role:        amlib_device_status_getter(0x72DCE0) を ready(2) 固定。network(state4)+allnet(state6) を両立
//              させ Error 8001/ALL.Net 待ちを解消（旧 return 0 は state4 で 8001 を誘発していた）。serve。

// ─────────────────────────────────────────────────────────────────────────────
// amlib_device_status_getter (FUN_0072dce0, RVA 0x32DCE0):
//   原実体 = `return device_manager[0x1d4 + idx*4]`（idx は EAX 渡し、各デバイスの状態 0/1/2/3）。
//   呼び出し元は amlib_init_sm_SYSTEM_STARTUP (FUN_0089a010) の **4箇所だけ**（xref 確定）:
//     - state-4 (network device): status **== 2**(ready) でないとエラーフラグ(param+0x1c=0x80/0x400)
//       → (uVar5 & 0x5f3)!=0 → DAT_016f5af0=0x14 → **Error 8001 "Network address error (DHCP)"**。
//     - state-6 (ALL.Net servers idx1..4): status **!= 1**(busy でない) なら前進。0/2/3 を受理。
//
// 旧実装は return 0（`xor eax,eax; ret`）で state-6 だけを満たしていたが、state-4 は `== 2` を
// 厳密に要求するため 0 では status!=2 → **8001 を誘発**していた（実機 screenshot で確認）。
// **return 2（ready）は state-4(==2) と state-6(!=1) の両方を同時に満たす唯一の安全値**。
// 呼び出し元が4箇所ともこの2 state なので固定 2 で全箇所OK（受理条件が 2 で衝突しないことを確認済）。
//
// Patch: `mov eax,2; ret` = B8 02 00 00 00 C3。EAX 渡し index・stack 引数なしなので ret(=C3)、stack 掃除不要。
// ─────────────────────────────────────────────────────────────────────────────
(function satisfyAllNet() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'satisfyAllNet: nrs.exe not found'); return; }

    var code = [0xB8, 0x02, 0x00, 0x00, 0x00, 0xC3];  // mov eax,2 ; ret  (ready; EAX-passed idx, no stack cleanup)
    try {
        var t = va(0x72DCE0);  // amlib_device_status_getter
        Memory.patchCode(t, code.length, function(c) { c.writeByteArray(code); });
        var ok = true;
        for (var i = 0; i < code.length; i++) if (t.add(i).readU8() !== code[i]) { ok = false; break; }
        logMsg('ALLNET', 'amlib_device_status_getter(0x72DCE0) → mov eax,2; ret (ready; state4 network + state6 allnet 両立) verify=' + ok);
    } catch(e) { logMsg('WARN', 'satisfyAllNet patchCode 0x32DCE0: ' + e); }
    logMsg('INIT_ALLNET', 'device status forced ready(2): network(state4) no errCode 0x14/8001, allnet(state6) advances.');
})();
