
// Keychip setup ステートマシン診断: amDongleSetupKeychip (FUN_0096d520)。観測のみ。
//
// PCPA client のステートマシン。keychip ctx が未設定だと errCode 1 → Error 0949 "Keychip Not Found"。
//   ctx = *PTR_DAT_00ccf000   (static 0xCCF000 / RVA 0x8CF000 のポインタ)
//   ctx+0x30 = SM state (1 open → 2 recv-wait → 3 send → 4 recvresp → 5 parse →
//              6 finalize → 7 error/retry → 8 done → 9 give-up)
//   ctx+0x34 = 保存した next-state、ctx+0x38 = retry カウンタ (≥3 → state 9 = fail)
//   ctx+0x56 = PCPA keychip port (u16)。pcpaOpenClient() で 127.0.0.1 へ
//   ctx+0x04, ctx+0x08 = 成功時のみ 1 に設定 (state 6, substate 8)。presence チェック
//                        FUN_0096c5d0 が読む。
// "keychip.appboot.systemflag" の後に "keychip.version" を送る。
(function diagKeychipSetup() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'diagKeychipSetup: nrs.exe not found'); return; }

    function ctx() {
        try { return nrsBase.add(0x8CF000).readPointer(); } catch(e) { return null; }
    }
    function snap(c) {
        if (!c || c.isNull()) return 'ctx=NULL';
        try {
            return 'state=' + c.add(0x30).readU32() +
                   ' next=' + c.add(0x34).readU32() +
                   ' retry=' + c.add(0x38).readU32() +
                   ' port=' + c.add(0x56).readU16() +
                   ' f4=' + c.add(0x04).readU32() +
                   ' f8=' + c.add(0x08).readU32();
        } catch(e) { return 'snap err: ' + e; }
    }

    var seen = -2, calls = 0, lastLog = '';
    try {
        Interceptor.attach(nrsBase.add(0x56D520), {
            onEnter: function() { this.before = snap(ctx()); },
            onLeave: function(ret) {
                calls++;
                var c = ctx();
                var st = -1;
                try { st = c && !c.isNull() ? c.add(0x30).readU32() : -1; } catch(e) {}
                // state 変化時、最初の 10 回、以降 500 回ごとにログする。
                if (st !== seen || calls <= 10 || calls % 500 === 0) {
                    logMsg('KCSETUP', '#' + calls + ' ret=' + ret.toInt32() +
                           ' [' + this.before + '] -> [' + snap(c) + ']');
                    seen = st;
                }
            }
        });
        logMsg('INIT_KCSETUP', 'amDongleSetupKeychip (FUN_0096d520) state-machine diagnostic hooked');
    } catch(e) { logMsg('WARN', 'diagKeychipSetup attach 0x56D520: ' + e); }

    // FUN_0096d520 に至る gate chain: FUN_00459220 (keychip init)、FUN_0096c480
    // (amDongleInit: ctx + ports + winsock)、FUN_0096dad0 (file/"toolmode" チェック)。
    try {
        Interceptor.attach(nrsBase.add(0x59220), {   // FUN_00459220 keychip init
            onLeave: function() { logMsg('KCGATE', 'FUN_00459220(keychip init) returned; ' + snap(ctx())); }
        });
        logMsg('INIT_KCSETUP', 'FUN_00459220 (keychip init) hooked');
    } catch(e) { logMsg('WARN', 'hook 0x59220: ' + e); }
    try {
        Interceptor.attach(nrsBase.add(0x56C480), {  // FUN_0096c480 amDongleInit
            onLeave: function(ret) { logMsg('KCGATE', 'amDongleInit(FUN_0096c480) ret=' + ret.toInt32() + ' ' + snap(ctx())); }
        });
        logMsg('INIT_KCSETUP', 'amDongleInit (FUN_0096c480) hooked');
    } catch(e) { logMsg('WARN', 'hook 0x56C480: ' + e); }
    try {
        Interceptor.attach(nrsBase.add(0x56DAD0), {  // FUN_0096dad0 file/toolmode check
            onEnter: function(args) {
                this.fn = '<null>';
                try { if (!args[0].isNull()) this.fn = args[0].readCString(); } catch(e) {}
            },
            onLeave: function(ret) {
                logMsg('KCGATE', 'FUN_0096dad0(file/toolmode) param="' + this.fn + '" ret=' + ret.toInt32());
            }
        });
        logMsg('INIT_KCSETUP', 'FUN_0096dad0 (file/toolmode) hooked');
    } catch(e) { logMsg('WARN', 'hook 0x56DAD0: ' + e); }
})();
