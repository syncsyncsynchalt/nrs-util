// subsys:      amdongle
// persistence: monitor
// va: 0x96EEC0, 0x96F1A0, 0x96EFC0, 0x96F290 (am* getters) ; 0x457500/0x457810/0x457822/0x457910/0x978450/0x975E00 (SM)
// ssot:        FACTS.md §hookAmDongleSM Monitor RVAs
// role:        amDongle getter と dongle/keychip ステートマシンへのログ専用 Interceptor（無改変）。Persistent パッチは amdongle/patch.js にある。
(function hookAmDongle() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'amDongle hook: nrs.exe not found'); return; }

    var AMF = {
        amDongleGetGameId:      0x96EEC0,
        amDongleGetRegion:      0x96F1A0,
        amDongleGetSystemFlag:  0x96EFC0,
        amDongleGetVersion:     0x96F290,
        amDongleGetModelType:   0,
        amDongleBusy:           0,
    };

    function hookDongle(name, sva) {
        if (!sva) return;
        try {
            Interceptor.attach(va(sva), {
                onEnter: function(args) {
                    this.buf    = args[0];
                    this.bufLen = args[1].toUInt32();
                },
                onLeave: function(ret) {
                    var out = '';
                    try { out = this.buf.readCString().slice(0, 80); } catch(e) {}
                    var retInt = ret.toInt32();
                    logMsg('amDongle', name + '() ret=' + retInt +
                           (out ? ' buf="' + out + '"' : ''));
                }
            });
        } catch(e) { logMsg('WARN', 'amDongle hook ' + name + ': ' + e); }
    }

    for (var k in AMF) hookDongle(k, AMF[k]);
    logMsg('INIT_AMDONGLE', 'amDongle getter hooks attached');
})();

// amDongle と keychip のステートマシンのモニタ（ログ専用; persistent パッチは
// amdongle/patch.js [0x975E00, 0x457AF0] にある）。
(function hookAmDongleSM() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'amDongleSM: nrs.exe not found'); return; }

    var SM = {
        dongleInit:    0x457500,  // 最上位オーケストレータ: state==7 まで外側 SM、その後 keychipSM
        outerTick:     0x457810,  // 内側 tick: amDongleTick7 + amDongleBusy
        outerSM:       0x457822,  // 6 状態オーケストレータ（dhcp/nic/mac + amDongle クエリ）
        keychipSM:     0x457910,  // keychip 検証 SM（9 状態）
        amDongle7:     0x978450,  // amDongle 7 状態ディスパッチャ（[CCF0EC]+0x18 を読む）
        amDongleBusy2: 0x975E00,  // amDongleBusy（amdongle/patch.js でも patchCode 済み）
    };

    var smCounts = {};
    function smLog(tag, msg) {
        if (!smCounts[tag]) smCounts[tag] = 0;
        smCounts[tag]++;
        var n = smCounts[tag];
        if (n <= 5 || n % 100 === 0) logMsg(tag, '[#' + n + '] ' + msg);
    }

    function hookSM(name, sva, onEnterFn, onLeaveFn) {
        try {
            Interceptor.attach(va(sva), {
                onEnter: onEnterFn || function(args) {},
                onLeave: onLeaveFn || function(ret) {}
            });
        } catch(e) { logMsg('WARN', 'hookSM ' + name + ': ' + e); }
    }

    hookSM('dongleInit', SM.dongleInit,
        function(args) { logMsg('dongleInit', 'CALL'); },
        function(ret)  { logMsg('dongleInit', 'RET'); }
    );
    hookSM('outerTick', SM.outerTick,
        function(args) {
            var s = 0;
            try { s = va(0x16F6C1C).readU32(); } catch(e) {}
            smLog('outerTick', 'outerState=' + s);
        },
        function(ret) { smLog('outerTick', 'al=' + (ret.toUInt32() & 0xff)); }
    );
    hookSM('outerSM', SM.outerSM,
        function(args) {
            var s = 0;
            try { s = va(0x16F6C1C).readU32(); } catch(e) {}
            smLog('outerSM', 'state=' + s);
        },
        function(ret) { smLog('outerSM', 'al=' + (ret.toUInt32() & 0xff)); }
    );
    hookSM('keychipSM', SM.keychipSM,
        function(args) {
            var s = 0, esi10 = 0;
            try { s = va(0x16F6CAC).readU32(); } catch(e) {}
            try { esi10 = va(0x16F6CBC).readU32(); } catch(e) {}
            smLog('keychipSM', 'state=' + s + ' [ctx+0x10]=' + esi10);
        },
        function(ret) { smLog('keychipSM', 'al=' + (ret.toUInt32() & 0xff)); }
    );
    hookSM('amDongle7', SM.amDongle7,
        function(args) {
            var ctxp = 0, state = 0;
            try { ctxp = va(0xCCF0EC).readU32(); } catch(e) {}
            try { state = ptr(ctxp).add(0x18).readU32(); } catch(e) {}
            smLog('amDongle7', 'ctx+0x18(state)=' + state);
        },
        function(ret) { smLog('amDongle7', 'ret=' + ret.toInt32()); }
    );
    hookSM('amDongleBusy2', SM.amDongleBusy2,
        function(args) {},
        function(ret) { smLog('amDongleBusy2', 'ret=0x' + ret.toUInt32().toString(16)); }
    );

    logMsg('INIT_SM', 'amDongle state machine monitors attached');
})();
