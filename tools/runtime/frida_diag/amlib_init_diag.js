
// ─────────────────────────────────────────────────────────────────────────────
// 診断: amlib init ステートマシン FUN_0089a010 (RVA 0x49a010) の state トレーサ。観測のみ。
//
// FUN_0089a010(param_1): param_1+4 = state、param_1+8 = substate。
//   state 2 = IC CARD R/W (FUN_004f6330)
//   state 3 = FUN_008b3b00/b40  → errCode 0x16
//   state 4 = device (FUN_0072dce0/deviceMgr type-0x20) → errCode 0x14 + bitmask _DAT_016f5af4
//   state 6 = ネットワークサーバ (LOCAL/ALL.NET GAME SERVER/UPLOAD/AUTH)
//   state 9 = エラー (DAT_016f5af0 に errCode を設定。scene system が errNo+msg にマップ)
//
// state 9 で errCode + bitmask + backtrace を取得し、失敗した device を特定する。
// ─────────────────────────────────────────────────────────────────────────────
(function diagAmlibInit() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'diagAmlibInit: nrs.exe not found'); return; }

    var errCodeAddr = nrsBase.add(0x12f5af0);   // DAT_016f5af0 (amlib master errCode)
    var errMaskAddr = nrsBase.add(0x12f5af4);   // _DAT_016f5af4 (失敗詳細の bitmask)

    // FUN_0072b450(void) → comm/device-manager ptr (type-0x20 device)。
    // deviceMgr+0x1d4[idx] = sub-device/server ごとの status (FUN_0072dce0 が読む)。
    // deviceMgr+0x1ec = エラー集約ワード (state 6 が & 0x5f3 をチェック → errCode 0x14 → 8005)。
    var getDevMgr = null;
    try { getDevMgr = new NativeFunction(nrsBase.add(0x32b450), 'pointer', []); } catch(e) {}
    function dumpDevMgr() {
        if (!getDevMgr) return '(no getDevMgr)';
        try {
            var dm = getDevMgr();
            if (dm.isNull()) return 'devMgr=NULL';
            var s = 'devMgr=' + dm + ' +0x1ec=0x' + dm.add(0x1ec).readU32().toString(16) + ' status[0..6]=';
            var arr = [];
            for (var i = 0; i < 7; i++) arr.push(dm.add(0x1d4 + i*4).readS32());
            return s + arr.join(',');
        } catch(e) { return 'devMgr dump err: ' + e; }
    }

    var lastState = -1, lastSub = -1, calls = 0, loggedErr9 = 0, loggedS6 = 0;
    try {
        Interceptor.attach(nrsBase.add(0x49A010), {
            onEnter: function(args) {
                this.p1 = args[0];
                try {
                    this.st  = this.p1.add(4).readU32();
                    this.sub = this.p1.add(8).readU32();
                } catch(e) { this.st = -1; this.sub = -1; }
            },
            onLeave: function() {
                calls++;
                var st = -1, sub = -1;
                try { st = this.p1.add(4).readU32(); sub = this.p1.add(8).readU32(); } catch(e) { return; }
                if (st !== lastState || sub !== lastSub) {
                    var ec = 0, em = 0;
                    try { ec = errCodeAddr.readU32(); em = errMaskAddr.readU32(); } catch(e) {}
                    logMsg('AMLIBINIT', '#' + calls + ' state ' + lastState + '->' + st +
                           ' sub=' + sub + ' errCode=' + ec + '(0x' + ec.toString(16) + ')' +
                           ' mask=0x' + em.toString(16));
                    // ネットワーク state: comm device-manager の status をダンプ (deviceMgr+0x1ec bits 2-4 =0x1c → 8005)。
                    if ((st === 6 || st === 7 || st === 8) && loggedS6 < 8) {
                        loggedS6++;
                        logMsg('AMLIBINIT', 'NET state' + st + ' ' + dumpDevMgr());
                    }
                    if (st === 9 && loggedErr9 < 6) {
                        loggedErr9++;
                        var bt = '';
                        try {
                            bt = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0,6)
                                 .map(function(f){
                                     var m = Process.findModuleByAddress(f);
                                     return m ? m.name + '+0x' + f.sub(m.base).toString(16) : '0x'+f.toString(16);
                                 }).join('<-');
                        } catch(e) {}
                        logMsg('AMLIBINIT', 'ERROR state9 from state ' + lastState +
                               ' errCode=0x' + (errCodeAddr.readU32()).toString(16) +
                               ' mask=0x' + (errMaskAddr.readU32()).toString(16) +
                               ' ' + dumpDevMgr() + ' bt=' + bt);
                    }
                    lastState = st; lastSub = sub;
                }
            }
        });
        logMsg('INIT_AMLIBINIT', 'FUN_0089a010 amlib init SM tracer hooked (RVA 0x49a010)');
    } catch(e) { logMsg('WARN', 'diagAmlibInit attach 0x49A010: ' + e); }
})();
