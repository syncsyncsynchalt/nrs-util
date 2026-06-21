
// ─────────────────────────────────────────────────────────────────────────────
// amDongleUpdate 診断 (FUN_00970fc0, RVA 0x570fc0) — FUN_00459460 から毎フレーム
// 呼ばれる keychip 再検証。観測のみ。ctx+8 か戻り値が変わるたびに
// ステートマシンをログする。
//
// ctx+4==0 || ctx+8==0 のとき非ゼロを返す → -0xc (keychip データ消失)。
// case-8 の MAC/SSD verify は不一致時に ctx+8=0 をクリアする ("Verify MAC/SSD NG!!!")。
// verify は (ctx+0x4c==0 && ctx+0x18==0) のときだけ走る。keychip command
// (FUN_0096c6c0/c8d0/c920/dbc0/…) が非ゼロを返すと ctx+0x4c!=0 → verify は SKIP される
// (意図した DS28CN01 バイパス)。
// ─────────────────────────────────────────────────────────────────────────────
(function diagDongleUpdate() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'diagDongleUpdate: nrs.exe not found'); return; }

    function C() {
        try { var c = nrsBase.add(0x8CF000).readPointer(); return c.isNull() ? null : c; }
        catch(e) { return null; }
    }
    function snap(c) {
        try {
            return 'sub=' + c.add(0x2c).readU32() + ' case=' + c.add(0x3c).readU32() +
                   ' type=0x' + c.add(0x5a).readU8().toString(16) +
                   ' f4=' + c.add(0x4).readU32() + ' f8=' + c.add(0x8).readU32() +
                   ' f10=' + c.add(0x10).readU32() +
                   ' err=' + c.add(0x44).readS32() +
                   ' f4c=' + c.add(0x4c).readU32() + ' f18=' + c.add(0x18).readU32() +
                   ' f1c=' + c.add(0x1c).readU32() + ' f20=' + c.add(0x20).readU32() +
                   ' f24=' + c.add(0x24).readU32();
        } catch(e) { return 'snap err: ' + e; }
    }

    var calls = 0, lastF8 = -1, lastRet = 999, lastErr = 999;
    try {
        Interceptor.attach(nrsBase.add(0x570FC0), {   // FUN_00970fc0 amDongleUpdate
            onLeave: function(ret) {
                calls++;
                var c = C();
                if (!c) return;
                var f8 = -1, err = 0;
                try { f8 = c.add(0x8).readU32(); err = c.add(0x44).readS32(); } catch(e) { return; }
                var r = ret.toInt32();
                // 最初の 20 回と、f8 / ret / err が変わるたびにログする。
                if (calls <= 20 || f8 !== lastF8 || r !== lastRet || err !== lastErr) {
                    logMsg('DONGLEUPD', '#' + calls + ' ret=' + r + ' [' + snap(c) + ']');
                    lastF8 = f8; lastRet = r; lastErr = err;
                }
            }
        });
        logMsg('INIT_DONGLEUPD', 'amDongleUpdate (FUN_00970fc0) diagnostic hooked');
    } catch(e) { logMsg('WARN', 'diagDongleUpdate attach 0x570FC0: ' + e); }
})();
