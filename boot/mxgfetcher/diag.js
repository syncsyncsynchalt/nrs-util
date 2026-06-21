// subsys:      mxgfetcher
// persistence: monitor
// va:          0x974B00, 0x974820, 0x975A70, 0x975320, 0x975700, 0x975830, 0x974560
// ssot:        mxgfetcher/FACTS.md
// role:        get_status/TCP SM の log-only 観測フック群（boot 修正には不要。load-bearing は getstatus.js）。
//
// getstatus.js から分離した純診断 Interceptor。状態を変えず ret/subState を間引きログするのみ。
(function gfetcherDiag() {
    // throttled onLeave logger: 先頭 head 件 + every 件ごと。
    function tap(staticVA, tag, head, every, label) {
        var n = 0;
        hook(staticVA, { onLeave: function (ret) {
            n++;
            if (n <= head || n % every === 0)
                logMsg(tag, '#' + n + ' ' + label + '=' + ret.toInt32());
        } }, tag);
    }
    tap(0x974B00, 'DIAG_974B00', 5,  200, 'ret');        // get_status result パーサ
    tap(0x974820, 'DIAG_974820', 10, 200, 'statusInt');  // status 文字列→int
    tap(0x975A70, 'DIAG_975A70', 5,  200, 'ret');        // get_status sender
    tap(0x975320, 'DIAG_975320', 10, 100, 'ret');        // TCP sub-state 4 パーサ
    tap(0x974560, 'DIAG_974560', 10, 200, 'ret');        // pause done チェック（0x975830 から呼ばれる）

    // 0x975700 — TCP SM step（busy=1 経路）。sub-state [0x1286FF4] も読む。
    var n7 = 0;
    hook(0x975700, { onLeave: function (ret) {
        n7++;
        var subState = va(0x1286FF4).readU32();
        if (n7 <= 10 || n7 % 500 === 0)
            logMsg('DIAG_975700', '#' + n7 + ' subState=' + subState + ' ret=' + ret.toInt32());
    } }, 'DIAG_975700');

    // 0x975830 — state-9 pause request SM。arg + stream ptr/busy をログする。
    var n8 = 0;
    hook(0x975830, {
        onEnter: function (args) {
            this.arg0 = args[0].toInt32();
            try {
                this.streamInfo = ' strPtr=0x' + va(0x1286FF0).readU32().toString(16) +
                                  ' strBusy=' + va(0x1286FF4).readU32();
            } catch (e) { this.streamInfo = ''; }
        },
        onLeave: function (ret) {
            n8++;
            if (n8 <= 10 || n8 % 200 === 0)
                logMsg('DIAG_975830', '#' + n8 + ' arg=' + this.arg0 + this.streamInfo + ' ret=' + ret.toInt32());
        }
    }, 'DIAG_975830');
})();
