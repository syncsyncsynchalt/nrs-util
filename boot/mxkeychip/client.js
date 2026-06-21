// subsys:      mxkeychip
// persistence: runtime   // network_role=serve
// va: 0x98AEA0
// ssot:        mxkeychip/FACTS.md
// role:        pcpaOpenClient 戻り値回復: orig<0 のときだけ ret→0（40106/40104 のキャッシュ無接続で SendRequest -4 を防ぐ）。runtime
//
// pcpaOpenClient は各ポート(40102/40104/40106/40110)へ接続する。orig=1=「新規接続確立・socket 格納」は
// pass-through 必須（pcpaSendRequest が有効 socket を見つけられる）。キャッシュ socket の無いポート(40106/40104)で
// 0 を強制すると SendRequest が即 -4。よって genuine error(orig<0) のときだけ 0 に回復する。
// 送受信の観測フック(pcpaSet/Add/Send/Recv)は diag.js に分離。
(function hookPcpa() {
    var pcpaOpenCount = 0;
    hook(0x98AEA0, {   // pcpaOpenClient (stream,ip,port,timeout,unk)
        onEnter: function (args) {
            this.stream = args[0];
            this.ip   = args[1].readCString();
            this.port = args[2].toUInt32();
        },
        onLeave: function (ret) {
            var orig = ret.toInt32();
            var forced = '';
            if (orig < 0) { ret.replace(0); forced = ' -> 0'; }
            pcpaOpenCount++;
            if (pcpaOpenCount <= 5 || pcpaOpenCount % 500 === 0)
                logMsg('pcpaOpen', '[#' + pcpaOpenCount + '] ' + this.ip + ':' + this.port + ' orig=' + orig + forced);
        }
    }, 'pcpaOpenClient');
    logMsg('INIT_PCPA', 'pcpaOpenClient hook attached (recv/send observation in diag.js)');
})();
