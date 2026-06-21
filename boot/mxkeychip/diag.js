// subsys:      mxkeychip
// persistence: monitor
// va:          0x98AB20, 0x98AB60, 0x98AF50, 0x98AFF0
// ssot:        mxkeychip/FACTS.md
// role:        PCPA 送受信の log-only 観測（pcpaSet/Add/Send/Recv）。boot 修正には不要。load-bearing は client.js。
//
// client.js から分離した純診断フック。pcpa_server.py が全ポートを応答するので注入はせず、
// 送出 key/val と受信バッファをログするのみ（state 変更なし）。
(function pcpaDiag() {
    // pcpaSetSendPacket / pcpaAddSendPacket: 送出 request フィールドをログ。
    hook(0x98AB20, {
        onEnter: function (args) {
            try { this.key = args[1].readCString(); } catch (e) { this.key = '?'; }
            try { this.val = args[2].readCString(); } catch (e) { this.val = '?'; }
        },
        onLeave: function () { logMsg('pcpaSet', '"' + this.key + '"="' + this.val + '"'); }
    }, 'pcpaSetSendPacket');

    hook(0x98AB60, {
        onEnter: function (args) {
            try { this.key = args[1].readCString(); } catch (e) { this.key = '?'; }
            try { this.val = args[2].readCString(); } catch (e) { this.val = '?'; }
        },
        onLeave: function () { logMsg('pcpaAdd', '"' + this.key + '"="' + this.val + '"'); }
    }, 'pcpaAddSendPacket');

    // pcpaSendRequest: 送出バッファ（stream+0x3DC）をログ。注入しない（server が見るべき）。
    var pcpaSendCount = 0;
    hook(0x98AF50, {
        onEnter: function (args) {
            this.stream = args[0];
            var sendBuf = '';
            try { sendBuf = this.stream.add(0x3DC).readCString().slice(0, 200); } catch (e) {}
            pcpaSendCount++;
            logMsg('pcpaSend', '[#' + pcpaSendCount + '] "' + sendBuf + '"');
        },
        onLeave: function (ret) {
            var orig = ret.toInt32();
            if (orig !== 0) logMsg('pcpaSend', '[#' + pcpaSendCount + '] ret=' + orig + ' (non-zero)');
        }
    }, 'pcpaSendRequest');

    // pcpaRecvResponse: orig=1=poll継続, orig=0=応答到着, orig<0=error。log のみ（注入禁止: 応答破壊を防ぐ）。
    var pcpaRecvCount = 0;
    hook(0x98AFF0, {
        onEnter: function (args) { this.stream = args[0]; },
        onLeave: function (ret) {
            var orig = ret.toInt32();
            var r1 = '';
            try { r1 = this.stream.add(0x258).readCString().slice(0, 120); } catch (e) {}
            pcpaRecvCount++;
            if (orig !== 0) {
                if (pcpaRecvCount <= 10 || pcpaRecvCount % 500 === 0)
                    logMsg('pcpaRecv', '[#' + pcpaRecvCount + '] wait orig=' + orig);
            } else {
                if (pcpaRecvCount <= 20 || pcpaRecvCount % 100 === 0)
                    logMsg('pcpaRecv', '[#' + pcpaRecvCount + '] OK buf="' + r1 + '"');
            }
        }
    }, 'pcpaRecvResponse');
})();
