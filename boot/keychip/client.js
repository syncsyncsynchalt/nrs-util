// subsys:      keychip
// persistence: runtime   // network_role=serve
// va: 0x98AEA0
// ssot:        keychip/FACTS.md
// role:        pcpaOpenClient 戻り値回復: orig<0 のときだけ ret→0（40106/40104 のキャッシュ無接続で SendRequest -4 を防ぐ）。runtime

// ─────────────────────────────────────────────────────────────────────────────
// amDongle / pcpa hooks (nrs.exe 固定 RVA + ASLR base)
// RVA = VA - ImageBase(0x00400000)
// ─────────────────────────────────────────────────────────────────────────────
(function hookPcpa() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'nrs.exe not found for pcpa hooks: ' + e); return; }

    var VA = {
        pcpaOpenClient:    0x98AEA0,  // pcpaOpenClient (5 args: stream,ip,port,timeout,unk)
        pcpaSetSendPacket: 0x98AB20,  // pcpaSetSendPacket (3 args)
        pcpaAddSendPacket: 0x98AB60,  // pcpaAddSendPacket (3 args)
        pcpaSendRequest:   0x98AF50,  // pcpaSendRequest (2 args: stream, unk)
        pcpaRecvResponse:  0x98AFF0,  // pcpaRecvResponse (2 args: stream, unk)
        amDongleInit:      0,         // TBD
    };

    // Fake PCPA response: code=54 bypasses DS28CN01 challenge-response validation
    // (per sega.bsnk.me/ringedge/software/security/security/ documentation)
    var PCPA_FAKE_RESP = 'result=0\ncode=54\n\x00';

    function writeFakeResp(stream) {
        if (!stream || stream.isNull()) return;
        try {
            for (var i = 0; i < PCPA_FAKE_RESP.length; i++) {
                var ch = PCPA_FAKE_RESP.charCodeAt(i);
                stream.add(0x258).add(i).writeU8(ch);
                stream.add(0x1EC).add(i).writeU8(ch);
            }
        } catch(e) {}
    }

    // pcpaOpenClient: connects to pcpa_server.py on various ports (40102/40104/40106/40110).
    // IMPORTANT: do NOT force return 0 unconditionally.
    // orig=1 means "new connection established, socket handle stored" — must pass through so
    // pcpaSendRequest can find the valid socket.  Forcing 0 ("use cached") on ports that have
    // no prior cached socket (40106, 40104) causes pcpaSendRequest to return -4 immediately.
    // Only override genuine errors (orig < 0).
    var pcpaOpenCount = 0;
    try {
        Interceptor.attach(va(VA.pcpaOpenClient), {
            onEnter: function(args) {
                this.stream = args[0];
                this.ip   = args[1].readCString();
                this.port = args[2].toUInt32();
            },
            onLeave: function(ret) {
                var orig = ret.toInt32();
                var forced = '';
                if (orig < 0) { ret.replace(0); forced = ' → 0'; }
                pcpaOpenCount++;
                if (pcpaOpenCount <= 5 || pcpaOpenCount % 500 === 0)
                    logMsg('pcpaOpen', '[#' + pcpaOpenCount + '] ' + this.ip + ':' +
                           this.port + ' orig=' + orig + forced);
            }
        });
    } catch(e) { logMsg('WARN', 'pcpaOpenClient hook: ' + e); }

    // pcpaSetSendPacket / pcpaAddSendPacket: log outgoing request fields
    try {
        Interceptor.attach(va(VA.pcpaSetSendPacket), {
            onEnter: function(args) {
                try { this.key = args[1].readCString(); } catch(e) { this.key = '?'; }
                try { this.val = args[2].readCString(); } catch(e) { this.val = '?'; }
            },
            onLeave: function(ret) {
                logMsg('pcpaSet', '"' + this.key + '"="' + this.val + '"');
            }
        });
    } catch(e) { logMsg('WARN', 'pcpaSetSendPacket hook: ' + e); }

    try {
        Interceptor.attach(va(VA.pcpaAddSendPacket), {
            onEnter: function(args) {
                try { this.key = args[1].readCString(); } catch(e) { this.key = '?'; }
                try { this.val = args[2].readCString(); } catch(e) { this.val = '?'; }
            },
            onLeave: function(ret) {
                logMsg('pcpaAdd', '"' + this.key + '"="' + this.val + '"');
            }
        });
    } catch(e) { logMsg('WARN', 'pcpaAddSendPacket hook: ' + e); }

    // pcpaSendRequest: log only. With pcpa_server.py running, the real send succeeds.
    // Do NOT force return 0 — that would prevent the server from seeing the request.
    var pcpaSendCount = 0;
    try {
        Interceptor.attach(va(VA.pcpaSendRequest), {
            onEnter: function(args) {
                this.stream = args[0];
                var sendBuf = '';
                try { sendBuf = this.stream.add(0x3DC).readCString().slice(0, 200); } catch(e) {}
                pcpaSendCount++;
                logMsg('pcpaSend', '[#' + pcpaSendCount + '] "' + sendBuf + '"');
            },
            onLeave: function(ret) {
                var orig = ret.toInt32();
                if (orig !== 0)
                    logMsg('pcpaSend', '[#' + pcpaSendCount + '] ret=' + orig + ' (non-zero)');
            }
        });
    } catch(e) { logMsg('WARN', 'pcpaSendRequest hook: ' + e); }

    // pcpaRecvResponse: pcpa_server.py handles all ports and responds correctly.
    // Do NOT inject fake responses: orig=1 means "still waiting" (poll again next tick),
    // NOT an error. Injecting code=54 on orig=1 would corrupt the response buffer before
    // the real server reply arrives, causing set_auth_params/resume/isrelease parsers to fail.
    // Just log and pass through. The game's polling loop handles orig=1 naturally.
    var pcpaRecvCount = 0;
    try {
        Interceptor.attach(va(VA.pcpaRecvResponse), {
            onEnter: function(args) { this.stream = args[0]; },
            onLeave: function(ret) {
                var orig = ret.toInt32();
                var r1 = '';
                try { r1 = this.stream.add(0x258).readCString().slice(0, 120); } catch(e) {}
                pcpaRecvCount++;
                if (orig !== 0) {
                    // orig=1: still polling (normal — server will respond next tick)
                    // orig<0: real error — log only, do not inject
                    if (pcpaRecvCount <= 10 || pcpaRecvCount % 500 === 0)
                        logMsg('pcpaRecv', '[#' + pcpaRecvCount + '] wait orig=' + orig);
                } else {
                    if (pcpaRecvCount <= 20 || pcpaRecvCount % 100 === 0)
                        logMsg('pcpaRecv', '[#' + pcpaRecvCount + '] OK buf="' + r1 + '"');
                }
            }
        });
    } catch(e) { logMsg('WARN', 'pcpaRecvResponse hook: ' + e); }

    logMsg('INIT_PCPA', 'pcpa hooks attached at base=' + nrsBase +
           ' (pcpaOpen va=0x' + VA.pcpaOpenClient.toString(16) + ')');
})();
