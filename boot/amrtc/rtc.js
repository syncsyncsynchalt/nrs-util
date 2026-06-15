// subsys:      amrtc
// persistence: runtime   // network_role=local
// va: —
// ssot:        amrtc/FACTS.md
// role:        amRtc サーバ時刻→PC ローカル時刻 / SetServerTime 無視。

// ─────────────────────────────────────────────────────────────────────────────
// amRtcGetServerTime bypass — return local system time instead of RingEdge RTC
//
// RVA 0x574040. Without a RingEdge RTC server the function returns -3 (no
// driver). TeknoParrot replaces it with PC local time. We hook onLeave: on
// failure we call GetLocalTime, pack it into the amRtcTime struct at args[1],
// and force ret→0.
//
// amRtcTime struct layout (observed from function body at 0x573FC0):
//   +0x00  WORD  year
//   +0x02  BYTE  month (1-12)
//   +0x03  BYTE  day   (1-31)
//   +0x04  BYTE  hour  (0-23)
//   +0x05  BYTE  minute(0-59)
//   +0x06  BYTE  second(0-59)
// ─────────────────────────────────────────────────────────────────────────────
(function hookAmRtc() {
    try {
        var nrsBase = Module.findBaseAddress('nrs.exe');
        if (!nrsBase) { logMsg('RTC', 'nrs.exe not found, skip'); return; }

        var gltAddr = null;
        try { gltAddr = Module.getGlobalExportByName('GetLocalTime'); } catch(e) {}
        if (!gltAddr || gltAddr.isNull()) { logMsg('RTC', 'GetLocalTime not found'); return; }
        var GetLocalTime = new NativeFunction(gltAddr, 'void', ['pointer']);

        var sysBuf = Memory.alloc(16);

        try {
            Interceptor.attach(va(0x974040), {
                onEnter: function(args) { this.outPtr = args[0]; },
                onLeave: function(ret) {
                    if (ret.toInt32() >= 0) return;
                    if (!this.outPtr || this.outPtr.isNull()) return;
                    try {
                        GetLocalTime(sysBuf);
                        var year   = sysBuf.readU16();
                        var month  = sysBuf.add(2).readU16();
                        var day    = sysBuf.add(6).readU16();
                        var hour   = sysBuf.add(8).readU16();
                        var minute = sysBuf.add(10).readU16();
                        var second = sysBuf.add(12).readU16();
                        this.outPtr.writeU16(year);
                        this.outPtr.add(2).writeU8(month);
                        this.outPtr.add(3).writeU8(day);
                        this.outPtr.add(4).writeU8(hour);
                        this.outPtr.add(5).writeU8(minute);
                        this.outPtr.add(6).writeU8(second);
                        ret.replace(0);
                        logMsg('RTC', 'amRtcGetServerTime → ' + year + '-' + month + '-' + day +
                               ' ' + hour + ':' + minute + ':' + second);
                    } catch(e) { logMsg('RTC', 'hook err: ' + e); }
                }
            });
        } catch(e) { logMsg('RTC', '0x574040 attach err: ' + e); }

        try {
            Interceptor.attach(va(0x9742C0), {
                onLeave: function(ret) { ret.replace(0); }
            });
        } catch(e) { logMsg('RTC', '0x5742C0 attach err: ' + e); }

        logMsg('RTC', 'amRtcGetServerTime(0x574040) + amRtcSetServerTime(0x5742C0) installed');
    } catch(e) { logMsg('RTC', 'hookAmRtc setup err: ' + e); }
})();
