// subsys:      amrtc
// persistence: runtime   // network_role=local
// va: —
// ssot:        amrtc/FACTS.md
// role:        amRtc サーバ時刻→PC ローカル時刻 / SetServerTime 無視。

// ─────────────────────────────────────────────────────────────────────────────
// amRtcGetServerTime (0x974040) bypass — RingEdge RTC ではなく PC のローカルシステム時刻を返す。
// RTC サーバが無いとこの関数は -3（ドライバ無し）を返す。onLeave フックで、失敗時に GetLocalTime を
// 呼んで outPtr の amRtcTime 構造体へ詰め、ret を 0 に強制する。
//
// amRtcTime 構造体レイアウト（0x973FC0 の関数本体より）:
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
        } catch(e) { logMsg('RTC', '0x974040 attach err: ' + e); }

        try {
            Interceptor.attach(va(0x9742C0), {
                onLeave: function(ret) { ret.replace(0); }
            });
        } catch(e) { logMsg('RTC', '0x9742C0 attach err: ' + e); }

        logMsg('RTC', 'amRtcGetServerTime(0x974040) + amRtcSetServerTime(0x9742C0) installed');
    } catch(e) { logMsg('RTC', 'hookAmRtc setup err: ' + e); }
})();
