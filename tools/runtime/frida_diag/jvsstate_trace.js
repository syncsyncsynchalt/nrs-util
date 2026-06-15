
// === TeknoParrot_JvsState 共有メモリ トレーサ（純観測・自己完結）===========
// 目的: docs/teknoparrot.md §5 — JvsState の (a) 発生源モジュール、(b) 8 バイト
//       レイアウトを実測する。観測専用（patchCode/挙動変更なし）。
// 自己完結: 00_base.js の有無に依存せずローカルヘルパで動く。よって
//   - frida_monitor の連結パイプライン（spawn 経路）でもそのまま動作し、
//   - tools/jvsstate_capture.py の単体 --attach（TeknoParrot 注入下の観測）でも安全に動く。
//     ※ TP 管理下の nrs.exe へ frida_monitor 全体を attach すると 08/09/10/13 等の
//        patchCode が TP のフックと二重適用され破綻するため、観測時は本ファイル単体を使う。
(function () {
    'use strict';
    var TARGET = 'TeknoParrot_JvsState';

    function _log(tag, msg) { send({ tag: tag, msg: msg }); }
    function _wstr(p) { try { var s = p.readUtf16String(); return s !== null ? s : '<null>'; } catch (e) { return '<w?>'; } }
    function _hex8(p) {
        try {
            var a = new Uint8Array(p.readByteArray(8));
            var r = [];
            for (var i = 0; i < a.length; i++) r.push(('0' + a[i].toString(16)).slice(-2));
            return r.join(' ');
        } catch (e) { return '??'; }
    }
    function _modAt(addr) {
        try { var m = Process.getModuleByAddress(addr); return m ? (m.name + '+0x' + addr.sub(m.base).toString(16)) : addr.toString(); }
        catch (e) { return addr.toString(); }
    }

    var jvsHandles = {};      // handle(str) -> true
    var dumpedViews = {};     // view(str)  -> last 8-byte hex

    function startViewDump(viewPtr, src) {
        var key = viewPtr.toString();
        if (dumpedViews[key] !== undefined) return;
        dumpedViews[key] = null;   // null != any hex string -> first read always logs the baseline
        var ticks = 0;
        var id = setInterval(function () {
            ticks++;
            try {
                var hex = _hex8(viewPtr);
                if (hex !== dumpedViews[key]) {
                    dumpedViews[key] = hex;
                    _log('JVSSTATE_DUMP', src + ' view=' + viewPtr + ' [' + hex + ']');
                }
            } catch (e) { _log('JVSSTATE_DUMP', 'err: ' + e); }
            if (ticks >= 3600) clearInterval(id);   // ~180s @ 50ms
        }, 50);
        _log('JVSSTATE', 'view dump start: ' + src + ' view=' + viewPtr);
    }

    function hookMappingCreate(name, nameArgIndex) {
        var addr = Module.getGlobalExportByName(name);
        if (!addr) { _log('WARN', 'JvsTrace: ' + name + ' not found'); return; }
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try { this.name = _wstr(args[nameArgIndex]); } catch (e) { this.name = '?'; }
                this.isTarget = (this.name === TARGET);
                if (this.isTarget) {
                    this.stack = Thread.backtrace(this.context, Backtracer.ACCURATE).map(_modAt).join(' <- ');
                }
            },
            onLeave: function (ret) {
                if (this.isTarget) {
                    jvsHandles[ret.toString()] = true;
                    _log('JVSSTATE', name + ' h=' + ret + ' caller: ' + this.stack);
                }
            }
        });
    }

    // CreateFileMappingW(name=arg5) / OpenFileMappingW(name=arg2)
    hookMappingCreate('CreateFileMappingW', 5);
    hookMappingCreate('OpenFileMappingW', 2);

    // MapViewOfFile(handle=arg0): JvsState ハンドルの view を定期 hexdump
    (function () {
        var addr = Module.getGlobalExportByName('MapViewOfFile');
        if (!addr) { _log('WARN', 'JvsTrace: MapViewOfFile not found'); return; }
        Interceptor.attach(addr, {
            onEnter: function (args) { this.h = args[0].toString(); this.isTarget = (jvsHandles[this.h] === true); },
            onLeave: function (ret) {
                if (this.isTarget && !ret.isNull()) {
                    _log('JVSSTATE', 'MapViewOfFile h=' + this.h + ' view=' + ret);
                    startViewDump(ret, 'h=' + this.h);
                }
            }
        });
    })();

    _log('JVSSTATE', 'tracer installed (target="' + TARGET + '")');
})();
