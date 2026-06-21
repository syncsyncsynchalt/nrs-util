
// TeknoParrot.dll 動的解析トレーサ（観測専用、自己完結）
// 目的: TeknoParrot が nrs.exe に対して行う操作を API 境界で観測する。
//
// 観測対象:
//   VirtualProtect  : nrs.exe への保護変更 → TP パッチの RVA
//   GetProcAddress  : TP が実行時解決する API（IAT は VMProtect で剥離済み）
//   LoadLibraryW/A  : TP が追加ロードする DLL
//   connect         : TP の接続先（PCPA/ALL.Net 等）
//   WSASend/WSARecv : TP の PCPA 通信内容
//   WriteProcessMemory : クロスプロセス書き込み
//
// 注意: frida_monitor.py（spawn 経路）とは併用しない。TP 管理下の nrs.exe 専用。
(function () {
    'use strict';

    var NRS_SIZE = 0x2132000;  // nrs.exe ImageSize (FACTS.md)

    function _log(tag, msg) { send({ tag: tag, msg: msg }); }
    function _modAt(addr) {
        try { var m = Process.getModuleByAddress(addr); return m ? (m.name + '+0x' + addr.sub(m.base).toString(16)) : addr.toString(); }
        catch (e) { return '?'; }
    }
    function _hexBytes(ptr, n) {
        try {
            var cnt = Math.min(n, 24);
            var a = new Uint8Array(ptr.readByteArray(cnt));
            var r = [];
            for (var i = 0; i < a.length; i++) r.push(('0' + a[i].toString(16)).slice(-2));
            return r.join(' ');
        } catch (e) { return '??'; }
    }

    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch (e) { _log('WARN', '35_traceTP: nrs.exe not found'); }

    function isInNrs(addr) {
        if (!nrsBase) return false;
        return addr.compare(nrsBase) >= 0 && addr.compare(nrsBase.add(NRS_SIZE)) < 0;
    }

    // VirtualProtect: nrs.exe 範囲への保護変更を追跡
    //   VP_WRITE (prot & 0xCC != 0): 書き込み許可化 → bytes = パッチ前オリジナル
    //   VP_EXEC  (prot & 0xCC == 0): 実行専用に復元 → bytes = TP パッチ済み（E9.. = JMP フック）
    var vpFn = Module.getGlobalExportByName('VirtualProtect');
    if (vpFn) {
        Interceptor.attach(vpFn, {
            onEnter: function (args) {
                var addr = args[0];
                if (!isInNrs(addr)) { this.skip = true; return; }
                this.skip = false;
                this.addr = addr;
                this.rva = addr.sub(nrsBase).toUInt32();
                this.size = args[1].toUInt32();
                this.prot = args[2].toUInt32();
                this.bytes = _hexBytes(addr, Math.min(this.size, 16));
                this.caller = _modAt(this.returnAddress);
            },
            onLeave: function () {
                if (this.skip) return;
                var tag = (this.prot & 0xCC) ? 'VP_WRITE' : 'VP_EXEC';
                _log(tag, 'rva=0x' + this.rva.toString(16) +
                    ' size=0x' + this.size.toString(16) +
                    ' prot=0x' + this.prot.toString(16) +
                    ' bytes=[' + this.bytes + ']' +
                    ' caller=' + this.caller);
            }
        });
        _log('TP_TRACE', 'VirtualProtect hook OK (nrs.exe range filter)');
    }

    // GetProcAddress: TP が実行時に解決する API
    // IAT が VMProtect で剥離されているため、実際の API はここで動的解決される。
    var gpaFn = Module.getGlobalExportByName('GetProcAddress');
    if (gpaFn) {
        var gpaCount = 0;
        Interceptor.attach(gpaFn, {
            onEnter: function (args) {
                this.modH = args[0];
                var np = args[1];
                try { this.name = np.toUInt32() < 0x10000 ? 'ord#' + np.toUInt32() : np.readAnsiString(); }
                catch (e) { this.name = '?'; }
                this.caller = _modAt(this.returnAddress);
            },
            onLeave: function (ret) {
                if (!ret.toUInt32()) return;
                var mod = '?';
                try {
                    var m = Process.getModuleByHandle(this.modH);
                    mod = m ? m.name : '?';
                } catch (e) {}
                gpaCount++;
                _log('GPA', '[' + gpaCount + '] ' + mod + '!' + this.name +
                    ' => 0x' + ret.toUInt32().toString(16) +
                    ' caller=' + this.caller);
            }
        });
        _log('TP_TRACE', 'GetProcAddress hook OK');
    }

    // LoadLibraryW/A: TP が追加ロードする DLL
    var llwFn = Module.getGlobalExportByName('LoadLibraryW');
    if (llwFn) {
        Interceptor.attach(llwFn, {
            onEnter: function (args) { try { this.p = args[0].readUtf16String(); } catch (e) { this.p = '?'; } this.caller = _modAt(this.returnAddress); },
            onLeave: function (ret) { _log('LoadLibraryW', '"' + this.p + '" h=0x' + ret.toUInt32().toString(16) + ' caller=' + this.caller); }
        });
    }
    var llaFn = Module.getGlobalExportByName('LoadLibraryA');
    if (llaFn) {
        Interceptor.attach(llaFn, {
            onEnter: function (args) { try { this.p = args[0].readAnsiString(); } catch (e) { this.p = '?'; } this.caller = _modAt(this.returnAddress); },
            onLeave: function (ret) { _log('LoadLibraryA', '"' + this.p + '" h=0x' + ret.toUInt32().toString(16) + ' caller=' + this.caller); }
        });
    }
    _log('TP_TRACE', 'LoadLibraryW/A hooks OK');

    // connect: TP のネットワーク接続先
    var connFn = Module.getGlobalExportByName('connect');
    if (connFn) {
        Interceptor.attach(connFn, {
            onEnter: function (args) {
                try {
                    var sa = args[1];
                    var family = sa.readU16();
                    if (family === 2) {
                        var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                        var ip = sa.add(4).readU8() + '.' + sa.add(5).readU8() + '.' + sa.add(6).readU8() + '.' + sa.add(7).readU8();
                        this.dest = ip + ':' + port;
                    } else { this.dest = 'family=' + family; }
                } catch (e) { this.dest = '?'; }
                this.caller = _modAt(this.returnAddress);
            },
            onLeave: function (ret) { _log('connect', this.dest + ' ret=' + ret.toInt32() + ' caller=' + this.caller); }
        });
        _log('TP_TRACE', 'connect hook OK');
    }

    // WSASend / WSARecv: PCPA 通信内容
    function _readWsaBuf(args) {
        try {
            var wsabuf = args[1];
            var len = wsabuf.readU32();
            var buf = wsabuf.add(4).readPointer();
            if (len > 0 && len < 512) {
                var str = '';
                try { str = buf.readCString().slice(0, 140); } catch (e) {}
                return 'len=' + len + ' "' + str + '"';
            }
        } catch (e) {}
        return null;
    }
    var wsaSendFn = Module.getGlobalExportByName('WSASend');
    if (wsaSendFn) {
        Interceptor.attach(wsaSendFn, {
            onEnter: function (args) { this.d = _readWsaBuf(args); this.caller = _modAt(this.returnAddress); },
            onLeave: function () { if (this.d) _log('WSASend', this.d + ' caller=' + this.caller); }
        });
    }
    var wsaRecvFn = Module.getGlobalExportByName('WSARecv');
    if (wsaRecvFn) {
        Interceptor.attach(wsaRecvFn, {
            onEnter: function (args) { this.d = _readWsaBuf(args); this.caller = _modAt(this.returnAddress); },
            onLeave: function () { if (this.d) _log('WSARecv', this.d + ' caller=' + this.caller); }
        });
    }
    _log('TP_TRACE', 'WSASend/WSARecv hooks OK');

    // WriteProcessMemory: クロスプロセス書き込み（念のため）
    var wpmFn = Module.getGlobalExportByName('WriteProcessMemory');
    if (wpmFn) {
        Interceptor.attach(wpmFn, {
            onEnter: function (args) {
                var targetAddr = args[1];
                var size = args[3].toUInt32();
                if (isInNrs(targetAddr)) {
                    _log('WriteProcessMemory', 'rva=0x' + targetAddr.sub(nrsBase).toUInt32().toString(16) +
                        ' size=' + size + ' bytes=[' + _hexBytes(targetAddr, Math.min(size, 16)) + ']' +
                        ' caller=' + _modAt(this.returnAddress));
                }
            }
        });
        _log('TP_TRACE', 'WriteProcessMemory hook OK (nrs.exe range filter)');
    }

    _log('TP_TRACE', 'All hooks installed. VP_EXEC rows show TP-patched bytes at nrs.exe RVAs.');
    _log('TP_TRACE', 'GPA rows show runtime API resolution (VMProtect IAT bypass).');
})();
