// subsys:      lib
// persistence: na
// va:          —
// ssot:        boot/CONVENTIONS.md ; BUGS.md [ANTI-PATTERN] Frida QuickJS missing globals
// role:        Shared helpers (logMsg, str/hex readers, hookFn, parseSockAddr) + script-global getStatusRecvDone. MUST load first (every other module depends on these).
'use strict';

// ── Address resolution ──────────────────────────────────────────────────────
// THE single boundary where RVA arithmetic exists. Every module addresses nrs.exe
// by Ghidra static VA (ImageBase 0x400000); va() maps it to the ASLR-shifted runtime
// address.
//   va(staticVA)        -> runtime pointer for a Ghidra static VA
//   rtToVa(runtimePtr)  -> static VA for a runtime pointer (for logging)
// Never address nrs.exe by raw module base elsewhere; the hygiene checker bans it.
var NRS_IMAGE_BASE = 0x400000;
var _nrsBaseCache = null;
function nrsBaseAddr() {
    if (_nrsBaseCache === null) _nrsBaseCache = Process.getModuleByName('nrs.exe').base;
    return _nrsBaseCache;
}
function va(staticVA) { return nrsBaseAddr().add(staticVA - NRS_IMAGE_BASE); }
function rtToVa(ptr) {
    try { return '0x' + ptr.sub(nrsBaseAddr()).add(NRS_IMAGE_BASE).toString(16); }
    catch (e) { return String(ptr); }
}

function logMsg(tag, msg) { send({ tag: tag, msg: msg }); }
function readWStr(ptr) {
    try { var s = ptr.readUtf16String(); return s !== null ? s : '<null>'; } catch(e) { return '<w?>'; }
}
function readAStr(ptr) {
    try { var s = ptr.readCString(); return s !== null ? s : '<null>'; } catch(e) { return '<a?>'; }
}
function hexBuf(ptr, n) {
    try {
        var len = Math.min(n, 64);
        var b = ptr.readByteArray(len);
        var a = new Uint8Array(b);
        var r = [];
        for (var i = 0; i < a.length; i++) r.push(('0' + a[i].toString(16)).slice(-2));
        return r.join(' ');
    } catch(e) { return '??'; }
}

function hookFn(name, onEnterFn, onLeaveFn) {
    var addr;
    try { addr = Module.getGlobalExportByName(name); }
    catch(e) { logMsg('WARN', 'Not found: ' + name); return; }
    if (!addr) { logMsg('WARN', 'Null: ' + name); return; }
    try { Interceptor.attach(addr, { onEnter: onEnterFn, onLeave: onLeaveFn }); }
    catch(e) { logMsg('WARN', 'Hook fail: ' + name + ' -> ' + e); }
}

function parseSockAddr(sa) {
    try {
        var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
        var ip   = sa.add(4).readU8() + '.' + sa.add(5).readU8() + '.' +
                   sa.add(6).readU8() + '.' + sa.add(7).readU8();
        return ip + ':' + port;
    } catch(e) { return '?'; }
}

// Script-global: set by amgfetcher/recv.js when a get_status response arrives via raw
// recv (port 40113); read+cleared by amgfetcher/getstatus.js (0x98ADC0 hook).
var getStatusRecvDone = false;
