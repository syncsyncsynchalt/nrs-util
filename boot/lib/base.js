// subsys:      lib
// persistence: na
// va:          —
// ssot:        boot/CONVENTIONS.md ; BUGS.md [ANTI-PATTERN] Frida QuickJS missing globals
// role:        共通ヘルパ(logMsg, str/hex リーダ, hookFn, parseSockAddr) + script-global getStatusRecvDone。必ず最初にロードする(他の全モジュールが依存)。
'use strict';

// 番地解決
// RVA 演算が存在する唯一の境界。各モジュールは nrs.exe を Ghidra static_VA
// (ImageBase 0x400000) で参照し、va() がそれを ASLR でずれた runtime 番地へ
// 写像する。
//   va(staticVA)        -> Ghidra static_VA に対する runtime ポインタ
//   rtToVa(runtimePtr)  -> runtime ポインタに対する static_VA (ログ用)
// ここ以外で生のモジュール base から nrs.exe を参照しないこと。hygiene checker が禁止する。
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

// Script-global: raw recv (port 40113) で get_status 応答が届いたとき amgfetcher/recv.js が
// セットし、amgfetcher/getstatus.js (0x98ADC0 hook) が読んでクリアする。
var getStatusRecvDone = false;

// 宣言的 patch/hook/watch ヘルパ
// boot patch を表現する標準手段。モジュールは Ghidra static_VA を渡す。va()
// (上記) が唯一の RVA 境界なので、モジュールは nrsBase に触れない。CONVENTIONS.md
// 参照: 単純な静的バイト stub も所属サブシステムのモジュールに patch() で置く（中央テーブル
// なし）。hook/timer ロジックを持つものも同様に各モジュールで hook()/watch() を使う。

// よく使う stdcall return stub を名前付きバイト配列で(可読 + トークン最小)。
var RET0 = [0x31, 0xC0, 0xC3];                    // xor eax,eax ; ret        -> return 0
var RET1 = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];  // mov eax,1 ; ret          -> return 1
function retImm(n) {                              // mov eax,n ; ret          -> return n (32-bit)
    return [0xB8, n & 0xFF, (n >>> 8) & 0xFF, (n >>> 16) & 0xFF, (n >>> 24) & 0xFF, 0xC3];
}
function retN(n) {                                // ret n  (stdcall の引数掃除。eax は不変)
    return [0xC2, n & 0xFF, (n >>> 8) & 0xFF];
}
// patchCode(static_VA) + read-back 検証 + ログ。`bytes` はバイト配列。
function patch(staticVA, bytes, note) {
    var p = va(staticVA);
    Memory.patchCode(p, bytes.length, function (code) { code.writeByteArray(bytes); });
    var ok = true;
    for (var i = 0; i < bytes.length; i++) { if (p.add(i).readU8() !== bytes[i]) { ok = false; break; } }
    logMsg(ok ? 'PATCH' : 'WARN', '0x' + staticVA.toString(16) + ' <- ' + bytes.length + 'b' +
           (note ? ' (' + note + ')' : '') + ' verify=' + ok);
    return ok;
}
// Interceptor.attach(static_VA)。失敗ログを標準化。
function hook(staticVA, handlers, note) {
    try { Interceptor.attach(va(staticVA), handlers); }
    catch (e) { logMsg('WARN', 'hook 0x' + staticVA.toString(16) + (note ? ' (' + note + ')' : '') + ' fail: ' + e); }
}
// try/catch + tag 付き setInterval watchdog (runtime-blocker の再強制パターン)。
function watch(intervalMs, fn, note) {
    return setInterval(function () {
        try { fn(); } catch (e) { logMsg('WARN', 'watch' + (note ? ' (' + note + ')' : '') + ': ' + e); }
    }, intervalMs);
}
