// subsys:      amplatform
// persistence: persistent   // network_role=local
// va: 0x981D60, 0x981FF0
// ssot:        amplatform/FACTS.md
// role:        amPlatform GetOsVersion/PlatformId を WindowsXP/AAL に patchCode（platform gate FUN_0045a6f0 回避）。永続

// ─────────────────────────────────────────────────────────────────────────────
// amPlatform identity — patchCode-replace the string getters so the platform gate
// FUN_0045a6f0 (reads PlatformId + OsVersion; latches errCode 2/3 on mismatch) sees
// the values a real RingEdge would report. Persistent (survives detach).
// ─────────────────────────────────────────────────────────────────────────────
(function hookAmPlatform() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'amPlatform hook: nrs.exe not found'); return; }

    // amPlatformGetOsVersion(buf,bufLen) / amPlatformGetPlatformId(buf,bufLen): stdcall,
    // write a string into char* buf. patchCode-replaced below.
    // PlatformId MUST be "AAL" (real RingEdge board ID), not the display name "RingEdge":
    // callers compare it against "AAL"/"AAM"/"NEC", so "RingEdge" fails all → Error 0901
    // "Wrong Platform" (via 0x491ACE) after SM exit.
    var APF = {
        amPlatformGetOsVersion:  0x981D60,
        amPlatformGetPlatformId: 0x981FF0,
    };

    // Platform ID: "AAL" is the RingEdge hardware board code used by nrs.exe comparisons.
    var PLATFORM_ID  = 'AAL';       // hardware board ID (compared against "AAL"/"AAM"/"NEC")
    var OS_VERSION   = 'WindowsXP'; // OS version string

    // patchPlatformFunc: persistent patchCode for string-returning platform functions.
    // Writes fillStr (null-terminated) to *[esp+4] (buf arg), returns 0.
    function patchPlatformFunc(name, sva, fillStr) {
        try {
            var strBytes = [];
            for (var i = 0; i < fillStr.length; i++) strBytes.push(fillStr.charCodeAt(i) & 0xFF);
            strBytes.push(0); // null terminator

            // mov eax, [esp+4]
            var code = [0x8B, 0x44, 0x24, 0x04];
            for (var i = 0; i < strBytes.length; i++) {
                if (i === 0) {
                    code.push(0xC6, 0x00, strBytes[i]); // mov byte [eax], val
                } else {
                    code.push(0xC6, 0x40, i, strBytes[i]); // mov byte [eax+i], val
                }
            }
            code.push(0x33, 0xC0);       // xor eax, eax  (return 0)
            code.push(0xC2, 0x04, 0x00); // ret 4

            patch(sva, code, name + '="' + fillStr + '"');
        } catch(e) { logMsg('WARN', 'amPlatform patchCode ' + name + ': ' + e); }
    }

    // NOTE: amPlatformGetBoardType (0x982C50) is intentionally NOT patched — and must not be:
    // it takes a DWORD* out (index 0-3 for a jump table at 0x982F61), so writing a string
    // would corrupt the index. The platform gate FUN_0045a6f0 reads only PlatformId +
    // OsVersion, never BoardType; its sole consumer amBackup_getAreaDescriptor (0x982F40)
    // does not gate attract.

    patchPlatformFunc('amPlatformGetPlatformId', APF.amPlatformGetPlatformId, PLATFORM_ID);
    patchPlatformFunc('amPlatformGetOsVersion',  APF.amPlatformGetOsVersion,  OS_VERSION);

    logMsg('INIT_AMPLATFORM', 'amPlatform patchCode installed (persistent): platformId="AAL"');
})();
