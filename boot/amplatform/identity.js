// subsys:      amplatform
// persistence: persistent   // network_role=local
// va: 0x981D60, 0x981FF0, 0x982C50
// ssot:        amplatform/FACTS.md
// role:        amPlatform GetOsVersion/PlatformId/BoardType を WindowsXP/AAL/0 に patchCode（Error 0901 回避）。永続

// ─────────────────────────────────────────────────────────────────────────────
// amPlatform hooks — TeknoParrot inline-patches these with JMP to its own code
// We hook BEFORE the JMP to capture what nrs.exe originally requested,
// and AFTER (onLeave) to capture what TeknoParrot returned.
// RVAs confirmed by VirtualProtect capture (size 1+4 inline patch pattern)
// ─────────────────────────────────────────────────────────────────────────────
(function hookAmPlatform() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'amPlatform hook: nrs.exe not found'); return; }

    // amPlatformGetOsVersion(buf, bufLen)  — stdcall(char* buf) → writes OS version string
    // amPlatformGetPlatformId(buf, bufLen) — stdcall(char* buf) → writes platform ID string
    // amPlatformGetBoardType(DWORD* out)   — stdcall(DWORD* out) → writes board type index 0-3
    //
    // IMPORTANT: amPlatformGetPlatformId must return "AAL" (real RingEdge board ID), NOT
    // "RingEdge" (a display name). Multiple callers compare it against "AAL"/"AAM"/"NEC"
    // hardware IDs (e.g. at RVA 0x582CD8, 0x583034, 0x5A743). Returning "RingEdge" fails
    // all comparisons and triggers Error 0901 "Wrong Platform" via 0x491ACE after SM exit.
    //
    // amPlatformGetBoardType (0x582C50) uses a DIFFERENT calling convention: it takes a
    // DWORD* output pointer (not char* buf), and callers read it as an integer index 0-3
    // for a jump table (at 0x982F61). Writing a string ("RingEdge") into that DWORD corrupts
    // it to 0x676E6952 (>"3"), causing the caller at 0x582F40 to return NULL.
    var APF = {
        amPlatformGetOsVersion:  0x981D60,
        amPlatformGetPlatformId: 0x981FF0,
        amPlatformGetBoardType:  0x982C50,
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

            Memory.patchCode(va(sva), code.length, function(c) {
                c.writeByteArray(code);
            });
            logMsg('amPlatform', name + ' patchCode(' + code.length + 'b)="' + fillStr + '"');
        } catch(e) { logMsg('WARN', 'amPlatform patchCode ' + name + ': ' + e); }
    }

    // patchBoardTypeFunc: patchCode for amPlatformGetBoardType (0x582C50).
    // Different from patchPlatformFunc: writes a DWORD integer (not string) to *[esp+4].
    // Board type 0 selects the first entry in the lookup table at 0xADFB88 (jump table index).
    function patchBoardTypeFunc(name, sva, boardTypeIndex) {
        try {
            var idx = boardTypeIndex & 0xFF;
            var code = [
                0x8B, 0x44, 0x24, 0x04,   // mov eax, [esp+4]  ; arg1 = DWORD* output
                0xC7, 0x00,               // mov dword ptr [eax],
                idx, 0x00, 0x00, 0x00,    //   boardTypeIndex (imm32 LE)
                0x33, 0xC0,               // xor eax, eax      ; return 0
                0xC2, 0x04, 0x00,         // ret 4
            ];
            Memory.patchCode(va(sva), code.length, function(c) {
                c.writeByteArray(code);
            });
            logMsg('amPlatform', name + ' patchCode(DWORD=' + boardTypeIndex + ', ' + code.length + 'b)');
        } catch(e) { logMsg('WARN', 'amPlatform patchCode ' + name + ': ' + e); }
    }

    patchPlatformFunc('amPlatformGetPlatformId', APF.amPlatformGetPlatformId, PLATFORM_ID);
    patchPlatformFunc('amPlatformGetOsVersion',  APF.amPlatformGetOsVersion,  OS_VERSION);
    patchBoardTypeFunc('amPlatformGetBoardType', APF.amPlatformGetBoardType,  0);

    logMsg('INIT_AMPLATFORM', 'amPlatform patchCode installed (persistent): platformId="AAL" boardType=0');
})();
