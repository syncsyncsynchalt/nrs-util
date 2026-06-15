// subsys:      devices
// persistence: persistent   // network_role=local
// va: 0x6F0B80
// ssot:        devices/FACTS.md
// role:        USB I/Oボード未検出 errCode 0xf を 0 に（0x2f0b80 imm 0F→00, Error 951）。永続

// ─────────────────────────────────────────────────────────────────────────────
// USB I/O board (838-15069 control board) — absent-but-non-fatal (TP-equiv, PERSISTENT).
//
// "USB Device Not Found" (errNo 951, amlib errCode 0xf) is the USB-connected NRS
// control I/O board (analog sticks + buttons), micetools ser_servo_838-15069.c. On a PC it
// can't be USB-enumerated, so the connected count DAT_016b88dc stays 0 and FUN_00679de0/
// FUN_0067a670 set the I/O status DAT_016b7000 = -112. The sole consumer that turns that
// into an error code is FUN_006f0ad0:
//   006f0b7f  MOV ECX,0xf            ← default (unrecognized/absent I/O status)
//   006f0b91  MOV [0x016f5af0],ECX   ← amlib errCode = 0xf  → errNo 951
// (the recognized statuses set ECX=0x10/0x11 at separate sites and are NOT touched.)
//
// TeknoParrot runs BBS without requiring this peripheral to fault. PERSISTENT fix
// (survives Frida detach — the earlier board-present Interceptor reverted on detach):
// patch the default-case immediate MOV ECX,0xf → MOV ECX,0 (imm byte 0F→00 at RVA 0x2f0b80),
// so an absent control board reports "no error" instead of errCode 0xf. Stick/button input
// is a separate read path (injected when needed); for attract the board is simply non-fatal.
// ─────────────────────────────────────────────────────────────────────────────
(function emulateUsbIoBoard() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'emulateUsbIoBoard: nrs.exe not found'); return; }

    // FUN_006f0ad0 default case: MOV ECX,0xf (B9 0F 00 00 00) at 0x6f0b7f; imm low byte at
    // RVA 0x2f0b80. Patch 0F→00 so the absent-board branch sets errCode 0 instead of 0xf.
    var sva = 0x6F0B80;
    try {
        var t = va(sva);
        var before = t.readU8();
        Memory.patchCode(t, 1, function(c) { c.writeByteArray([0x00]); });
        var after = t.readU8();
        logMsg('USBIO', 'FUN_006f0ad0 errCode imm 0x' + before.toString(16) + '→0x' + after.toString(16) +
               ' @va 0x' + sva.toString(16) + (before === 0x0f ? '' : ' [WARN: expected 0x0f]'));
        logMsg('INIT_USBIO', 'USB I/O board absent → non-fatal (errCode 0xf disabled, patchCode persistent). errNo 951 should not arm.');
    } catch(e) { logMsg('WARN', 'emulateUsbIoBoard patchCode 0x2f0b80: ' + e); }
})();
