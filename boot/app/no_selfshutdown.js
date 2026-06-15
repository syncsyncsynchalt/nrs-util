// subsys:      app
// persistence: persistent
// va:          0x6C3F20
// ssot:        app/FACTS.md ; mxdrivers/FACTS.md (eeprom が露見させた経緯)
// role:        ルートシステムシーンの self-shutdown を無力化（0x6C3F20 je→jmp）。amBackup/eeprom を
//              成功させると FUN_0089e880 の制御フラグ判定が true になり ATTRACT 前に clean 終了するのを防ぐ。

// ─────────────────────────────────────────────────────────────────────────────
// Root system-scene self-shutdown neutralization
//
// scene_list_init (0x89D690) sets the root scene's per-frame callback to LAB_006C3F10.
// That callback decides to shut the game down:
//   0x6C3F10  cmp [DAT_016f5a9c], 0
//   0x6C3F17  jne 0x6C3F31
//   0x6C3F19  call FUN_0089e880        ; "should we shut down?" (reads control flags
//                                        DAT_0227fe6c / DAT_0227fe70 & 4 / DAT_02282a64)
//   0x6C3F1E  test al, al
//   0x6C3F20  je  0x6C3F41             ; al==0 → skip shutdown   ← patched to JMP
//   0x6C3F22  mov [DAT_016f5a9c], 1
//   0x6C3F2C  call FUN_0089df40        ; FUN_0089df40 sets DAT_016f5aa0=1 → main loop
//                                        FUN_00644d40 exits → clean ExitProcess
//   0x6C3F31  cmp [DAT_016f5a9c], -1   ; (alt path) → 0x6C3F3A mov [DAT_016f5aa0],1
//   0x6C3F41  ...normal scene update...
//
// Captured live (suspended spawn + eeprom ON) via a DAT_016f5aa0 write probe:
//   *** FUN_0089df40 SET DAT_016f5aa0=1 *** bt= 0x6c3f31 <- 0x89df40 <- 0x6c3f31 <- 0x89da28 <- 0x89d7ba
//
// Root cause: with amBackup/amEeprom emulation succeeding, the game advances into the
// full "real cabinet" operation path where the app/scene controller's control flags
// (DAT_0227fe6c …) drive FUN_0089e880 to request shutdown. The flag writers live deep in
// the scene controller (0x89Exxx / 0x8Axxx, struct access — no direct xref). Per the boot's
// established approach (neutralize emulation-induced checks, cf. keychip/region.js), we
// disarm the self-shutdown so ATTRACT is reached. Patch: 0x6C3F20 `je 0x6C3F41` (74 1F) →
// `jmp 0x6C3F41` (EB 1F) — always skip the shutdown call (and the alt 0x6C3F3A path).
// Harmless when eeprom is off (FUN_0089e880 returns 0 there, so `je` was taken anyway).
// patchCode = persistent (survives Frida detach).
// ─────────────────────────────────────────────────────────────────────────────
(function noSelfShutdown() {
    try {
        var t = va(0x6C3F20);
        if (t.readU8() === 0x74) {                      // je rel8 — sanity check
            Memory.patchCode(t, 1, function (c) { c.writeByteArray([0xEB]); });  // → jmp rel8
            var ok = t.readU8() === 0xEB;
            logMsg('PATCH', 'root-scene self-shutdown disarmed (0x6C3F20 je→jmp) verify=' + ok);
        } else {
            logMsg('WARN', 'noSelfShutdown: unexpected byte at 0x6C3F20 = 0x' + t.readU8().toString(16) + ' (skip)');
        }
    } catch (e) { logMsg('WARN', 'noSelfShutdown patch: ' + e); }
})();
