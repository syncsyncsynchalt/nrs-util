// subsys:      devices
// persistence: persistent
// va:          0x4F6310, 0x8B3B00, 0x6F0B80
// ssot:        ./FACTS.md
// role:        周辺デバイス presence 連鎖の固定応答（IC Card R/W・Touch Panel・USB I/O）。
(function devicesPresence() {
    patch(0x4F6310, RET1, 'IC Card R/W ready bit1 -> 1 (responded; Error 5101, state2)');
    patch(0x8B3B00, RET1, 'Touch Panel status -> 1 (responded; Error 5501, state3)');
    patch(0x6F0B80, [0x00], 'USB I/O board errCode imm 0F->00 (FUN_006f0ad0; Error 951 non-fatal)');
})();
