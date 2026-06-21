// subsys:      app
// persistence: persistent
// va:          0x6C3F20
// ssot:        app/FACTS.md ; mxdrivers/FACTS.md (eeprom 関連)
// role:        ルートシステムシーンの self-shutdown を無力化（0x6C3F20 je→jmp）。amBackup/eeprom を成功させると
//              FUN_0089e880 の制御フラグ判定が true になり ATTRACT 前に clean 終了するのを防ぐ。詳細 app/FACTS.md。
//
// scene_list_init(0x89D690) がルートシーンの per-frame callback を LAB_006C3F10 に設定。callback は
// FUN_0089e880(「shut down すべきか」)が true だと FUN_0089df40 で DAT_016f5aa0=1 → main loop 終了→clean ExitProcess。
// 0x6C3F20 `je 0x6C3F41`(74 1F)→`jmp`(EB 1F) で常に shutdown 呼び出しを飛ばす。byte!=0x74 なら異常として skip。
(function noSelfShutdown() {
    var t = va(0x6C3F20);
    if (t.readU8() === 0x74) patch(0x6C3F20, [0xEB], 'root-scene self-shutdown disarmed (je->jmp)');
    else logMsg('WARN', 'noSelfShutdown: unexpected byte at 0x6C3F20 = 0x' + t.readU8().toString(16) + ' (skip)');
})();
