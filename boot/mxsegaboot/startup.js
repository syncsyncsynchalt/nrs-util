// subsys:      mxsegaboot
// persistence: persistent
// va:          0x72B3A0, 0x701280
// ssot:        ./FACTS.md
// role:        SYSTEM STARTUP ゲート: EXTEND IMAGE install 完了(state5) + P-ras ready(state7)。
(function mxsegabootStartup() {
    patch(0x72B3A0, [0x31, 0xC0, 0x85, 0xF6, 0x74, 0x02, 0x89, 0x06, 0xB0, 0x04, 0xC3],
          'FUN_0072b3a0 EXTEND IMAGE install -> ret 4 (done) + *ESI=0 (success); state5 必須');
    patch(0x701280, [0xB0, 0x01, 0xC3], 'FUN_00701280 P-ras ready -> mov al,1;ret (FreePlay; state7)');
})();
