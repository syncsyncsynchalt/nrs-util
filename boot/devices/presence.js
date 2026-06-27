// subsys:      devices
// persistence: persistent
// va:          0x4F6310, 0x8B3B00, 0x6F0B80, 0x45A0F5, 0x45A0F9
// ssot:        ./FACTS.md
// role:        周辺デバイス presence 連鎖の固定応答（IC Card R/W・Touch Panel・USB I/O ＋ dipsw/board index）。
(function devicesPresence() {
    patch(0x4F6310, RET1, 'IC Card R/W ready bit1 -> 1 (responded; Error 5101, state2)');
    patch(0x8B3B00, RET1, 'Touch Panel status -> 1 (responded; Error 5501, state3)');
    patch(0x6F0B80, [0x00], 'USB I/O board errCode imm 0F->00 (FUN_006f0ad0; Error 951 non-fatal)');
    // dipsw を実基板の clean 値で供給（TP 方式＝ハード読みの値供給）。FUN_0045a0e0 は
    // amDipswReadByte(FUN_00984190/FUN_00984130→FUN_009836e0) で byte2/byte3 を読み、そこから
    // board index `DAT_01601953=(byte3>>4)&7` と flag `DAT_0160194c`(test/service スイッチ群)を導く。
    // スタンドアロンは dipsw ドライバ不在で読み失敗→bytes が garbage:
    //   ・index garbage → board-table DAT_00b84554[index]!=8 → errCode 0xa(FUN_00679cb0) latch
    //   ・DAT_0160194c&0x20 garbage → errCode 0xb（0xa を消すと latch race で surface）
    // 2つの byte ロード命令を実基板の値に固定（MOV r8,[esp+N]→MOV r8,imm + NOP*2）:
    //   byte2(CL)=3: FUN_00984190 が成功時に *p=3 とハードコードする値。DAT_0160194c bit0x1/0x2。
    //   byte3(AL)=0x20: board index 2（table[2]==8 を満たす唯一値）＋ test/service スイッチ全 OFF。
    //     既存の `SHR AL,4; AND AL,7` がこの 0x20 から index 2 を自然算出、bit0x8(=flag0x20)=0 で 0xb 回避。
    // これで index・flag とも実基板と一致し errCode 0xa/0xb を源流で解消（FUN_006c5470 の 0x11/0x1e も）。
    patch(0x45A0F5, [0xB1, 0x03, 0x90, 0x90], 'dipsw byte2 -> 3 (FUN_0045a0e0; real-board hardcoded value)');
    patch(0x45A0F9, [0xB0, 0x20, 0x90, 0x90], 'dipsw byte3 -> 0x20 (board index 2 + test SW off; errCode 0xa/0xb 源流解消)');
})();
