// subsys:      mxkeychip
// persistence: runtime   // network_role=local
// va: —
// ssot:        mxkeychip/FACTS.md
// role:        keychipSM setup を駆動して補助（DAT_016014a2 ラッチ等を satisfy 維持）。runtime

// keychip コンテキストが真正に認証済みのときは常に DAT_016014a2（keychip-present
// フラグ）= 1 に保持し、TeknoParrot の「boot から present」終状態に一致させる。
//
// このフラグは一方向ラッチ: amDongleUpdate (FUN_00970fc0) が一度でも非ゼロを返すと
//（boot ウィンドウ中の過渡）FUN_00459460 が 0 にクリアし、1 へ戻る経路は無い。
// 一度 a2=0 になると FUN_006f0a80 が a2==0 を読んで amlib errCode 1 をラッチ →
// 固着 "Error 0949 Keychip Not Found"（descriptor が空だと "Error 1000" も）。
// コンテキストは実際には認証済み（ctx+4/+8/+0x10=1、amDongleUpdate ret=0、
// MAC/SSD verify pass）で、ラッチだけが誤っている。
//
// suppress でなく satisfy: FUN_006f0a80.onEnter（errCode 1 をラッチする consumer）で
// keychip が真正に present なら（ctx+4 && ctx+8。FUN_0096c5d0 が使うテスト）a2=1 を
// 再表明し、読まれる前にフラグを正す。ゲーム main スレッドの毎回 call で走るので、
// 一方向ラッチも継続的に上書きする。errCode ストアや error-display コードには触れない。
//   FUN_006f0a80: CMP [0x016014a2],0 ; JZ latch_error
(function holdKeychipPresent() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'holdKeychipPresent: nrs.exe not found'); return; }

    var a2 = va(0x16014A2);          // DAT_016014a2 keychip-present flag
    var ctxPtr = va(0xCCF000);       // PTR_DAT_00ccf000 keychip context pointer

    function genuinePresent() {
        try {
            var c = ctxPtr.readPointer();
            if (c.isNull()) return false;
            // ctx+4 && ctx+8（FUN_0096c5d0（keychip-present プリミティブ）と同じテスト）。
            return c.add(0x4).readU32() !== 0 && c.add(0x8).readU32() !== 0;
        } catch(e) { return false; }
    }

    var forced = 0;
    try {
        Interceptor.attach(va(0x6F0A80), {   // FUN_006f0a80 (errCode-1 latcher)
            onEnter: function() {
                try {
                    if (genuinePresent() && a2.readU8() === 0) {
                        a2.writeU8(1);                 // 真正な keychip presence を反映
                        forced++;
                        if (forced <= 5 || forced % 2000 === 0) {
                            logMsg('KCHOLD', 'keychip genuinely present (ctx+4/+8!=0); held DAT_016014a2=1 (#' + forced + ')');
                        }
                    }
                } catch(e) {}
            }
        });
        logMsg('INIT_KCHOLD', 'holdKeychipPresent armed at FUN_006f0a80 (a2=1 when keychip genuinely present)');
    } catch(e) { logMsg('WARN', 'holdKeychipPresent attach 0x2F0A80: ' + e); }
})();
