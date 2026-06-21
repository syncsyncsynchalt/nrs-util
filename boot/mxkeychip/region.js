// subsys:      mxkeychip
// persistence: runtime   // network_role=local
// va: 0x986A66, 0x986A74, 0x986A92 (region SM jne NOP), 0x97588A, 0x97595F, 0x975A1F (isrelease jl->jmp), 0x459109, 0x45A846 (errCode=4 store NOP), 0x458FD0, 0x45A7F0 (region check hooks), 0x98A5F0 (error-display diag hook), 0x16014C4, 0x1601744, 0x1601989 (DAT/watchdog)
// ssot:        mxkeychip/FACTS.md
// role:        Error 0903(region) を TeknoParrot 方式=チェック無力化で恒久解消（amlib region setter の
//              errCode=4 ストア2箇所を NOP）。PcbRegion=JAPAN(01) data-write は anti-tamper(FUN_0048f9c0)の
//              region-index 整合用に維持。NOP/DAT書込=永続(patchCode/data) / watchdog と診断=runtime(他コード safety-net)

// Error 0903 (region) 修正。TP 方式: 本物の keychip 証明書データを供給せず、region
// チェック自体を無力化する。4 層、全て永続（patchCode / data）:
//   1. outer keychip-region SM から出る jne を NOP（0x986A66/74/92）。
//   2. isrelease SM の error-display 分岐を jl→jmp（0x97588A/5F/A1F）。
//   3. amlib region setter の errCode=4 ストアを NOP（0x459109/0x45A846）。
//   4. data 書込で region=JAPAN を強制 + watchdog で master errCode をクリア。
(function patchRegionCheck() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'patchRegionCheck: nrs.exe not found'); return; }

    // outer keychip-region SM から Error 09xx へ飛ぶ jne を NOP（チェックの戻り値に
    // 関わらずジャンプを潰す）:
    //   0x986A66: 0F 85 E3 00 00 00  jne 0x986B4F  -> Error 0x381
    //   0x986A74: 0F 85 04 01 00 00  jne 0x986B7E  -> Error 0x387 (0903 Wrong Region)
    //   0x986A92: 0F 85 15 01 00 00  jne 0x986BAD  -> Error 0x38D
    var nop6 = [0x90,0x90,0x90,0x90,0x90,0x90];
    [
        { name: '0x986A66 jne->0x381',  va: 0x986A66, code: nop6 },
        { name: '0x986A74 jne->0x387',  va: 0x986A74, code: nop6 },
        { name: '0x986A92 jne->0x38D',  va: 0x986A92, code: nop6 },
    ].forEach(function(e) {
        try {
            Memory.patchCode(va(e.va), e.code.length, function(c) {
                c.writeByteArray(e.code);
            });
            logMsg('INIT_REGION', e.name + ' NOP6 patched');
        } catch(ex) { logMsg('WARN', 'patchRegionCheck NOP ' + e.name + ': ' + ex); }
    });
    logMsg('INIT_REGION', 'region jump NOP patches installed (3 jumps)');

    // isrelease SM sub-state の error display バイパス
    // isrelease SM（FUN_00975830 周辺）には、同期 PCPA 交換後に [0x1286FEC] >= 1 だと
    // error display を呼ぶ sub-state ハンドラが 3 つある:
    //   RVA 0x57588A: jl → Error 0x2EB (747, "Wrong Region" 系)
    //   RVA 0x57595F: jl → Error 0x31E (798, "Wrong Region" 系)
    //   RVA 0x575A1F: jl → Error 0x387 (903, "Wrong Region")
    // 3 つとも: cmp [0x1286FEC], 1; jl skip_error; push errCode; call 0x98A5F0
    // pcpaSend/pcpaRecv フックが無効だと、実際の交換が [0x1286FEC] に非ゼロ結果を
    // 書き込み → Error 0903 が表示される（永続 Win32 ウィンドウ）。
    // 各サイトで jl (7C 17) → jmp (EB 17) に変える（patchCode、永続）: jmp は
    // [0x1286FEC] の値に関わらず常に error display をスキップする。
    [
        { name: '0x97588A jl->jmp (err747)', va: 0x97588A },
        { name: '0x97595F jl->jmp (err798)', va: 0x97595F },
        { name: '0x975A1F jl->jmp (err903)', va: 0x975A1F },
    ].forEach(function(e) {
        try {
            Memory.patchCode(va(e.va), 2, function(c) {
                c.writeByteArray([0xEB, 0x17]); // jl → jmp: error display を常にスキップ
            });
            logMsg('INIT_REGION', e.name + ' patched (patchCode persistent)');
        } catch(ex) { logMsg('WARN', 'patchCode ' + e.name + ': ' + ex); }
    });

    // amlib init region setter の errCode=4 ストアを NOP 化（TP 方式＝チェック無力化）
    // region ゲートは FUN_00458fd0 / FUN_0045a7f0 の2関数:
    //   if ((DAT_016014c4 & (DAT_016014a2 ? DAT_01601989 : 0) & 5) == 0)
    //       if (DAT_016f5af0 == 0) DAT_016f5af0 = 4;   // → on-screen Error 0903
    //   PcbRegion(DAT_016014c4) はバイナリ内に writer が無く（全 xref READ）、本構成では 0 のまま
    //   → ゲート FAIL 不可避。下の forceRegion で 01 を data-write するが、458fd0 がその着弾より前に
    //   走ると errCode 4 を display struct(DAT_016f5a80)へ snapshot して固着しうる（timing-fragile）。
    //   そこでストア `MOV [0x016f5af0],4`（C7 05 + addr4 + imm4 = 10B）自体を NOP 化する。呼び出し元
    //   (FUN_006c3730/FUN_00643de0) は戻り値を捨てるので、制御フローと戻り値はどちらも不変。patchCode=永続。
    //   0x459109: FUN_00458fd0 の errCode=4 ストア（早期に走る本命の latcher）
    //   0x45A846: FUN_0045a7f0 の errCode=4 ストア（errCode は同一。防御的に併せて潰す）
    var nop10 = [0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90];
    [
        { name: '0x459109 errCode=4 store (FUN_00458fd0)', va: 0x459109 },
        { name: '0x45A846 errCode=4 store (FUN_0045a7f0)', va: 0x45A846 },
    ].forEach(function(e) {
        try {
            var t = va(e.va);
            Memory.patchCode(t, 10, function(c) { c.writeByteArray(nop10); });
            var ok = true;
            for (var i = 0; i < 10; i++) if (t.add(i).readU8() !== 0x90) { ok = false; break; }
            logMsg('INIT_REGION', e.name + ' → NOP10 (errCode 4 latch killed, TP-style) verify=' + ok);
        } catch(ex) { logMsg('WARN', 'patchCode region setter ' + e.name + ': ' + ex); }
    });

    // log のみ: error display 0x98A5F0 を errCode + backtrace 付きで記録（上のパッチが
    // 取りこぼした呼び出し元を露見させる）。
    try {
        Interceptor.attach(va(0x98A5F0), {
            onEnter: function(args) {
                var errCode = 0, bt = '';
                try { errCode = this.context.esp.add(4).readU32(); } catch(e) {}
                try {
                    bt = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0,5)
                             .map(function(f){ return '0x'+f.toString(16); }).join('<-');
                } catch(e) {}
                logMsg('ERR_DISPLAY', 'errCode=0x' + errCode.toString(16) + '(' + errCode + ') bt=' + bt);
            }
        });
        logMsg('INIT_REGION', '0x98A5F0 (error display) hooked for diag');
    } catch(e) { logMsg('WARN', 'hook 0x58A5F0: ' + e); }

    // forceRegion: region オペランドを JAPAN に data 書込 + diag フック
    // 上の NOP10 の後ろ盾: gate オペランドを強制してチェックも通るようにする。
    // DAT_016014c4 (PcbRegion) はバイナリ内に writer が無い → 0 のまま; Frida の data
    // 書込は detach 後も残る。オペランド (static_VA):
    //   0x16014C4 game/PCB region、0x1601744 cached region、0x1601989 dongle region
    //   0x16014A2 gate、0x16F5AF0 master errCode
    function forceRegion() {
        try {
            va(0x16014C4).writeU8(0x01);   // DAT_016014c4 = JAPAN (game/PCB region)
            va(0x1601744).writeU8(0x01);   // DAT_01601744 = JAPAN (c4 との比較用)
            va(0x1601989).writeU8(0x01);   // DAT_01601989 = JAPAN (dongle region)
            // 早期にも強制する: 通常は keychip setup の後に pcpa keychip.appboot.region
            // から populate されるが、その早期ウィンドウでは dongle=0 → (c4 & 0 & 5)==0 →
            // errCode 4 → device シーンが片付いた後に浮上する固着 "Error 0903 Wrong Region"
            // シーンになる。0x01 に保持してこの隙間を塞ぐ。
        } catch(e) {}
    }
    forceRegion();   // 即時; data 書込は detach 後も残る
    function logRegion(tag) {
        try {
            var gameR   = va(0x16014C4).readU8();
            var dongleR = va(0x1601989).readU8();
            var gate    = va(0x16014A2).readU8();
            var eff     = gate ? dongleR : 0;
            var anded   = gameR & eff & 5;
            var err     = va(0x16F5AF0).readU32();
            logMsg('REGION_CHK', tag + ' game=0x' + gameR.toString(16) +
                   ' dongle=0x' + dongleR.toString(16) + ' gate=' + gate +
                   ' (game&eff&5)=0x' + anded.toString(16) +
                   ' -> ' + (anded !== 0 ? 'PASS' : 'FAIL') + ' errCode=' + err);
        } catch(e) { logMsg('WARN', 'logRegion ' + tag + ': ' + e); }
    }
    var diag458fd0 = 0;
    try {
        Interceptor.attach(va(0x458FD0), {
            onEnter: function() { forceRegion(); },
            onLeave: function() { if (diag458fd0++ < 3) logRegion('458fd0#' + diag458fd0); }
        });
        logMsg('INIT_REGION', '0x458FD0 (amlib region check 1) hooked: force+log');
    } catch(e) { logMsg('WARN', 'hook 0x458FD0: ' + e); }
    var diag45a7f0 = 0;
    try {
        Interceptor.attach(va(0x45A7F0), {
            onEnter: function() { forceRegion(); },
            onLeave: function() { if (diag45a7f0++ < 5) logRegion('45a7f0#' + diag45a7f0); }
        });
        logMsg('INIT_REGION', '0x45A7F0 (amlib region check 2) hooked: force+log');
    } catch(e) { logMsg('WARN', 'hook 0x45A7F0: ' + e); }

    // Watchdog: region を強制保持 + master errCode DAT_016f5af0 をクリア
    // 上で無力化していない errCode setter（0xa board-table / 0x14 network 等）の
    // safety-net + forceRegion を適用し続ける。DAT_016f5af0 は amlib init の errCode
    //（struct DAT_016f5a80 のフィールド、init は FUN_006c35c0）; init チェックは
    // hw/platform 不在で立てる:
    //   2/3/7=platform(amPlatformGetPlatformId!="AAL"), 4=region, 6=amStorage,
    //   10=board-table, 0xb/0xd/0xe/0x14-0x18=他の device/config チェック。
    // pure-Frida バイパスではいくつか fail する（"AAL" でなく "RingEdge" を返す、本物の
    // board table が無い）→ 最初の失敗がコードをラッチ → on-screen Error 09xx。display は
    // struct ポインタ経由で読む（名前ではパッチ不可）ので、tick 毎にクリアする
    //（data 書込は detach 後も残る）。distinct なコードを log する。
    var lastErrCode = 0;
    setInterval(function() {
        forceRegion();
        try {
            var e = va(0x16F5AF0).readU32();
            if (e !== 0) {
                if (e !== lastErrCode) {
                    logMsg('ERRCODE', 'DAT_016f5af0 latched ' + e + ' (0x' + e.toString(16) + ') -> cleared');
                    lastErrCode = e;
                }
                va(0x16F5AF0).writeU32(0);   // amlib init エラーを全クリア（hw 不在の副産物）
            }
        } catch(ex) {}
    }, 250);
})();
