// subsys:      mxgfetcher
// persistence: runtime   // network_role=local
// va: 0x457FE0, 0x9746C0, 0x974760, 0x9747A0, 0x975140, 0x6FF980, 0x9744F0, 0x975857, 0x98ADC0, 0x458271
// ssot:        mxgfetcher/FACTS.md
// role:        HLSM state7→8 force (0x457FE0 onEnter) + result/parser patchCodes + 0x98ADC0 recv-completion fix。load-bearing のみ（純診断は diag.js）。runtime; detach で revert。Pairs with mxgfetcher/recv.js。

// amGfetcher get_status SM の強制（HLSM ドライバ）。load-bearing なパッチのみ。
//
// NOTE: 0x97718E / 0x9771CB は FUN_00977050（amInstall チャネル）内の strcmp 途中バイトで、
// [0x1287038] の init-flag CMP ではない。フックしない（0x97718E は命令途中で intercept
// 不可、0x9771CB は xref が無い）。ATTRACT 到達に init-flag の強制は不要。
(function patchAmGfetcher() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'patchAmGfetcher: nrs.exe not found'); return; }

    // 共有の boot 完了フラグ: HLSM が state-9→0 遷移を検出したら立てる。
    // FUN_6FF980 パッチが「boot」（return 1）から「attract」（return 0）へ切り替えるのに使う。
    var bootDone = 0;

    // 診断: FUN_00457FE0（high-level SM）
    // state 遷移ごと、加えて heartbeat として 500 tick ごとにログする。
    var hlsmCount = 0;
    var hlsmLastState = -1;
    try {
        Interceptor.attach(va(0x457FE0), {
            onEnter: function(args) {
                this.p1 = args[0];
                // ステートマシンの強制遷移（関数本体が走る前に適用）:
                //   param_1[0x14] = 現在の state（前 tick の値。first-switch がまだ走っていない）
                //   param_1[0x18] = 次の state（first-switch がこの tick で 0x14 に設定する値）
                // param_1[0x18] を狙い、この tick で実行されることになる state に作用する。
                try {
                    var nextSt0 = this.p1.add(0x18).readU32();
                    var tcpBsy  = this.p1.add(3).readU8();
                    // state7 → state8 を強制: case=7 は param_1[1]=1 の副作用を走らせ、P-ras
                    // state が完全に整っていないとクラッシュする。case=7 を丸ごと飛ばす
                    // （first-switch が走る前に next=8 を書く）のが安全な経路。
                    if (nextSt0 === 7 && tcpBsy === 0) {
                        this.p1.add(0x18).writeU32(8);
                    }
                    // state 4: isrelease=1 を強制しない。
                    // Path A（FUN_004573E0=1 かつ isrelease=1）→ auth-exit（game mode では誤り）。
                    // Path B（FUN_004573E0=0 または isrelease!=1）→ state 5 → get_status → game mode。
                    // 実 keychip が無ければ FUN_004573E0 は自然に 0 を返す → Path B が正しい。
                } catch(e) {}
            },
            onLeave: function(ret) {
                hlsmCount++;
                try {
                    var state    = this.p1.add(0x14).readU32();
                    var nextSt   = this.p1.add(0x18).readU32();
                    var tcpBusy  = this.p1.add(3).readU8();
                    var statInt  = this.p1.add(0xb4).readS32();
                    var result   = this.p1.add(4).readS32();
                    var released = this.p1.add(2).readU8();   // param_1[2]: auth 完了フラグ
                    var isrelRes = this.p1.add(0x24).readS32(); // param_1+0x24: isrelease の結果
                    var changed  = (state !== hlsmLastState);
                    // state-9 成功（next=0）を検出: boot シーケンス完了。
                    // FUN_006FF980 は常に 1 を返すよう patchCode 済み。0x458271 の NOP
                    // （GETSTATUS_FIX で適用）が state=0 の再 boot を防ぐ。
                    if (state === 9 && nextSt === 0 && !bootDone) {
                        bootDone = 1;
                        logMsg('HLSM', 'BOOT_DONE: state-9 set next=0, attract mode armed');
                    }
                    if (changed || state === 4 || state >= 6 || hlsmCount <= 10 || hlsmCount % 500 === 0) {
                        hlsmLastState = state;
                        logMsg('HLSM', '#' + hlsmCount + ' state=' + state + ' next=' + nextSt +
                               ' busy=' + tcpBusy + ' statusInt=' + statInt + ' result=' + result +
                               ' released=' + released + ' isrelRes=' + isrelRes +
                               (changed ? ' [TRANSITION]' : '') +
                               (bootDone ? ' [ATTRACT]' : ''));
                    }
                } catch(e) { logMsg('HLSM', 'read err: ' + e); }
            }
        });
        logMsg('INIT_DIAG', 'FUN_00457FE0 (high-level SM) hooked');
    } catch(e) { logMsg('WARN', 'FUN_00457FE0 hook: ' + e); }

    // patchCode: レスポンスパーサ群 → 常に return 0（永続。Frida detach 後も有効）
    // これらのパーサは PCPA レスポンスバッファ内のフィールドを探すのに FUN_58AAE0 を呼ぶ。
    // エミュレートしたレスポンスでは FUN_58AAE0 が null を返す → パーサが -5（エラー）を返し
    // pcpaSetSendPacket が 0 を返す → [0x1286FEC] チェック → attract モードで Error 0903
    // "Wrong Region"。よって 0 を返す必要がある。Interceptor.replace ではなく patchCode で
    // detach をまたいで維持する。
    //
    // バイト列: xor eax, eax (33 C0) + ret (C3) = 3 バイト → cdecl, return 0。
    var retZero3 = [0x33, 0xC0, 0xC3];
    [
        { name: 'FUN_009746C0 (resume parser)',       va: 0x9746C0 },
        { name: 'FUN_00974760 (isrelease case5)',     va: 0x974760 },
        { name: 'FUN_009747A0 (isrelease case10)',    va: 0x9747A0 },
        { name: 'FUN_00975140 (result= checker)',     va: 0x975140 },
    ].forEach(function(e) {
        try {
            Memory.patchCode(va(e.va), retZero3.length, function(c) {
                c.writeByteArray(retZero3);
            });
            logMsg('PATCH', e.name + ' → xor eax,eax; ret (patchCode, persistent)');
        } catch(ex) { logMsg('WARN', e.name + ' patchCode: ' + ex); }
    });

    // FUN_004573E0: パッチしない。
    // state4 path-A（FUN_004573E0=1 かつ isrelease=1）→ released=1 → foreground.next=1 → EXIT。
    // state4 path-B（FUN_004573E0=0 または isrelease!=1）→ state5 → get_status → game mode。
    // keychip が無ければ FUN_004573E0 は自然に 0 を返す → path-B → game mode。正しい。
    logMsg('PATCH', 'FUN_004573E0 not patched: natural 0 = state4 path-B = game mode');

    // patchCode: FUN_006FF980（HLSM state-0 ゲート） → 常に return 1（永続）
    // hlsm_region_check() は DAT_0210aed0/aed2/aed4 フラグを見る（ハードウェアが無いと 0）。
    // 初回 boot で state=0 の condition-A を発火させる（ctx.next=1）には 1 を返す必要がある。
    // 0x458271 の NOP（GETSTATUS_FIX で state=5→6 時に適用）が ctx.next=1 の書き込みを
    // 塞ぐ → return 値に関わらず state=0 は attract に留まる。
    // uint hlsm_region_check(void): 引数なし → ret (C3)。mov eax,1; ret = 6 バイト。
    try {
        Memory.patchCode(va(0x6FF980), 6, function(c) {
            c.writeByteArray([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]); // mov eax,1; ret
        });
        var ok980 = va(0x6FF980).readU8() === 0xB8;
        logMsg('PATCH', 'FUN_006FF980 → patchCode(mov eax,1; ret) persistent, verify=' + ok980);
    } catch(e) { logMsg('WARN', '0x6FF980 patchCode: ' + e); }

    // NOTE: state7→8 は 0x457FE0 onEnter の直接書き込み（case=7 が走る前に next=8）で駆動する。
    // FUN_006FF650（0x6FF650）は意図的にパッチしない。attach 中は冗長（detach 前に boot が
    // ATTRACT へ到達する）。

    // FUN_009744F0（TCP SM done チェック） → patchCode（永続・hang-safe）
    // sub-state 8 のクリーンアップがストリームを閉じる（[0x1286FF0]=0）と、native 9744F0 は
    // [0x1286FF0]=0 を見て [0x1287000]=0 ではなく -3 を返し、[ebp+4]=result を -3 に壊す。
    // result=-3 だと 0x45829C の間接テーブルが error-counter 経路（0x45805F）にマップし、
    // advance 経路（0x458043）に行かないため state=5 が state=6 へ進まない。同じ -3 が
    // FUN_00458330 によって esi[4]/esi[8]（error result）に格納される → Error 0903 経路。
    // Interceptor.replace ではなく patchCode で Frida detach をまたいで維持する。
    //
    // hang-safe: ストリームが閉じている（[0x1286FF0]==0）とき [0x1287000] は非ゼロのまま
    // 残りうる。素朴に「[0x1287000]!=0 の間 return 1=pending」とすると 9744F0 が永久に回り
    // → FUN_00458330 のループが抜けない → HLSM ストール → watchdog "Error 1000"。
    // そこでまずストリームポインタで分岐する: [0x1286FF0]==0（ストリーム閉）なら 0（done）を
    // 返し sub-state をリセットする。native ロジック:
    //     if ([0x1286FF0] == 0)      { [0x1286FF4]=0; return 0; }  // ストリーム閉 → done
    //     if ([0x1287000] != 0)      { return 1; }                 // pending
    //     [0x1286FF4]=0; return 0;                                 // done → reset
    // ecx = &[0x1286FF0]; [ecx+0x10]=[0x1287000]; [ecx+4]=[0x1286FF4]（連続配置）。
    // NOTE: この番地に Interceptor.attach はしない（detach 時の trampoline 復元が patchCode を
    // 上書きする）。GETSTATUS_FIX が [0x1287000]=0 を強制するのと両立する。
    // ハンドアセンブル（プロジェクト規約: X86Writer ではなく writeByteArray）。30 バイト、
    // 32B の関数フレームに収まる:
    //   off  bytes            insn
    //    0   B9 <ff0Addr>     mov ecx, &[0x1286FF0]
    //    5   8B 01            mov eax, [ecx]        ; stream ptr
    //    7   85 C0            test eax, eax
    //    9   74 07            jz  +7 (->18 ret0_reset) ; ストリーム閉 → done
    //   11   8B 41 10         mov eax, [ecx+0x10]   ; r=[0x1287000]
    //   14   85 C0            test eax, eax
    //   16   75 06            jnz +6 (->24 pending)
    //   18   31 C0            xor eax, eax          ; (ret0_reset)
    //   20   89 41 04         mov [ecx+4], eax      ; [0x1286FF4] = 0
    //   23   C3               ret                   ; return 0 (done)
    //   24   B8 01 00 00 00   mov eax, 1            ; (pending)
    //   29   C3               ret                   ; return 1
    try {
        var ff0Addr = va(0x1286FF0).toUInt32();  // &[0x1286FF0]
        var le = function(a) { return [a & 0xff, (a>>>8) & 0xff, (a>>>16) & 0xff, (a>>>24) & 0xff]; };
        var code = [0xB9].concat(le(ff0Addr))
                         .concat([0x8B, 0x01, 0x85, 0xC0, 0x74, 0x07,
                                  0x8B, 0x41, 0x10, 0x85, 0xC0, 0x75, 0x06,
                                  0x31, 0xC0, 0x89, 0x41, 0x04, 0xC3,
                                  0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]);
        Memory.patchCode(va(0x9744F0), code.length, function(c) {
            c.writeByteArray(code);
        });
        logMsg('PATCH', '0x9744F0 patchCode (persistent hang-safe, ' + code.length + 'b): stream==0→ret0; else r!=0→ret1; r==0→reset+ret0');
    } catch(e) { logMsg('WARN', '0x9744F0 patchCode: ' + e); }

    // FUN_00975830 pause SM の strBusy スタック
    // HLSM 前の init で呼ばれる 975830(arg=0) はフルの同期 pause 交換を行い [0x1286FF4]=1 を
    // 残す。state=9 ハンドラは 975830(arg=1) を呼び、strBusy=1 を見て永久に 1（busy）を返す。
    // 0x975857 のバイト列: B8 01 00 00 00 (mov eax,1) C2 04 00 (ret 4) → busy 経路。
    // 0x975857 を EB 06（jmp to 0x97585F）でパッチ → strBusy チェックを飛ばし、常に send 経路
    // （0x98AB20 同期交換）へ進む。Send が 0 を返す → state=9 ハンドラが next=0, tcpBusy=1 を
    // 設定 → attract モード。
    try {
        Memory.patchCode(va(0x975857), 2, function(c) {
            c.writeByteArray([0xEB, 0x06]); // jmp to 0x97585F (send path)
        });
        logMsg('PATCH', '0x975857 patched: bypass strBusy check in pause SM');
    } catch(e) { logMsg('WARN', '0x975857 patch: ' + e); }

    // 0x98ADC0（PCPA recv poll） → get_status recv 後に ret=1 を強制
    // ポート 40113 は raw winsock recv() を使う。raw recv 経路では 0x98DAB0 が 1 を返さない
    // → 0x98ADC0 が常に 0 を返す → [stream+0x21C] が 0 のまま → 0x98B260 が 0 を返す
    // → 0x574510 の pending 経路が発火 → SM が永久に再送する。
    // raw recv() が get_status レスポンスを捕捉したら（recv フックでフラグを立てる）、
    // 0x98ADC0 に一度だけ 1 を返させる → 0x98B260 が [stream+0x21C]=1 を書く → 1 を返す
    // → 0x574510 が done 経路（je 0x574533）を取る → SM がきれいに進む。
    // 静的解析: 0x98ADC0 入力=1 → ジャンプテーブル index 17 → 0x98ADD2 = ret 1。
    try {
        Interceptor.attach(va(0x98ADC0), {
            onLeave: function(r) {
                if (getStatusRecvDone) {
                    logMsg('GETSTATUS_FIX', '0x98ADC0 forced 0→1 (was ' + r.toInt32() + ')');
                    r.replace(1);
                    getStatusRecvDone = false;
                    // [0x1287000]=0 を強制し、置換した FUN_009744F0 が同 tick で 0 を返すようにする。
                    try {
                        va(0x1287000).writeU32(0);  // [0x1287000] = 0
                        logMsg('GETSTATUS_FIX', '[0x1287000] forced 0 → next 9744F0 returns 0');
                    } catch(e) { logMsg('WARN', 'GETSTATUS_FIX [1287000]: ' + e); }
                    // NOTE: ここで FUN_006FF980 はパッチしない（同番地への Interceptor.replace が
                    // detach 時に patchCode を上書きする）。再 boot は下の 0x458271 の NOP で防ぐ。
                    // detach 後: FUN_006FF980 は自然に 0 を返す（ハードウェアフラグ未設定）ので
                    // state=0 condition A はいずれにせよ false。NOP が condition B と C を処理する。
                    // state=0 の advance を恒久的に NOP 化: 0x458271 の ctx.next=1 書き込みをパッチ。
                    // state=0 ハンドラ（0x458237）には 3 つの再 boot 条件がある:
                    //   A. FUN_006FF980()!=0（上で修正済み）
                    //   B. DAT_0210B508!=0（[0x210B508] は init 中に設定され detach 後も残る）
                    //   C. counter >= threshold（ctx+0x10 は毎 tick 増加。時間経過で再 boot）
                    // 3 つは全て 0x458271: 89 5D 18 (mov [ebp+0x18], ebx → ctx.next=1) に収束する。
                    // NOP×3 で、detach 後にどの条件も state=0 → state=1 へ進めないようにする。
                    // ここ（state=5→6 遷移）で適用 = 初回 boot 後・attract 前。
                    try {
                        Memory.patchCode(va(0x458271), 3, function(c) {
                            c.writeByteArray([0x90, 0x90, 0x90]); // NOP: ctx.next=1 を塞ぐ
                        });
                        logMsg('GETSTATUS_FIX', '0x458271 NOP×3 → state=0 advance blocked (DAT_210B508 + counter-timeout fix)');
                    } catch(e) { logMsg('WARN', 'GETSTATUS_FIX patchCode 458271: ' + e); }
                }
            }
        });
        logMsg('PATCH', '0x98ADC0 onLeave hooked (get_status recv completion fix)');
    } catch(e) { logMsg('WARN', '0x98ADC0 hook: ' + e); }
})();
