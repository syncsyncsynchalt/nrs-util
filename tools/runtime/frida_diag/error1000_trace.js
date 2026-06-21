
// Error 1000 トリガ診断: FUN_006f2730 (RVA 0x2f2730) をフック。観測のみ。
//
// FUN_006f2730 = ゲームアプリのエラー描画関数:
//   void FUN_006f2730(int param_1)   // cdecl、スタック引数 1 個
//     msgPtr = *(param_1 + 0xc);     // char* message。NULL → デフォルト経路
//     errNo  = *(param_1 + 0x10);    // uint16 エラー番号 (msgPtr!=0 のときだけ読む)
//     flags  = *(param_1 + 0x16);    // byte。(&4)!=0 → "Caution" それ以外 "Error"
//   msgPtr==0 → "Error 1000\n\nUnknown Application Error"。
//
// 呼び出し元は間接 (fn ptr / handler table) で static xref なし。確定した
// errNo + message + flags byte + fuzzy backtrace を取得してトリガ箇所を特定する。
(function hookError1000() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'hookError1000: nrs.exe not found'); return; }

    var fired = 0;
    try {
        Interceptor.attach(nrsBase.add(0x2F2730), {
            onEnter: function(args) {
                fired++;
                var msg = 'errenderer FUN_006f2730 #' + fired;
                try {
                    var desc    = args[0];                       // param_1
                    var msgPtr  = desc.add(0xc).readPointer();   // [param_1+0xc]
                    var errNo   = msgPtr.isNull() ? 1000 : desc.add(0x10).readU16();
                    var flags   = desc.add(0x16).readU8();
                    var kind    = (flags & 4) ? 'Caution' : 'Error';
                    var text    = msgPtr.isNull() ? '<NULL→Unknown Application Error>'
                                                  : msgPtr.readCString();
                    var ec0 = desc.readU32();            // desc+0x00 = amlib errCode (0x15 は billing だった)
                    var ec4 = desc.add(4).readS32();     // desc+0x04
                    var ec8 = desc.add(8).readU32();     // desc+0x08
                    msg += ' desc=' + desc +
                           ' +0=' + ec0 + '(0x' + ec0.toString(16) + ')' +
                           ' +4=' + ec4 + ' +8=0x' + ec8.toString(16) +
                           ' kind=' + kind +
                           ' errNo=' + errNo +
                           ' flags=0x' + flags.toString(16) +
                           ' msg="' + text + '"';
                } catch(e) { msg += ' (read err: ' + e + ')'; }

                // 間接呼び出し元 / 発生経路を特定するための fuzzy backtrace。
                try {
                    var bt = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0, 12)
                        .map(function(f) {
                            var mod = Process.findModuleByAddress(f);
                            return mod
                                ? mod.name + '+0x' + f.sub(mod.base).toString(16)
                                : '0x' + f.toString(16);
                        }).join(' <- ');
                    msg += ' bt=[' + bt + ']';
                } catch(e) { msg += ' (bt err: ' + e + ')'; }

                logMsg('ERR1000', msg);
            }
        });
        logMsg('INIT_ERR1000', 'FUN_006f2730 (RVA 0x2f2730) error-renderer hooked');
    } catch(e) { logMsg('WARN', 'hookError1000 attach 0x2F2730: ' + e); }
})();
