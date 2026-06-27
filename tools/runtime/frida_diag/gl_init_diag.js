// subsys:      tools/runtime (diag, not a boot module)
// persistence: monitor
// va:          — (opengl32/gdi32 export のみ。nrs static_VA は触らない)
// ssot:        —
// role:        OpenGL/WGL 初期化を観測し、採用レンダラ(GL_RENDERER)・pixel format・context 成否・SwapBuffers 回数を記録（純観測）。
//
// nrs.exe は OpenGL レンダラ（opengl32 + glut/glu、WGL コンテキスト、ウィンドウクラス "WGL"）。
// D3D は不使用（import に d3d9/d3d11/dxgi なし。Ghidra list_imports で確認）。
// 「NVIDIA でないと画面が出ない」の定番要因は、ベンダ提供の OpenGL ICD（NVIDIA=nvoglv32 等）が
// 載らず Windows 既定の GDI Generic（ソフト OpenGL 1.1）に落ちること。これを実測で確定する。
//
// 決定的シグナル: wglMakeCurrent 成功直後に glGetString(GL_RENDERER/GL_VENDOR/GL_VERSION) を自前で呼ぶ。
//   "GDI Generic" / "Microsoft" → ICD 未ロード（＝黒画面の主因）
//   "NVIDIA ..."               → HW 加速（正常）
//   "Intel ..." / "AMD ..."    → ICD は載っている（黒なら GL 機能/拡張の非互換を疑う）
// 補助: ChoosePixelFormat の選択 PFD が GENERIC_FORMAT(ソフト)か ICD 加速か、SwapBuffers 回数（0=描画未到達）。
//
// boot バンドル末尾に連結して走らせる前提（launch.py --diag）。base.js が先頭ロードされるので
// logMsg / watch などの共通ヘルパがそのまま使える。状態変更（ret.replace 等）は一切しない。
(function glInitDiag() {
    'use strict';

    var GL_VENDOR = 0x1F00, GL_RENDERER = 0x1F01, GL_VERSION = 0x1F02;
    // PIXELFORMATDESCRIPTOR.dwFlags（offset 4）の主要ビット
    var PFD_DOUBLEBUFFER = 0x1, PFD_SUPPORT_OPENGL = 0x20,
        PFD_GENERIC_FORMAT = 0x40, PFD_GENERIC_ACCELERATED = 0x1000;

    var installed = false;
    var glStringDumped = false;
    var swapCount = 0;
    var clearCount = 0;
    var glQueryCount = 0;
    var selfQuery = false;            // 自前の glGetString 呼び出しを GLQUERY ログから除外する再入ガード
    var NRS_IMAGE_SIZE = 0x2132000;   // nrs.exe ImageSize（FACTS）。backtrace を nrs フレームに絞る用。

    function resolve(name) {
        try { return Module.getGlobalExportByName(name); } catch (e) { return null; }
    }

    // PIXELFORMATDESCRIPTOR.dwFlags を可読化。GENERIC_FORMAT 無し = ベンダ ICD 完全加速。
    function pfdFlags(f) {
        var s = [];
        if (f & PFD_SUPPORT_OPENGL) s.push('OPENGL');
        if (f & PFD_DOUBLEBUFFER) s.push('DBL');
        if (f & PFD_GENERIC_FORMAT) s.push('GENERIC_FORMAT(SW)');
        if (f & PFD_GENERIC_ACCELERATED) s.push('GENERIC_ACCEL');
        if (!(f & PFD_GENERIC_FORMAT)) s.push('ICD_ACCEL');
        return s.join('|') + ' (0x' + (f >>> 0).toString(16) + ')';
    }

    // backtrace を nrs.exe 内フレームだけに絞り static_VA で返す（Ghidra にそのまま貼れる）。
    function btNrs(ctx) {
        try {
            var frames = Thread.backtrace(ctx, Backtracer.ACCURATE);
            var out = [];
            for (var i = 0; i < frames.length && out.length < 8; i++) {
                var s = rtToVa(frames[i]);            // '0x....' static_VA 文字列
                var n = parseInt(s, 16);
                if (n >= 0x400000 && n < 0x400000 + NRS_IMAGE_SIZE) out.push(s);
            }
            return out.length ? out.join(' <- ') : '<no nrs frame>';
        } catch (e) { return '<bt err:' + e + '>'; }
    }

    function install() {
        if (installed) return true;
        var pGlGetString = resolve('glGetString');
        var pWglCreate   = resolve('wglCreateContext');
        var pWglMake     = resolve('wglMakeCurrent');
        var pChoose      = resolve('ChoosePixelFormat');
        var pSetPF       = resolve('SetPixelFormat');
        var pDescribePF  = resolve('DescribePixelFormat');  // app は import しないが gdi32 export を直接使える
        var pSwap        = resolve('SwapBuffers');
        var pGlClear     = resolve('glClear');
        var pWglGetProc  = resolve('wglGetProcAddress');
        if (!pGlGetString || !pWglMake) return false;       // opengl32 未ロード — 次の周回で再試行

        var glGetString = new NativeFunction(pGlGetString, 'pointer', ['uint'], 'stdcall');
        var describePF  = pDescribePF
            ? new NativeFunction(pDescribePF, 'int', ['pointer', 'int', 'uint', 'pointer'], 'stdcall')
            : null;

        function glStr(enumVal) {
            try {
                var p = glGetString(enumVal);
                return p.isNull() ? '<null>' : p.readCString();
            } catch (e) { return '<err:' + e + '>'; }
        }

        // context 生成成否
        if (pWglCreate) Interceptor.attach(pWglCreate, {
            onLeave: function (ret) {
                logMsg('GLCTX', 'wglCreateContext -> ' + (ret.isNull() ? 'NULL (FAILED)' : ret));
            }
        });

        // context が current になった瞬間に GL 文字列を実測（このスレッドで context 有効＝呼んで安全）
        Interceptor.attach(pWglMake, {
            onEnter: function (args) { this.hglrc = args[1]; },
            onLeave: function (ret) {
                if (ret.toInt32() === 0 || this.hglrc.isNull()) return;  // unbind や失敗は無視
                if (glStringDumped) return;                              // 初回のみ
                glStringDumped = true;
                selfQuery = true;   // ↓自前 query は GLQUERY フックの対象外にする
                var vendor = glStr(GL_VENDOR), renderer = glStr(GL_RENDERER), version = glStr(GL_VERSION);
                selfQuery = false;
                logMsg('GL', 'VENDOR="' + vendor + '" RENDERER="' + renderer + '" VERSION="' + version + '"');
                var soft = /GDI Generic/i.test(renderer) || /Microsoft/i.test(vendor);
                var nv   = /NVIDIA/i.test(vendor) || /NVIDIA/i.test(renderer);
                logMsg('GLVERDICT', soft
                    ? 'SOFTWARE FALLBACK (GDI Generic) — ベンダ OpenGL ICD 未ロード。これが黒画面の主因。'
                    : (nv ? 'NVIDIA ICD active (hardware accel) — 正常系の基準値。'
                          : 'Non-NVIDIA HW ICD ("' + vendor + '") — ICD は載っている。黒なら GL 機能/拡張の非互換を疑う。'));
            }
        });

        // 要求 PFD と選択 index、選ばれた PFD の実フラグ（ソフトフォールバック検出）
        if (pChoose) Interceptor.attach(pChoose, {
            onEnter: function (args) { this.hdc = args[0]; this.ppfd = args[1]; },
            onLeave: function (ret) {
                var idx = ret.toInt32();
                var reqFlags = -1;
                try { reqFlags = this.ppfd.add(4).readU32(); } catch (e) {}
                var chosen = '';
                if (describePF && idx > 0) {
                    try {
                        var buf = Memory.alloc(40);
                        buf.writeU16(40);  // nSize
                        describePF(this.hdc, idx, 40, buf);
                        chosen = ' chosen-flags=' + pfdFlags(buf.add(4).readU32()) +
                                 ' color=' + buf.add(9).readU8() + ' depth=' + buf.add(23).readU8();
                    } catch (e) {}
                }
                logMsg('PIXELFORMAT', 'ChoosePixelFormat req-flags=0x' + (reqFlags >>> 0).toString(16) +
                       ' -> idx=' + idx + chosen);
            }
        });

        // pixel format 設定成否
        if (pSetPF) Interceptor.attach(pSetPF, {
            onLeave: function (ret) {
                logMsg('PIXELFORMAT', 'SetPixelFormat -> ' + (ret.toInt32() ? 'OK' : 'FAILED'));
            }
        });

        // フレーム提示の有無（0=描画未到達 / >0=描画はしている＝黒ならウィンドウ/合成側）
        if (pSwap) Interceptor.attach(pSwap, {
            onLeave: function (ret) {
                swapCount++;
                if (swapCount <= 3 || swapCount % 300 === 0) {
                    logMsg('SWAP', 'SwapBuffers #' + swapCount + ' ret=' + ret.toInt32());
                }
            }
        });

        // 描画ループの生死: glClear が来ていれば render 関数には入っている（提示の手前で止まる型）。
        // 1 回も来なければ描画パスごとスキップ。初回に backtrace で render 関数の static_VA を採取する。
        if (pGlClear) Interceptor.attach(pGlClear, {
            onEnter: function () {
                clearCount++;
                if (clearCount === 1) logMsg('GLDRAW', 'first glClear — render loop alive. caller: ' + btNrs(this.context));
                else if (clearCount % 600 === 0) logMsg('GLDRAW', 'glClear #' + clearCount);
            }
        });

        // ゲーム自身の glGetString（自前 query は selfQuery で除外）。GL_VENDOR/RENDERER を読んで
        // 自前で分岐＝GL 層の "NVIDIA 判定" をしていないかを backtrace 付きで暴く。
        Interceptor.attach(pGlGetString, {
            onEnter: function (args) {
                if (selfQuery) { this.skip = true; return; }
                this.glenum = args[0].toInt32();
            },
            onLeave: function (ret) {
                if (this.skip || glQueryCount >= 24) return;
                glQueryCount++;
                var e = this.glenum;
                var name = e === 0x1F00 ? 'GL_VENDOR' : e === 0x1F01 ? 'GL_RENDERER' :
                           e === 0x1F02 ? 'GL_VERSION' : e === 0x1F03 ? 'GL_EXTENSIONS' : '0x' + e.toString(16);
                var val = '';
                try { val = ret.isNull() ? '<null>' : ret.readCString(); } catch (x) {}
                if (val && val.length > 70) val = val.slice(0, 70) + '…';
                logMsg('GLQUERY', 'game glGetString(' + name + ')="' + val + '" caller: ' + btNrs(this.context));
            }
        });

        // AMD で解決できない GL 拡張（NULL 返り）を記録。描画初期化がここで中断していないかの手掛かり。
        if (pWglGetProc) Interceptor.attach(pWglGetProc, {
            onEnter: function (args) { try { this.pname = args[0].readCString(); } catch (e) { this.pname = '?'; } },
            onLeave: function (ret) {
                if (ret.isNull()) logMsg('WGLPROC', 'wglGetProcAddress("' + this.pname + '") = NULL (未対応拡張)');
            }
        });

        installed = true;
        logMsg('GLDIAG', 'OpenGL/WGL hooks installed (glGetString/wglCreateContext/wglMakeCurrent/' +
               'ChoosePixelFormat/SetPixelFormat/SwapBuffers/glClear/wglGetProcAddress)');
        return true;
    }

    // opengl32/gdi32 は静的 import だが、念のためロード完了を待ってから一度だけ張る
    if (!install()) {
        var t = watch(250, function () { if (install()) clearInterval(t); }, 'glInitDiag-installer');
    }
})();
