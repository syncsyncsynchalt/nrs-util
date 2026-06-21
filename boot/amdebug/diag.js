// subsys:      amdebug
// persistence: monitor      // network_role=local
// va: 0x1696F38, 0x1696F3C, 0x55C800, 0x55C7BC
// ssot:        amdebug/FACTS.md
// role:        amiDebug ログ可視化: DebugLogLevel/Mask を開放しレベル付きログをシンクで捕捉＋retail で破棄される無条件ログを復元、send() で送出。monitor
'use strict';

// nrs.exe の amiDebug ロギングは retail ビルドで実質無効化されている。このモジュールは解析用に
// 両系統を Frida から可視化する（FACTS.md 参照）。
//   A) レベル付きログ … 既定 DebugLogLevel=-1 で全抑止。フィルタを開放しシンク 0x55C800 を捕捉
//   B) 無条件ログ    … 0x55C790 で _vsnprintf 整形後に結果を破棄。整形直後 0x55C7BC で復元
// すべて logMsg('AMDBG', ...) で送出（実体は lib/base.js の send()）。
(function amDebugLogCapture() {
    // フィルタ開放を切替えたい場合はここを false に（A 系統が静かになる。B 系統は影響なし）。
    var ENABLE_ALL = true;

    // A. フィルタ開放: amDebug_logLevel / amDebug_logMask を全通過に
    // ゲート式（シンク実体準拠）: (level&~8) <= logLevel  かつ  logMask & (1<<((level&~8)&0x1f))
    if (ENABLE_ALL) {
        try {
            va(0x1696F38).writeS32(0x7fffffff); // amDebug_logLevel  (既定 -1 = 全抑止)
            va(0x1696F3C).writeU32(0xffffffff); // amDebug_logMask   (全カテゴリ bit ON)
            logMsg('AMDBG', '[init] DebugLogLevel/Mask opened (level=0x7fffffff mask=0xffffffff)');
        } catch (e) {
            logMsg('WARN', 'amdebug: filter open failed -> ' + e);
        }
    }

    // A. レベル付きログ捕捉: amDebugLog_sink (__fastcall ECX=level, EDX=msg)
    // シンクは format/mask ゲートを通過したメッセージのみ到達。onEnter で整形済み文字列を読む。
    try {
        Interceptor.attach(va(0x55C800), {
            onEnter: function () {
                var lv = this.context.ecx.toInt32() & 7;          // 重大度 = level & 7
                var msg = this.context.edx.readCString();          // EDX = 整形済みメッセージ
                if (msg) logMsg('AMDBG', '[lv' + lv + '] ' + msg.replace(/\n+$/, ''));
            }
        });
    } catch (e) {
        logMsg('WARN', 'amdebug: sink hook (0x55C800) failed -> ' + e);
    }

    // B. 破棄される無条件ログの復元: amDebugOut_format (0x55C790)
    // 0x55C7BC = 関数内 _vsnprintf の戻り直後。逆アセンブルより整形済みバッファは esp+0x10
    //   SUB ESP,0x404 → buf=[esp]; PUSH ECX/EAX/0x400/buf(4*4=0x10) → CALL _vsnprintf
    //   戻り時 esp = entry-0x414, buf = entry-0x404 = esp+0x10。固定バイナリでオフセット安定。
    try {
        Interceptor.attach(va(0x55C7BC), {
            onEnter: function () {
                var msg = this.context.esp.add(0x10).readCString();
                if (msg) logMsg('AMDBG', '[raw] ' + msg.replace(/\n+$/, ''));
            }
        });
    } catch (e) {
        logMsg('WARN', 'amdebug: raw-log hook (0x55C7BC) failed -> ' + e);
    }
})();
