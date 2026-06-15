"""JVS I/O investigation - hook ReadFile/WriteFile for JVS protocol traffic.

TeknoParrot patches nrs.exe IAT for COM functions. This script hooks the
underlying kernel functions AND TeknoParrot's exported interface to see JVS data.

使い方:
    # TeknoParrot ヘッドレス起動と同時に待機（推奨）
    python tools/runtime/jvs_trace.py --wait 60 --duration 120

    # PID 直指定
    python tools/runtime/jvs_trace.py --pid 1234

ランブック (JVS フレーム + JvsState ビット割当):
    1. TP UI で Test/Service/Coin/Start にキーを束縛
    2. 本スクリプトを --wait で起動
    3. TP ヘッドレス: cd C:\\src\\TPBootstrapper
                     .\\OpenParrotWin32\\OpenParrotLoader.exe .\\TeknoParrot\\TeknoParrot "C:\\src\\bbs\\nrs.exe"
    4. ATTRACT 後に束縛キーを押す
    5. captures/jvstrace-*.txt の ReadFile/WriteFile 行が JVS フレーム
"""
import frida, sys, time, argparse, datetime, os, subprocess

SCRIPT = r"""
'use strict';

var LOG = [];
var logFile = null;

function ts() { return new Date().toISOString().substr(11,12); }
function hexd(buf, maxB) {
    if (!buf) return '';
    var b = maxB ? Math.min(buf.byteLength, maxB) : buf.byteLength;
    var h = '';
    for (var i = 0; i < b; i++) h += ('00' + buf[i].toString(16)).slice(-2) + ' ';
    return h.trim();
}
function logMsg(tag, msg) {
    send({ tag: tag, msg: ts() + ' ' + msg });
}

var nrsBase = null;
try { nrsBase = Process.getModuleByName('nrs.exe').base; }
catch(e) { logMsg('ERR', 'nrs.exe not found'); }

var tpBase = null;
try { tpBase = Process.getModuleByName('TeknoParrot.dll').base; }
catch(e) { logMsg('WARN', 'TeknoParrot.dll not found'); }

logMsg('INIT', 'nrsBase=' + (nrsBase ? nrsBase : '?') + ' tpBase=' + (tpBase ? tpBase : '?'));

// --- Track open handles ---
var handles = {};  // handle -> description

// Hook CreateFileA to track ALL opens
var cfaFn = Module.getGlobalExportByName('CreateFileA');
if (cfaFn) Interceptor.attach(cfaFn, {
    onEnter: function(args) { this.path = args[0].readAnsiString(); },
    onLeave: function(ret) {
        var h = ret.toUInt32();
        if (h !== 0xFFFFFFFF) {
            handles[h] = this.path;
            if (this.path && (this.path.match(/COM\d|pipe|jvs/i))) {
                logMsg('CreateFileA', 'path="' + this.path + '" h=0x' + h.toString(16));
            }
        } else if (this.path && (this.path.match(/COM\d|pipe|jvs/i))) {
            logMsg('CreateFileA', 'FAIL path="' + this.path + '"');
        }
    }
});

var cfwFn = Module.getGlobalExportByName('CreateFileW');
if (cfwFn) Interceptor.attach(cfwFn, {
    onEnter: function(args) { try { this.path = args[0].readUtf16String(); } catch(e) { this.path = '?'; } },
    onLeave: function(ret) {
        var h = ret.toUInt32();
        if (h !== 0xFFFFFFFF) {
            handles[h] = this.path;
            if (this.path && (this.path.match(/COM\d|pipe|jvs/i))) {
                logMsg('CreateFileW', 'path="' + this.path + '" h=0x' + h.toString(16));
            }
        } else if (this.path && (this.path.match(/COM\d|pipe|jvs/i))) {
            logMsg('CreateFileW', 'FAIL path="' + this.path + '"');
        }
    }
});

// Hook ReadFile - log all reads (rate-limited, but log COM/pipe fully)
var rfCounts = {};
var rfFn = Module.getGlobalExportByName('ReadFile');
if (rfFn) Interceptor.attach(rfFn, {
    onEnter: function(args) {
        this.h = args[0].toUInt32();
        this.buf = args[1];
        this.sz = args[2].toUInt32();
    },
    onLeave: function(ret) {
        if (ret.toUInt32() === 0) return;
        var path = handles[this.h] || '';
        var isCom = path.match(/COM\d|pipe|jvs/i);
        if (!isCom) return;  // only log COM/pipe reads
        var data = null;
        try { data = this.buf.readByteArray(Math.min(this.sz, 64)); } catch(e) {}
        logMsg('ReadFile', 'h=0x' + this.h.toString(16) + ' "' + path + '" n=' + this.sz + ' hex=[' + hexd(data, 32) + ']');
    }
});

// Hook WriteFile
var wfFn = Module.getGlobalExportByName('WriteFile');
if (wfFn) Interceptor.attach(wfFn, {
    onEnter: function(args) {
        this.h = args[0].toUInt32();
        this.buf = args[1];
        this.sz = args[2].toUInt32();
        var path = handles[this.h] || '';
        var isCom = path.match(/COM\d|pipe|jvs/i);
        if (!isCom) return;
        var data = null;
        try { data = this.buf.readByteArray(Math.min(this.sz, 64)); } catch(e) {}
        logMsg('WriteFile', 'h=0x' + this.h.toString(16) + ' "' + path + '" n=' + this.sz + ' hex=[' + hexd(data, 32) + ']');
    }
});

// Hook SetupComm, SetCommState, SetCommTimeouts (JVS COM init)
['SetupComm','SetCommState','SetCommTimeouts','SetCommMask','GetCommState','PurgeComm','ClearCommError'].forEach(function(fn) {
    var f = Module.getGlobalExportByName(fn);
    if (f) Interceptor.attach(f, {
        onEnter: function(args) {
            var h = args[0].toUInt32();
            var path = handles[h] || '?';
            logMsg(fn, 'h=0x' + h.toString(16) + ' (' + path + ')');
        },
        onLeave: function(ret) {}
    });
});

// Hook CreateNamedPipeA/W (maybe TeknoParrot creates the pipe from within?)
var cnpa = Module.getGlobalExportByName('CreateNamedPipeA');
if (cnpa) Interceptor.attach(cnpa, {
    onEnter: function(args) { logMsg('CreateNamedPipeA', '"' + args[0].readAnsiString() + '"'); }
});
var cnpw = Module.getGlobalExportByName('CreateNamedPipeW');
if (cnpw) Interceptor.attach(cnpw, {
    onEnter: function(args) { try { logMsg('CreateNamedPipeW', '"' + args[0].readUtf16String() + '"'); } catch(e) {} }
});

// Hook ConnectNamedPipe
var np = Module.getGlobalExportByName('ConnectNamedPipe');
if (np) Interceptor.attach(np, { onEnter: function(args) { logMsg('ConnectNamedPipe', 'h=0x' + args[0].toUInt32().toString(16)); } });

// Hook OpenMutexA/W (TeknoParrot_JvsState uses mutex?)
var oma = Module.getGlobalExportByName('OpenMutexA');
if (oma) Interceptor.attach(oma, {
    onEnter: function(args) { logMsg('OpenMutexA', '"' + args[2].readAnsiString() + '"'); }
});

// Hook OpenFileMappingA/W (TeknoParrot_JvsState shared memory)
var ofma = Module.getGlobalExportByName('OpenFileMappingA');
if (ofma) Interceptor.attach(ofma, {
    onEnter: function(args) { logMsg('OpenFileMappingA', '"' + args[2].readAnsiString() + '"'); }
});
var ofmw = Module.getGlobalExportByName('OpenFileMappingW');
if (ofmw) Interceptor.attach(ofmw, {
    onEnter: function(args) { try { logMsg('OpenFileMappingW', '"' + args[2].readUtf16String() + '"'); } catch(e) {} }
});

// Hook CreateFileMappingA/W - catch shared memory creation
var cfma = Module.getGlobalExportByName('CreateFileMappingA');
if (cfma) Interceptor.attach(cfma, {
    onEnter: function(args) {
        var name = ''; try { name = args[4].readAnsiString(); } catch(e) {}
        if (name) logMsg('CreateFileMappingA', 'name="' + name + '" size=' + args[3].toUInt32());
    },
    onLeave: function(ret) {}
});

// Map of shared memory handles -> names
var mapHandles = {};
var cfmw = Module.getGlobalExportByName('CreateFileMappingW');
if (cfmw) Interceptor.attach(cfmw, {
    onEnter: function(args) {
        var name = ''; try { name = args[4].readUtf16String(); } catch(e) {}
        if (name) {
            this.name = name;
            logMsg('CreateFileMappingW', 'name="' + name + '" size=' + args[3].toUInt32());
        }
    },
    onLeave: function(ret) {
        if (this.name) mapHandles[ret.toUInt32()] = this.name;
    }
});

// Hook MapViewOfFile
var mvof = Module.getGlobalExportByName('MapViewOfFile');
if (mvof) Interceptor.attach(mvof, {
    onEnter: function(args) {
        var h = args[0].toUInt32();
        var name = mapHandles[h] || '';
        if (name.match(/jvs|JVS|tekno|Tekno/i)) {
            logMsg('MapViewOfFile', 'h=0x' + h.toString(16) + ' name="' + name + '"');
        }
    },
    onLeave: function(ret) {}
});

logMsg('INIT', 'JVS trace hooks installed. Waiting for JVS init...');
"""

CAPTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "captures")


def wait_for_process(name="nrs.exe", timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = subprocess.run(['tasklist', '/FI', f'IMAGENAME eq {name}', '/FO', 'CSV', '/NH'],
                           capture_output=True, text=True)
        for line in r.stdout.splitlines():
            parts = line.strip('"').split('","')
            if len(parts) >= 2 and parts[0].lower() == name.lower():
                return int(parts[1])
        time.sleep(0.2)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pid', type=int, default=None)
    ap.add_argument('--duration', type=int, default=120)
    ap.add_argument('--wait', type=int, default=60, help='seconds to wait for nrs.exe to appear')
    a = ap.parse_args()

    os.makedirs(CAPTURES_DIR, exist_ok=True)
    log_path = os.path.join(CAPTURES_DIR, f"jvstrace-{time.strftime('%Y%m%d-%H%M%S')}.txt")
    with open(log_path, 'w', encoding='utf-8') as f:
        f.write(f"=== JVS trace | {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n\n")
    print(f"[*] Log: {log_path}")

    pid = a.pid or wait_for_process("nrs.exe", timeout=a.wait)
    if not pid:
        print(f"[!] nrs.exe not found within {a.wait}s. Start TeknoParrot first.", file=sys.stderr)
        return 1

    print(f"[*] Attaching to nrs.exe PID={pid} for JVS trace")

    def on_message(msg, data):
        if msg['type'] == 'send':
            p = msg['payload']
            line = f"[{p.get('tag','?'):20s}] {p.get('msg','')}"
        elif msg['type'] == 'error':
            line = f"[ERR] {msg.get('description','')[:300]}"
        else:
            line = f"[?] {msg}"
        try:
            print(line)
        except Exception:
            print(line.encode('ascii', 'replace').decode('ascii'))
        sys.stdout.flush()
        with open(log_path, 'a', encoding='utf-8') as fh:
            fh.write(line + '\n')

    sess = frida.attach(pid)
    scr = sess.create_script(SCRIPT)
    scr.on('message', on_message)
    scr.load()
    print(f"[*] Monitoring {a.duration}s (press JVS buttons to capture frames)...")
    try:
        time.sleep(a.duration)
    except KeyboardInterrupt:
        pass
    try:
        sess.detach()
    except Exception:
        pass
    print(f"[*] Done. Log: {log_path}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
