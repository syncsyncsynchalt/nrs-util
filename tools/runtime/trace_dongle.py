"""稼働中の nrs.exe で amDongle/amNet ステートマシンをトレースする。
使い方: python trace_dongle.py [--pid PID] [--duration SEC]
"""
import frida, sys, time, argparse

SCRIPT = r"""
'use strict';

function logMsg(tag, msg) { send({ tag: tag, msg: msg }); }

var nrsBase = null;
try { nrsBase = Process.getModuleByName('nrs.exe').base; }
catch(e) { logMsg('ERR', 'nrs.exe not found: ' + e); }

if (!nrsBase) {
    logMsg('ERR', 'Cannot find nrs.exe module');
} else {
    logMsg('INIT', 'nrs.exe base = 0x' + nrsBase.toUInt32().toString(16));

    // RVA = static_VA - ImageBase(0x400000)
    var RVA = {
        amNetworkInit:  0x5801E0,
        amNetConnect:   0x5803B0,
        amNetOuterLoop: 0x5819D0,
        amDongleTick:   0x578450,  // 7-state sm tick: reads [CCF0EC]+0x18
        amDongleBusy:   0x575E00,  // returns [CCF0EC]+0xC or -3
        outerTick:      0x057810,  // calls amDongleTick + amDongleBusy
        outerSM:        0x057822,  // 6-state orchestrator
        keychipSM:      0x057910,  // 9-state keychip verifier
        dongleInit:     0x057500,  // top-level: loops outerSM until state==7, then keychipSM
    };

    // Global variable RVAs (static_VA - 0x400000)
    var GVAR = {
        amNetCtxPtr:    0x8CF448,  // [0xCCF448]: pointer to amNet ctx
        amDongleCtxPtr: 0x8CF0EC,  // [0xCCF0EC]: pointer to amDongle ctx
        outerState:     0x12F6C1C, // [0x16f6C1C]: outer state (wait for 7)
        keychipState:   0x12F6CAC, // [0x16f6CAC]: keychip state
    };

    function readGvar(rva) {
        try { return nrsBase.add(rva).readU32(); } catch(e) { return 0xDEAD; }
    }
    function readGvarSigned(rva) {
        try { return nrsBase.add(rva).readS32(); } catch(e) { return -999; }
    }

    // Rate limiter
    var counts = {};
    function rlog(tag, msg, max) {
        if (!counts[tag]) counts[tag] = 0;
        counts[tag]++;
        if (counts[tag] <= (max || 10) || counts[tag] % 50 === 0) {
            logMsg(tag, '[#' + counts[tag] + '] ' + msg);
        }
    }

    function hook(name, rva, onEnterFn, onLeaveFn) {
        try {
            Interceptor.attach(nrsBase.add(rva), {
                onEnter: onEnterFn || function(args) {},
                onLeave: onLeaveFn || function(ret) {}
            });
        } catch(e) { logMsg('WARN', 'hook ' + name + ' failed: ' + e); }
    }

    // amNetworkInit
    hook('amNetInit', RVA.amNetworkInit,
        function() { logMsg('amNetInit', 'CALL'); },
        function(ret) { logMsg('amNetInit', 'ret=' + ret.toInt32()); }
    );

    // amNet outer loop (runs pcpa query cycle)
    hook('amNetLoop', RVA.amNetOuterLoop,
        function() { rlog('amNetLoop', 'ENTER', 3); },
        function(ret) { rlog('amNetLoop', 'ret=' + ret.toInt32(), 3); }
    );

    // amDongle tick (7-state dispatcher)
    hook('amDngTick', RVA.amDongleTick,
        function() {
            var ctxp = readGvar(GVAR.amDongleCtxPtr);
            var state = 0;
            try { state = ptr(ctxp).add(0x18).readU32(); } catch(e) {}
            rlog('amDngTick', 'ctx+0x18(state)=' + state, 50);
        },
        function(ret) { rlog('amDngTick', 'ret=' + ret.toInt32(), 50); }
    );

    // amDongle busy (returns ctx+0xC)
    hook('amDngBusy', RVA.amDongleBusy,
        function() {},
        function(ret) {
            rlog('amDngBusy', 'ret=0x' + ret.toUInt32().toString(16) + ' (outerState=' + readGvar(GVAR.outerState) + ')', 50);
        }
    );

    // outer tick (amDongleTick + amDongleBusy wrapper)
    hook('outerTick', RVA.outerTick,
        function() {
            rlog('outerTick', 'outerState=' + readGvar(GVAR.outerState), 50);
        },
        function(ret) { rlog('outerTick', 'al=' + (ret.toUInt32() & 0xff), 50); }
    );

    // outer state machine (6-state orchestrator)
    hook('outerSM', RVA.outerSM,
        function() {
            var s = readGvar(GVAR.outerState);
            rlog('outerSM', 'state=' + s, 100);
        },
        function(ret) { rlog('outerSM', 'al=' + (ret.toUInt32() & 0xff), 100); }
    );

    // keychip state machine
    hook('keychipSM', RVA.keychipSM,
        function() {
            var s = readGvar(GVAR.keychipState);
            rlog('keychipSM', 'state=' + s, 100);
        },
        function(ret) { rlog('keychipSM', 'al=' + (ret.toUInt32() & 0xff), 100); }
    );

    // top-level dongle init
    hook('dongleInit', RVA.dongleInit,
        function() { logMsg('dongleInit', 'CALL'); },
        function(ret) { logMsg('dongleInit', 'ret' ); }
    );

    // Sleep hook to detect spin-waits
    var sleepFn = Module.getGlobalExportByName('Sleep');
    if (sleepFn) {
        Interceptor.attach(sleepFn, {
            onEnter: function(args) { this.ms = args[0].toUInt32(); },
            onLeave: function(ret) { rlog('Sleep', 'ms=' + this.ms, 20); }
        });
    }

    // WaitForSingleObject (non-zero/non-infinite timeout only)
    var wsfoFn = Module.getGlobalExportByName('WaitForSingleObject');
    if (wsfoFn) {
        Interceptor.attach(wsfoFn, {
            onEnter: function(args) {
                this.h = args[0].toUInt32();
                this.ms = args[1].toUInt32();
            },
            onLeave: function(ret) {
                if (this.ms > 0 && this.ms !== 0xFFFFFFFF) {
                    rlog('WFSO', 'h=0x' + this.h.toString(16) + ' ms=' + this.ms + ' ret=' + ret.toUInt32(), 30);
                }
            }
        });
    }

    // bind hook to monitor port activity (skip 30002 spam)
    var bindFn = Module.getGlobalExportByName('bind');
    if (bindFn) {
        Interceptor.attach(bindFn, {
            onEnter: function(args) {
                try {
                    this.port = (args[1].add(2).readU8() << 8) | args[1].add(3).readU8();
                } catch(e) { this.port = -1; }
            },
            onLeave: function(ret) {
                if (this.port !== 30002) {
                    logMsg('bind', 'port=' + this.port + ' ret=' + ret.toInt32());
                }
            }
        });
    }

    logMsg('INIT', 'All hooks installed. Monitoring...');
}
"""

def on_message(msg, data):
    if msg['type'] == 'send':
        p = msg['payload']
        print(f"[{p.get('tag','?'):12s}] {p.get('msg','')}")
        sys.stdout.flush()
    elif msg['type'] == 'error':
        print(f"[ERR] {msg.get('description','')} | {msg.get('stack','')[:300]}", file=sys.stderr)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pid', type=int, default=6636)
    ap.add_argument('--duration', type=int, default=30)
    a = ap.parse_args()

    print(f"[*] Attaching to PID={a.pid}")
    sess = frida.attach(a.pid)
    scr = sess.create_script(SCRIPT)
    scr.on('message', on_message)
    scr.load()
    print(f"[*] Monitoring {a.duration}s...")
    time.sleep(a.duration)
    sess.detach()
    print("[*] Done")

if __name__ == '__main__':
    main()
