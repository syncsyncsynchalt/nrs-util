"""スレッド PC インスペクタ — 稼働中の nrs.exe に attach し全スレッドの状態を表示する。"""
import frida, sys, time

SCRIPT = r"""
'use strict';
var threads = Process.enumerateThreads();
var out = [];
threads.forEach(function(t) {
    var ctx = t.context;
    // x86 (32-bit): eip field
    var pc = null;
    try { pc = ctx.eip; } catch(e) {}
    if (!pc) try { pc = ctx.pc; } catch(e) {}
    var pcStr = pc ? pc.toString() : '0x0';
    var modName = '?';
    try {
        var p = ptr(pcStr);
        var m = Process.getModuleByAddress(p);
        if (m) {
            var rva = p.sub(m.base);
            modName = m.name + '+0x' + rva.toString(16);
        }
    } catch(e) {}
    out.push({ id: t.id, state: t.state, pc: pcStr, mod: modName });
});
send({ tag: 'THREADS', threads: out });
"""

pid = 6636
print(f'[*] Attaching to PID={pid}')
sess = frida.attach(pid)
scr = sess.create_script(SCRIPT)

def on_msg(msg, data):
    if msg['type'] == 'send':
        p = msg['payload']
        if p['tag'] == 'THREADS':
            print(f"[*] {len(p['threads'])} threads:")
            for t in p['threads']:
                print(f"  TID={t['id']:5d} state={t['state']:10s} pc={t['pc']:12s} @ {t['mod']}")
    elif msg['type'] == 'error':
        print('ERR:', msg.get('description',''), msg.get('stack','')[:200])

scr.on('message', on_msg)
scr.load()
time.sleep(2)
sess.detach()
print('[*] Done')
