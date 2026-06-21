"""稼働中の nrs.exe で error_scene_render (FUN_006f2730 / RVA 0x2f2730) をフックし、
描画するエラー descriptor をダンプする: param_1, errCode(+0x00), msgptr(+0xc)->str,
errNo(+0x10), flags(+0x16) と backtrace。読み取り専用。

使い方: python tools/runtime/hook_error_render.py [pid]
"""
import frida, sys, time, subprocess

def find_pid():
    r = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq nrs.exe', '/FO', 'CSV', '/NH'],
                       capture_output=True, text=True)
    for line in r.stdout.splitlines():
        parts = line.strip('"').split('","')
        if len(parts) >= 2 and parts[0].lower() == 'nrs.exe':
            return int(parts[1])
    return None

pid = int(sys.argv[1]) if len(sys.argv) > 1 else find_pid()
if not pid:
    print('nrs.exe not found'); sys.exit(1)

JS = r"""
var base = Process.getModuleByName('nrs.exe').base;
var RENDER = base.add(0x2f2730);   // error_scene_render
var n = 0;
Interceptor.attach(RENDER, {
  onEnter: function(args) {
    if (n >= 3) return;
    n++;
    var p = args[0];
    var o = { call: n, descriptor: p.toString() };
    try { o.errCode_p00 = p.add(0x00).readU32(); } catch(e) { o.errCode_p00 = 'ERR'; }
    try { var m = p.add(0xc).readPointer(); o.msgptr_pc = m.toString();
          o.msg = m.isNull() ? '(null)' : m.readCString(); } catch(e) { o.msg = 'ERR'; }
    try { o.errNo_p10 = p.add(0x10).readU16(); } catch(e) { o.errNo_p10 = 'ERR'; }
    try { o.flags_p16 = p.add(0x16).readU8(); } catch(e) { o.flags_p16 = 'ERR'; }
    // descriptor RVA (so we can find its writer in Ghidra: static = 0x400000 + RVA)
    try { o.descriptor_rva = '0x' + p.sub(base).toString(16); } catch(e) {}
    o.bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
             .slice(0, 8).map(function(a){ return a.toString() + ' (rva 0x' + a.sub(base).toString(16) + ')'; });
    send(JSON.stringify(o, null, 2));
  }
});
send('hook installed on error_scene_render');
"""

session = frida.attach(pid)
script = session.create_script(JS)
def on_message(message, data):
    if message.get('type') == 'send':
        print(message['payload'])
    else:
        print('ERR', message)
script.on('message', on_message)
script.load()
time.sleep(2.0)
session.detach()
