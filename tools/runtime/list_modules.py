"""List all modules loaded in nrs.exe (32-bit process)."""
import frida, sys, time

PID = 8272

SCRIPT = r"""
var mods = Process.enumerateModules();
mods.forEach(function(m) {
    send(m.name + ' @ ' + m.base + ' size=' + m.size);
});
send('__DONE__');
"""

def on_msg(msg, data):
    if msg['type'] == 'send':
        print(msg['payload'])
    elif msg['type'] == 'error':
        print('ERR:', msg.get('description', '')[:300])

sess = frida.attach(PID)
scr = sess.create_script(SCRIPT)
scr.on('message', on_msg)
scr.load()
time.sleep(5)
sess.detach()
