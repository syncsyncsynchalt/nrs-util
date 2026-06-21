"""One-shot read-only dump of amNet/error-scene globals from a running nrs.exe.

Usage: python tools/runtime/read_amnet_state.py [pid]
If pid omitted, attaches to the first nrs.exe found.
RVA = static_VA - 0x400000 (nrs.exe ImageBase 0x400000).
"""
import frida, sys, json, time, subprocess

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
function u8(rva){ try{return base.add(rva).readU8();}catch(e){return 'ERR';} }
function u16(rva){ try{return base.add(rva).readU16();}catch(e){return 'ERR';} }
function u32(rva){ try{return base.add(rva).readU32();}catch(e){return 'ERR';} }
function s(rva){ try{return base.add(rva).readCString();}catch(e){return 'ERR';} }
function hex(v){ return (typeof v==='number')? '0x'+v.toString(16): v; }
var out = {
  base: base.toString(),
  // amNet SM result globals
  nic_resolved_DAT016019a5: u8(0x12019a5),
  ip_match_DAT016019a6: u8(0x12019a6),
  ref_str_DAT0160198a: s(0x120198a),
  ip_str_DAT016019a7: s(0x12019a7),
  mask_str_DAT016019c7: s(0x12019c7),
  bcast_str_DAT016019b7: s(0x12019b7),
  // network connect SM (FUN_006fe040)
  fe040_gate_DAT0210aed0: u8(0x1d0aed0),
  fe040_state_DAT0210aee0: u32(0x1d0aee0),
  net_connected_DAT0210b508: u32(0x1d0b508),
  // errCode master + display struct
  master_errcode_DAT016f5af0: hex(u32(0x12f5af0)),
  disp_errcode_p00: hex(u32(0x12f5a80)),
  disp_msgptr_pc: hex(u32(0x12f5a80 + 0xc)),
  disp_errno_p10: u16(0x12f5a80 + 0x10),
};
// amNet ctx nic fields
try {
  var ctx = base.add(0x8cf448).readPointer();
  out.ctx = ctx.toString();
  out.ctx_dhcp_status_30 = ctx.add(0x30).readS32();
  out.ctx_nic_ip_3c = hex(ctx.add(0x3c).readU32());
  out.ctx_nic_mask_40 = hex(ctx.add(0x40).readU32());
  out.ctx_nic_ready_69 = ctx.add(0x69).readU8();
} catch(e){ out.ctx = 'ERR ' + e; }
// resolve disp_msgptr to string
try { out.disp_msg = ptr(u32(0x12f5a80+0xc)).readCString(); } catch(e){ out.disp_msg='(null)'; }
send(JSON.stringify(out, null, 2));
"""

session = frida.attach(pid)
script = session.create_script(JS)
got = {}
def on_message(message, data):
    if message.get('type') == 'send':
        print(message['payload'])
        got['ok'] = True
    else:
        print('ERR', message)
script.on('message', on_message)
script.load()
time.sleep(1.0)
session.detach()
if not got:
    print('(no payload received)')
