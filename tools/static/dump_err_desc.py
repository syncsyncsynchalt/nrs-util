#!/usr/bin/env python
"""ワンショット: 稼働中の nrs.exe に attach し、Error-1000 シーンの descriptor をダンプする。

エラー描画関数 FUN_006f2730 は次を読む:
  desc+0xc  = char* message（非 null のとき表示）
  desc+0x10 = uint16 エラー番号
  desc+0x16 = byte flags（&4 -> "Caution"）
descriptor のバイト列と、それが指す message 文字列をダンプする。

使い方:  python tools/static/dump_err_desc.py <pid> <desc_addr_hex>
例:      python tools/static/dump_err_desc.py 1044 0x1e28ce50
"""
import sys
import frida

JS = r"""
rpc.exports.dump = function(addrStr) {
    var desc = ptr(addrStr);
    var out = { desc: addrStr };
    out.raw = desc.readByteArray(0x40);
    function rd32(o) { try { return '0x' + desc.add(o).readU32().toString(16); } catch(e) { return 'ERR'; } }
    function rd16(o) { try { return desc.add(o).readU16(); } catch(e) { return 'ERR'; } }
    function rd8(o)  { try { return '0x' + desc.add(o).readU8().toString(16); } catch(e) { return 'ERR'; } }
    out.fields = {
        '+0x00': rd32(0x00), '+0x04': rd32(0x04), '+0x08': rd32(0x08),
        '+0x0c_msgPtr': rd32(0x0c), '+0x10_errNo': rd16(0x10),
        '+0x14': rd32(0x14), '+0x16_flags': rd8(0x16),
    };
    try {
        var msgPtr = desc.add(0xc).readPointer();
        out.msgPtr = '0x' + msgPtr.toString(16);
        out.msg = msgPtr.isNull() ? '<NULL>' : msgPtr.readCString();
        if (!msgPtr.isNull()) {
            var m = Process.findModuleByAddress(msgPtr);
            out.msgLoc = m ? (m.name + '+0x' + msgPtr.sub(m.base).toString(16)) : '<heap/non-module>';
        }
    } catch(e) { out.msgErr = '' + e; }
    return out;
};
"""

def main():
    if len(sys.argv) < 3:
        print("usage: dump_err_desc.py <pid> <desc_addr_hex>")
        sys.exit(2)
    pid = int(sys.argv[1])
    addr = sys.argv[2]
    session = frida.attach(pid)
    script = session.create_script(JS)
    script.load()
    res = script.exports_sync.dump(addr)
    print("desc:", res.get("desc"))
    print("fields:", res.get("fields"))
    print("msgPtr:", res.get("msgPtr"), "loc:", res.get("msgLoc"))
    print("msg:", repr(res.get("msg")))
    raw = res.get("raw")
    if raw:
        print("raw[0x40]:", raw.hex())
    session.detach()

if __name__ == "__main__":
    main()
