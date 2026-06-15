
// ─────────────────────────────────────────────────────────────────────────────
// VirtualProtect .rdata patch reader
// When TeknoParrot patches a 4-byte .rdata entry (func ptr overwrite),
// we read the NEW value right after the write.
// ─────────────────────────────────────────────────────────────────────────────
(function hookRdataPatch() {
    var RDATA_PATCH_RVAS = [
        0x6DC164, 0x6DC168, 0x6DC1A4, 0x6DC238, 0x6DC254,
        0x6DC2B4, 0x6DC2BC, 0x6DC2C0, 0x6DC2C4, 0x6DC2C8, 0x6DC2CC,
    ];
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { return; }
    // Convert to set of VAs for quick lookup
    var patchSet = {};
    RDATA_PATCH_RVAS.forEach(function(rva) {
        patchSet['0x' + (nrsBase.add(rva).toUInt32()).toString(16)] = rva;
    });

    // Enhance VirtualProtect to read the patched value for known .rdata sites
    var vpOrig = Module.getGlobalExportByName('VirtualProtect');
    Interceptor.attach(vpOrig, {
        onEnter: function(args) {
            this.addr = args[0].toUInt32();
            this.size = args[1].toUInt32();
            this.prot = args[2].toUInt32();
        },
        onLeave: function(ret) {
            if (this.size === 4 && this.prot === 0x40) {
                var key = '0x' + this.addr.toString(16);
                var rva = patchSet[key];
                if (rva !== undefined) {
                    var newPtr = 0;
                    try { newPtr = ptr(this.addr).readU32(); } catch(e) {}
                    if (newPtr) {
                        logMsg('rdataPatch', 'RVA=0x' + rva.toString(16) +
                               ' newFnPtr=0x' + newPtr.toString(16));
                    }
                }
            }
        }
    });
})();
