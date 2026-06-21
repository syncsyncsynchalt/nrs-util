// subsys:      mxdrivers
// persistence: runtime   // network_role=local
// va: —
// ssot:        mxdrivers/FACTS.md
// role:        mxsram/mxsuperio/mxhwreset/jvs_pipe/mxsmbus を CreateFile/NtCreateFile/DeviceIoControl フックでダミー成功。mxsram(micetools mxsram.c) + mxsmbus(AT24C64AN eeprom, SetupAPI 発見) は micetools 準拠で data/nvram/{sram,eeprom}.bin に永続。runtime

// ─────────────────────────────────────────────────────────────────────────────
// RingEdge device emulation — mxhwreset / mxsuperio / mxsram / jvs_pipe
//
// TeknoParrot emulates these four devices. Without emulation, CreateFile calls
// return INVALID_HANDLE_VALUE and the game either logs errors or crashes when
// it tries DeviceIoControl on invalid handles.
//
// Strategy: intercept CreateFileA and CreateFileW (Win32) plus NtCreateFile
// (native API — the game uses this for device paths). For matching paths, return
// a dummy event handle and record it. Any DeviceIoControl on a dummy handle is
// intercepted and made to return success with a zeroed output buffer.
//
// NtCreateFile is also used to diagnose what h=0x6e8/h=0x9e0 actually are.
// ─────────────────────────────────────────────────────────────────────────────
(function emulateRingEdgeDevices() {
    var NULL_PTR = ptr(0);

    // Create four dummy event handles (unnamed auto-reset events).
    // Using real OS handles avoids kernel complaints about unknown handle types.
    var CreateEventA;
    try { CreateEventA = new NativeFunction(
        Module.getGlobalExportByName('CreateEventA'),
        'pointer', ['pointer', 'int', 'int', 'pointer']); }
    catch(e) { logMsg('RINGEDGE', 'CreateEventA not found: ' + e); return; }

    var FAKE = {
        jvs_pipe:  CreateEventA(NULL_PTR, 0, 0, NULL_PTR),
        mxhwreset: CreateEventA(NULL_PTR, 0, 0, NULL_PTR),
        mxsuperio: CreateEventA(NULL_PTR, 0, 0, NULL_PTR),
        mxsram:    CreateEventA(NULL_PTR, 0, 0, NULL_PTR),
        mxsmbus:   CreateEventA(NULL_PTR, 0, 0, NULL_PTR),  // amEeprom (AT24C64AN) backing
    };
    logMsg('RINGEDGE', 'fake handles: jvs_pipe=' + FAKE.jvs_pipe +
           ' mxhwreset=' + FAKE.mxhwreset +
           ' mxsuperio=' + FAKE.mxsuperio + ' mxsram=' + FAKE.mxsram +
           ' mxsmbus=' + FAKE.mxsmbus);

    // Set of fake handle string representations for fast lookup
    var fakeSet = {};
    Object.keys(FAKE).forEach(function(k) { fakeSet[FAKE[k].toString()] = k; });

    function classify(path) {
        var p = path.toLowerCase();
        if (p.indexOf('teknoparrot_jvs') >= 0) return 'jvs_pipe';
        if (p.indexOf('mxhwreset')       >= 0) return 'mxhwreset';
        if (p.indexOf('mxsuperio')       >= 0) return 'mxsuperio';
        if (p.indexOf('mxsram')          >= 0) return 'mxsram';
        if (p.indexOf('mxsmbus')         >= 0) return 'mxsmbus';
        return null;
    }

    // ── Win32 CreateFileA hook (additional attachment — existing hookFn logs first) ──
    var cfaAddr;
    try { cfaAddr = Module.getGlobalExportByName('CreateFileA'); } catch(e) {}
    if (cfaAddr) {
        Interceptor.attach(cfaAddr, {
            onEnter: function(args) {
                try { this.dev = classify(args[0].readCString()); } catch(e) { this.dev = null; }
            },
            onLeave: function(ret) {
                if (this.dev) {
                    ret.replace(FAKE[this.dev]);
                    logMsg('RINGEDGE', 'CreateFileA "' + this.dev + '" -> fake_h=' + FAKE[this.dev]);
                }
            }
        });
    }

    // ── Win32 CreateFileW hook ──
    var cfwAddr;
    try { cfwAddr = Module.getGlobalExportByName('CreateFileW'); } catch(e) {}
    if (cfwAddr) {
        Interceptor.attach(cfwAddr, {
            onEnter: function(args) {
                try { this.dev = classify(args[0].readUtf16String()); } catch(e) { this.dev = null; }
            },
            onLeave: function(ret) {
                if (this.dev) {
                    ret.replace(FAKE[this.dev]);
                    logMsg('RINGEDGE', 'CreateFileW "' + this.dev + '" -> fake_h=' + FAKE[this.dev]);
                }
            }
        });
    }

    // ── NtCreateFile hook — diagnostic + emulation ──
    // The game uses NtCreateFile (ntdll) directly for some device paths, bypassing
    // the Win32 CreateFile layer that our other hooks intercept.
    var ntcfAddr;
    try { ntcfAddr = Module.getGlobalExportByName('NtCreateFile'); } catch(e) {}
    if (ntcfAddr) {
        Interceptor.attach(ntcfAddr, {
            onEnter: function(args) {
                // args[0] = PHANDLE FileHandle (output)
                // args[2] = POBJECT_ATTRIBUTES { ULONG Length; HANDLE Root; PUNICODE_STRING Name; ... }
                this.hPtr = args[0];
                this.dev = null;
                this.path = null;
                try {
                    var oa = args[2];
                    var uni = oa.add(8).readPointer();   // PUNICODE_STRING ObjectName
                    var len = uni.readU16();              // Length in bytes
                    var buf = uni.add(4).readPointer();  // Buffer (wchar_t*)
                    this.path = buf.readUtf16String(Math.floor(len / 2));
                    this.dev = classify(this.path);
                } catch(e) {}
            },
            onLeave: function(ret) {
                if (this.dev) {
                    // Override: write fake handle into *FileHandle, return STATUS_SUCCESS
                    try { this.hPtr.writePointer(FAKE[this.dev]); } catch(e) {}
                    ret.replace(0);  // STATUS_SUCCESS
                    logMsg('RINGEDGE', 'NtCreateFile "' + this.path + '" -> ' + this.dev +
                           ' fake_h=' + FAKE[this.dev]);
                } else if (this.path) {
                    // Diagnostic: log anything else that wasn't caught by CreateFileA/W
                    // (only log device paths, skip normal files)
                    var p = (this.path || '').toLowerCase();
                    if (p.indexOf('\\\\.\\') >= 0 || p.indexOf('\\device\\') >= 0 ||
                        p.indexOf('\\??\\') >= 0 || p.indexOf('namedpipe') >= 0) {
                        var h = ptr(0);
                        try { h = this.hPtr.readPointer(); } catch(e) {}
                        var st = (ret.toInt32() >>> 0).toString(16);
                        logMsg('NtCreateFile', '"' + this.path + '" status=0x' + st + ' h=' + h);
                    }
                }
            }
        });
        logMsg('RINGEDGE', 'NtCreateFile hook installed (diagnostic + emulation)');
    }

    // ── SetupAPI hooks: make MXSMBUS_GUID device discoverable (for amEeprom) ───────
    // amEepromCreateDeviceFile (nrs FUN_00984910) finds the SMBUS device by interface
    // GUID via SetupDi*, then CreateFileA(DevicePath). The real device is absent, so we
    // advertise a single fake interface whose DevicePath is "\\.\mxsmbus" (caught by the
    // CreateFile hooks above). We ONLY intervene for MXSMBUS_GUID / our fake HDEVINFO;
    // every other SetupDi* call passes through untouched (USB/input enumeration intact).
    // GUID {5C49E1FE-3FEC-4B8D-A4B5-76BE7025D842} — confirmed in the real mxsmbus.sys.
    //
    // ENABLE_EEPROM gate: when true the eeprom emulation below is active (amEepromInit
    // succeeds, amBackup eeprom records read/write/persist, is broken=0) and the MXSMBUS
    // device is discoverable. When false the device stays undiscoverable, amEepromInit
    // fails (records -3, harmless). Making eeprom succeed advances the game into the full
    // "real cabinet" operation path; its self-shutdown before ATTRACT is disarmed by
    // app/no_selfshutdown.js.
    var ENABLE_EEPROM = true;
    var MXSMBUS_GUID = [0xFE,0xE1,0x49,0x5C, 0xEC,0x3F, 0x8D,0x4B,
                        0xA4,0xB5,0x76,0xBE,0x70,0x25,0xD8,0x42];
    var FAKE_HDEVINFO = ptr('0x5b115b00');  // sentinel HDEVINFO for our fake set
    var fakeDevInfoSet = {};
    function guidIsMxsmbus(p) {
        if (!ENABLE_EEPROM) return false;   // gate: device stays undiscoverable when off
        try { for (var i = 0; i < 16; i++) { if (p.add(i).readU8() !== MXSMBUS_GUID[i]) return false; } return true; }
        catch (e) { return false; }
    }
    function hookExport(name, onEnter, onLeave) {
        try { Interceptor.attach(Module.getGlobalExportByName(name), { onEnter: onEnter, onLeave: onLeave }); return true; }
        catch (e) { logMsg('RINGEDGE', 'SetupAPI hook ' + name + ' fail: ' + e); return false; }
    }

    // SetupDiGetClassDevsA(ClassGuid, Enumerator, hwndParent, Flags) -> HDEVINFO
    hookExport('SetupDiGetClassDevsA',
        function (args) { this.isMx = args[0] && !args[0].isNull() && guidIsMxsmbus(args[0]); },
        function (ret) {
            if (this.isMx) {
                fakeDevInfoSet[FAKE_HDEVINFO.toString()] = true;
                ret.replace(FAKE_HDEVINFO);
                logMsg('RINGEDGE', 'SetupDiGetClassDevsA(MXSMBUS_GUID) -> fake HDEVINFO');
            }
        });

    // SetupDiEnumDeviceInterfaces(DeviceInfoSet, DevInfoData, InterfaceClassGuid, MemberIndex, DeviceInterfaceData)
    hookExport('SetupDiEnumDeviceInterfaces',
        function (args) {
            this.isMx = fakeDevInfoSet[args[0].toString()] === true;
            this.idx  = args[3].toUInt32();
            this.ifd  = args[4];
        },
        function (ret) {
            if (!this.isMx) return;
            if (this.idx === 0) {
                // Minimal SP_DEVICE_INTERFACE_DATA fill: keep cbSize, set Flags=SPINT_ACTIVE(1).
                try { if (this.ifd && !this.ifd.isNull()) this.ifd.add(20).writeU32(1); } catch (e) {}
                ret.replace(1);  // TRUE
            } else {
                ret.replace(0);  // FALSE — no more interfaces (ERROR_NO_MORE_ITEMS)
            }
        });

    // SetupDiGetDeviceInterfaceDetailA(DeviceInfoSet, ifd, DeviceInterfaceDetailData, size, reqSize, DevInfoData)
    hookExport('SetupDiGetDeviceInterfaceDetailA',
        function (args) { this.isMx = fakeDevInfoSet[args[0].toString()] === true; this.detail = args[2]; this.size = args[3].toUInt32(); },
        function (ret) {
            if (!this.isMx) return;
            // SP_DEVICE_INTERFACE_DETAIL_DATA_A: { DWORD cbSize; CHAR DevicePath[]; }
            // Path starts at +4 (cbSize already 5 from caller). Caller buffer = 0x400.
            try {
                if (this.detail && !this.detail.isNull() && this.size >= 16) {
                    this.detail.add(4).writeAnsiString('\\\\.\\mxsmbus');
                }
            } catch (e) {}
            ret.replace(1);  // TRUE
            logMsg('RINGEDGE', 'SetupDiGetDeviceInterfaceDetailA -> "\\\\.\\mxsmbus"');
        });

    // SetupDiDestroyDeviceInfoList(DeviceInfoSet)
    hookExport('SetupDiDestroyDeviceInfoList',
        function (args) { this.isMx = fakeDevInfoSet[args[0].toString()] === true; },
        function (ret) { if (this.isMx) ret.replace(1); });

    // ── mxsram file-backed SRAM buffer (micetools dll/drivers/mxsram.c: 1024×2084, 0xFF init) ──
    // micetools maps SRAM_PATH via open_mapped_file (persistent). We mirror that: a 2 MB RAM
    // buffer loaded from / written through to data/nvram/sram.bin (mmap-equivalent auto-sync).
    var SRAM_SIZE = 1024 * 2084;  // 2,134,016 bytes
    var SRAM_PATH = 'C:\\src\\nrs-util\\data\\nvram\\sram.bin';
    var sramBuf = Memory.alloc(SRAM_SIZE);
    for (var si = 0; si < SRAM_SIZE; si += 65536) {
        sramBuf.add(si).writeByteArray(new Array(Math.min(65536, SRAM_SIZE - si)).fill(0xFF));
    }
    // Per-handle file pointer (micetools: ctx->m_Pointer). Keyed by handle string.
    var sramPtrs = {};
    function sramPtrGet(h)    { var k = h.toString(); return sramPtrs[k] || 0; }
    function sramPtrSet(h, v) { sramPtrs[h.toString()] = v; }

    // ── #1 persistence: native CreateFileW/ReadFile/WriteFile/SetFilePointer on the backing file ─
    // Win32 NativeFunctions (kernel32). Errors degrade to volatile + WARN, matching micetools'
    // "SRAM will be memory-backed and not syncronised!" fallback.
    var GENERIC_RW = 0xC0000000, OPEN_ALWAYS = 4, FILE_ATTR_NORMAL = 0x80, FILE_BEGIN = 0, FILE_END = 2;
    var SRAM_DIR = 'C:\\src\\nrs-util\\data\\nvram';
    var _CreateFileW, _ReadFile, _WriteFile, _SetFilePointer, _CreateDirectoryW, _GetLastError;
    try {
        _CreateFileW      = new NativeFunction(Module.getGlobalExportByName('CreateFileW'),
                              'pointer', ['pointer','uint','uint','pointer','uint','uint','pointer']);
        _ReadFile         = new NativeFunction(Module.getGlobalExportByName('ReadFile'),
                              'int', ['pointer','pointer','uint','pointer','pointer']);
        _WriteFile        = new NativeFunction(Module.getGlobalExportByName('WriteFile'),
                              'int', ['pointer','pointer','uint','pointer','pointer']);
        _SetFilePointer   = new NativeFunction(Module.getGlobalExportByName('SetFilePointer'),
                              'uint', ['pointer','int','pointer','uint']);
        _CreateDirectoryW = new NativeFunction(Module.getGlobalExportByName('CreateDirectoryW'),
                              'int', ['pointer','pointer']);
        _GetLastError     = new NativeFunction(Module.getGlobalExportByName('GetLastError'),
                              'uint', []);
    } catch (e) { logMsg('RINGEDGE', 'mxsram: file API resolve failed -> ' + e); }

    var sramBackFile = ptr(-1);   // INVALID_HANDLE_VALUE
    function sramBackOpen() {
        if (!_CreateFileW) return;
        try { _CreateDirectoryW(Memory.allocUtf16String(SRAM_DIR), ptr(0)); } catch (e) {}  // ignore if exists
        var wpath = Memory.allocUtf16String(SRAM_PATH);
        // OPEN_ALWAYS: opens or creates. GetLastError == ERROR_ALREADY_EXISTS → file pre-existed.
        sramBackFile = _CreateFileW(wpath, GENERIC_RW, 0, ptr(0), OPEN_ALWAYS, FILE_ATTR_NORMAL, ptr(0));
        if (sramBackFile.equals(ptr(-1))) {
            logMsg('RINGEDGE', 'mxsram: SRAM will be memory-backed and not syncronised! (open failed)');
            sramBackFile = ptr(-1); return;
        }
        // Reliable existence via file size (fresh OPEN_ALWAYS file has size 0).
        var existedBefore = (_SetFilePointer(sramBackFile, 0, ptr(0), FILE_END) >>> 0) >= SRAM_SIZE;
        var nbuf = Memory.alloc(4);
        if (existedBefore) {
            // Load existing image into sramBuf.
            _SetFilePointer(sramBackFile, 0, ptr(0), FILE_BEGIN);
            var ok = _ReadFile(sramBackFile, sramBuf, SRAM_SIZE, nbuf, ptr(0));
            logMsg('RINGEDGE', 'mxsram: loaded sram.bin (' + (ok ? nbuf.readU32() : 0) + ' bytes)');
        } else {
            // New file: persist the 0xFF-initialised buffer (micetools build_sram → 0xFF).
            _SetFilePointer(sramBackFile, 0, ptr(0), FILE_BEGIN);
            _WriteFile(sramBackFile, sramBuf, SRAM_SIZE, nbuf, ptr(0));
            logMsg('RINGEDGE', 'mxsram: created blank sram.bin (' + SRAM_SIZE + ' bytes, 0xFF)');
        }
    }
    // Write-through a region [off, off+len) of sramBuf to the backing file.
    function sramBackWrite(off, len) {
        if (sramBackFile.equals(ptr(-1)) || !_WriteFile) return;
        try {
            var nbuf = Memory.alloc(4);
            _SetFilePointer(sramBackFile, off, ptr(0), FILE_BEGIN);
            _WriteFile(sramBackFile, sramBuf.add(off), len, nbuf, ptr(0));
        } catch (e) {}
    }
    sramBackOpen();

    // ── AT24C64AN EEPROM store (micetools smb_at24c64an.c: 8 KB, 0xFF init, file-backed) ──
    // amEeprom (SMBUS vaddr 0x57) backing for amBackup STATIC/CREDIT/NETWORK/HISTORY records.
    var EEPROM_SIZE = 0x2000;  // 8 KB (64 kbit)
    var EEPROM_PATH = 'C:\\src\\nrs-util\\data\\nvram\\eeprom.bin';
    var eepromBuf = Memory.alloc(EEPROM_SIZE);
    eepromBuf.writeByteArray(new Array(EEPROM_SIZE).fill(0xFF));
    var eepromBackFile = ptr(-1);

    // amiCrc32R == standard CRC32 (poly 0xEDB88320, init/final ~). micetools lib/ami/amiCrc.c.
    function crc32(arr) {
        var crc = 0xFFFFFFFF;
        for (var i = 0; i < arr.length; i++) {
            crc = (crc ^ arr[i]) >>> 0;
            for (var j = 0; j < 8; j++)
                crc = (crc & 1) ? ((crc >>> 1) ^ 0xEDB88320) >>> 0 : (crc >>> 1) >>> 0;
        }
        return (~crc) >>> 0;
    }
    // Seed the AM_SYSDATAwH_STATIC record (region/serial) with a valid CRC at REG+DUP.
    // Blank (0xFF) STATIC makes amlib_storage_init_all reset region→0 and take the
    // "serial != SBVA" reformat path (FUN_0089d090) → boot stalls. Real hardware has a
    // factory STATIC record; we mirror micetools build_eeprom for STATIC only (others self-heal).
    // Layout: m_Crc[4] Rsv[8] m_Region@0xC m_Rental@0xD Rsv@0xE m_strSerialId[17]@0xF (size 0x20).
    function seedStatic(off) {
        var rec = new Array(0x20); for (var i = 0; i < 0x20; i++) rec[i] = 0;
        rec[0xC] = 0x01;                     // m_Region = JAPAN (matches region.js forced value)
        var serial = 'SBVA-01A99999999';     // must start with "SBVA" (binary strncmp check)
        for (var s = 0; s < serial.length && s < 16; s++) rec[0xF + s] = serial.charCodeAt(s);
        var crc = crc32(rec.slice(4));       // CRC over bytes [4..0x20)
        rec[0] = crc & 0xff; rec[1] = (crc >>> 8) & 0xff; rec[2] = (crc >>> 16) & 0xff; rec[3] = (crc >>> 24) & 0xff;
        eepromBuf.add(off).writeByteArray(rec);
    }
    function eepromBackOpen() {
        if (!_CreateFileW) return;
        var wpath = Memory.allocUtf16String(EEPROM_PATH);
        eepromBackFile = _CreateFileW(wpath, GENERIC_RW, 0, ptr(0), OPEN_ALWAYS, FILE_ATTR_NORMAL, ptr(0));
        if (eepromBackFile.equals(ptr(-1))) {
            logMsg('RINGEDGE', 'mxsmbus: EEPROM will be memory-backed and not syncronised! (open failed)');
            eepromBackFile = ptr(-1); return;
        }
        // Reliable existence check via file size (GetLastError-after-NativeFunction is
        // unreliable under Frida): a fresh OPEN_ALWAYS file has size 0.
        var existed = (_SetFilePointer(eepromBackFile, 0, ptr(0), FILE_END) >>> 0) >= EEPROM_SIZE;
        var nbuf = Memory.alloc(4);
        _SetFilePointer(eepromBackFile, 0, ptr(0), FILE_BEGIN);
        if (existed) {
            var ok = _ReadFile(eepromBackFile, eepromBuf, EEPROM_SIZE, nbuf, ptr(0));
            logMsg('RINGEDGE', 'mxsmbus: loaded eeprom.bin (' + (ok ? nbuf.readU32() : 0) + ' bytes)');
        } else {
            // New file: seed STATIC (region/serial) at REG(0x000)+DUP(0x200), then persist.
            seedStatic(0x000);
            seedStatic(0x200);
            _WriteFile(eepromBackFile, eepromBuf, EEPROM_SIZE, nbuf, ptr(0));
            logMsg('RINGEDGE', 'mxsmbus: created eeprom.bin (' + EEPROM_SIZE + ' bytes; STATIC seeded region=01 serial=SBVA)');
        }
    }
    function eepromRead(addr, dst, len) {
        if (addr >= EEPROM_SIZE) return 0;
        if (addr + len > EEPROM_SIZE) len = EEPROM_SIZE - addr;
        try { dst.writeByteArray(eepromBuf.add(addr).readByteArray(len)); } catch (e) { return 0; }
        return len;
    }
    function eepromWrite(addr, src, len) {
        if (addr >= EEPROM_SIZE) return 0;
        if (addr + len > EEPROM_SIZE) len = EEPROM_SIZE - addr;
        try {
            eepromBuf.add(addr).writeByteArray(src.readByteArray(len));
            if (!eepromBackFile.equals(ptr(-1)) && _WriteFile) {
                var nbuf = Memory.alloc(4);
                _SetFilePointer(eepromBackFile, addr, ptr(0), FILE_BEGIN);
                _WriteFile(eepromBackFile, eepromBuf.add(addr), len, nbuf, ptr(0));
            }
        } catch (e) { return 0; }
        return len;
    }
    eepromBackOpen();

    // W83791D bank state for mxsuperio hwmon emulation
    var w83791dBank = 0;

    // ── DeviceIoControl hook (additional attachment) ──
    // Proper IOCTL dispatch per micetools reference (not just zero-fill).
    var fakeDicCounts = {};
    Object.keys(FAKE).forEach(function(k) { fakeDicCounts[k] = 0; });

    var dicAddr;
    try { dicAddr = Module.getGlobalExportByName('DeviceIoControl'); } catch(e) {}
    if (dicAddr) {
        Interceptor.attach(dicAddr, {
            onEnter: function(args) {
                var hStr = args[0].toString();
                var dev = fakeSet[hStr];
                if (dev !== undefined) {
                    this.isFake  = true;
                    this.devName = dev;
                    this.ioctl   = args[1].toUInt32();
                    this.inBuf   = args[2];
                    this.inLen   = args[3].toUInt32();
                    this.outBuf  = args[4];
                    this.outLen  = args[5].toUInt32();
                    this.bytesRet = args[6];   // lpBytesReturned
                }
            },
            onLeave: function(ret) {
                if (!this.isFake) return;
                var dev = this.devName, ioctl = this.ioctl;
                var out = this.outBuf, outLen = this.outLen;

                // ── mxsram: faithful micetools mxsram_DeviceIoControl ──────────────
                // Only PING / GET_SECTOR_SIZE / GET_DRIVE_GEOMETRY succeed; everything
                // else (incl. IOCTL_DISK_GET_LENGTH_INFO) returns FALSE. lpBytesReturned
                // is set; only GEOMETRY zeroes its output buffer.
                if (dev === 'mxsram') {
                    var okSram = true, nret = 0;
                    if (ioctl === 0x9c406000) {            // IOCTL_MXSRAM_PING → version
                        if (out && !out.isNull() && outLen >= 4) {
                            try { out.writeU32(0x01000001); } catch(e) {}
                        }
                        nret = 4;
                    } else if (ioctl === 0x9c406004) {     // IOCTL_MXSRAM_GET_SECTOR_SIZE → 512 (RE1)
                        if (out && !out.isNull() && outLen >= 4) {
                            try { out.writeU32(512); } catch(e) {}
                        }
                        nret = 4;
                    } else if (ioctl === 0x00070000) {     // IOCTL_DISK_GET_DRIVE_GEOMETRY (24 B)
                        if (out && !out.isNull() && outLen >= 24) {
                            try {
                                out.writeByteArray(new Array(24).fill(0));  // memset (geometry only)
                                out.writeU32(256);          // Cylinders.LowPart
                                out.add(8).writeU32(12);    // MediaType = FixedMedia
                                out.add(12).writeU32(2);    // TracksPerCylinder
                                out.add(16).writeU32(8);    // SectorsPerTrack
                                out.add(20).writeU32(512);  // BytesPerSector
                            } catch(e) {}
                        }
                        nret = 24;
                    } else {
                        okSram = false;                    // unhandled → FALSE
                    }
                    if (okSram && this.bytesRet && !this.bytesRet.isNull()) {
                        try { this.bytesRet.writeU32(nret); } catch(e) {}
                    }
                    ret.replace(okSram ? 1 : 0);
                    var ns = ++fakeDicCounts[dev];
                    if (ns <= 3 || ns % 100 === 0) {
                        logMsg('RINGEDGE', 'DIC[' + ns + '] mxsram ioctl=0x' +
                               ioctl.toString(16) + (okSram ? ' -> ok' : ' -> FALSE'));
                    }
                    return;
                }

                // ── mxsmbus: amEeprom (AT24C64AN @0x57) via SMBUS I2C/REQUEST ───────
                // micetools mxsmbus.c + smb_at24c64an.c. METHOD_BUFFERED: in/out packet.
                if (dev === 'mxsmbus') {
                    var okSmb = true, nretSmb = 0, dbg = '';
                    if (ioctl === 0x9c406008) {            // IOCTL_MXSMBUS_GET_VERSION
                        if (out && !out.isNull() && outLen >= 4) { try { out.writeU32(0x01020001); } catch(e) {} }
                        nretSmb = 4; dbg = 'GET_VERSION';
                    } else if (ioctl === 0x9c40200c || ioctl === 0x9c402004) {
                        var isI2C = (ioctl === 0x9c40200c);  // I2C(0x27): WORD addr/code; REQUEST(0x25): BYTE
                        var inb = this.inBuf;
                        try {
                            if (inb && !inb.isNull() && out && !out.isNull()) {
                                var cmd = inb.add(1).readU8();
                                var vaddr, code, nbytes, dataOff;
                                if (isI2C) { vaddr = inb.add(2).readU16() & 0x7fff; code = inb.add(4).readU16(); nbytes = inb.add(6).readU8(); dataOff = 7; }
                                else       { vaddr = inb.add(2).readU8()  & 0x7f;   code = inb.add(3).readU8();  nbytes = inb.add(4).readU8(); dataOff = 5; }
                                out.writeU8(0);  // status = success
                                if (vaddr === 0x57) {            // AT24C64AN EEPROM
                                    if (cmd === 9)      eepromRead(code, out.add(dataOff), nbytes);        // READ_BLOCK
                                    else if (cmd === 8) eepromWrite(code, inb.add(dataOff), nbytes);       // WRITE_BLOCK
                                    else                out.add(dataOff).writeU8(0);                       // byte read → ready/0
                                }
                                dbg = (isI2C ? 'I2C' : 'REQ') + ' cmd=' + cmd + ' addr=0x' + vaddr.toString(16) +
                                      ' code=0x' + code.toString(16) + ' n=' + nbytes;
                            }
                        } catch(e) { dbg = 'parse-err ' + e; }
                        nretSmb = outLen;
                    } else {
                        okSmb = false; dbg = 'unhandled';
                    }
                    if (okSmb && this.bytesRet && !this.bytesRet.isNull()) { try { this.bytesRet.writeU32(nretSmb); } catch(e) {} }
                    ret.replace(okSmb ? 1 : 0);
                    var nm = ++fakeDicCounts[dev];
                    if (nm <= 10 || nm % 200 === 0) {
                        logMsg('RINGEDGE', 'DIC[' + nm + '] mxsmbus ioctl=0x' + ioctl.toString(16) +
                               ' ' + dbg + (okSmb ? '' : ' -> FALSE'));
                    }
                    return;
                }

                // ── other fake devices (mxsuperio etc.): generic zero-fill + success ──
                if (out && !out.isNull() && outLen > 0 && outLen <= 4096) {
                    try { out.writeByteArray(new Array(outLen).fill(0)); } catch(e) {}
                }
                if (dev === 'mxsuperio') {
                    if (ioctl === 0x9c406000) {
                        // IOCTL_MXSUPERIO_PING → version 0x01000001
                        if (out && !out.isNull() && outLen >= 4) {
                            try { out.writeU32(0x01000001); } catch(e) {}
                        }
                    } else if (ioctl === 0x9c40200c) {
                        // IOCTL_MXSUPERIO_HWMONITOR_LPC_READ → W83791D register read
                        if (this.inBuf && !this.inBuf.isNull() && this.inLen >= 3 &&
                            out && !out.isNull() && outLen >= 3) {
                            try {
                                var idx = this.inBuf.readU8();
                                var reg = this.inBuf.add(1).readU8();
                                var data = 0;
                                if (w83791dBank === 0) {
                                    if      (reg === 0x58) data = 0x71;
                                    else if (reg === 0x4F) data = 0xa3;
                                    else if (reg === 0x48) data = 0x11;
                                    else if (reg === 0x4E) data = 0x00;
                                    else if (reg === 0x40) data = 0x01;
                                    else if (reg === 0x27) data = 26;
                                    else if (reg === 0x20) data = 0x76;
                                    else if (reg === 0x21) data = 0x86;
                                    else if (reg === 0x23) data = 0x94;
                                    else if (reg === 0x24) data = 0xbe;
                                    else if (reg === 0x25) data = 0xd1;
                                    else if (reg === 0x47) data = 0x05;
                                } else if (w83791dBank === 1) {
                                    if      (reg === 0x50) data = 35;
                                    else if (reg === 0x51) data = 0x07;
                                }
                                out.writeU8(idx);
                                out.add(1).writeU8(reg);
                                out.add(2).writeU8(data);
                            } catch(e) {}
                        }
                    } else if (ioctl === 0x9c40a010) {
                        // IOCTL_MXSUPERIO_HWMONITOR_LPC_WRITE → update bank state
                        if (this.inBuf && !this.inBuf.isNull() && this.inLen >= 3) {
                            try {
                                var wrReg  = this.inBuf.add(1).readU8();
                                var wrData = this.inBuf.add(2).readU8();
                                if (wrReg === 0x4E) w83791dBank = wrData & 0x07;
                            } catch(e) {}
                        }
                    }
                }
                ret.replace(1);  // TRUE = success
                var n = ++fakeDicCounts[dev];
                if (n <= 3 || n % 100 === 0) {
                    logMsg('RINGEDGE', 'DIC[' + n + '] ' + dev +
                           ' ioctl=0x' + ioctl.toString(16) + ' -> ok');
                }
            }
        });
    }

    // ── mxsram SetFilePointer / ReadFile / WriteFile hooks ──
    // Game accesses SRAM via file ops on the fake handle (micetools pattern).
    var sfpAddr;
    try { sfpAddr = Module.getGlobalExportByName('SetFilePointer'); } catch(e) {}
    if (sfpAddr) {
        Interceptor.attach(sfpAddr, {
            onEnter: function(args) {
                if (fakeSet[args[0].toString()] === 'mxsram') {
                    this.isSram  = true;
                    this.h       = args[0];
                    this.distLow = args[1].toInt32();
                    this.method  = args[3].toUInt32();
                }
            },
            onLeave: function(ret) {
                if (!this.isSram) return;
                var p = sramPtrGet(this.h);
                if      (this.method === 0) p = this.distLow;          // FILE_BEGIN
                else if (this.method === 1) p += this.distLow;         // FILE_CURRENT
                else if (this.method === 2) p = SRAM_SIZE + this.distLow; // FILE_END
                if (p < 0)         p = 0;
                if (p > SRAM_SIZE) p = SRAM_SIZE;
                sramPtrSet(this.h, p);
                ret.replace(p);
                logMsg('RINGEDGE', 'SetFilePointer(mxsram) pos=' + p);
            }
        });
    }

    var rfAddr2;
    try { rfAddr2 = Module.getGlobalExportByName('ReadFile'); } catch(e) {}
    if (rfAddr2) {
        Interceptor.attach(rfAddr2, {
            onEnter: function(args) {
                if (fakeSet[args[0].toString()] === 'mxsram') {
                    this.isSram  = true;
                    this.h       = args[0];
                    this.buf     = args[1];
                    this.reqLen  = args[2].toUInt32();
                    this.lpNread = args[3];
                }
            },
            onLeave: function(ret) {
                if (!this.isSram) return;
                var pos = sramPtrGet(this.h);
                var n = Math.min(this.reqLen, Math.max(0, SRAM_SIZE - pos));
                if (n > 0 && this.buf && !this.buf.isNull()) {
                    try {
                        this.buf.writeByteArray(sramBuf.add(pos).readByteArray(n));
                        sramPtrSet(this.h, pos + n);
                    } catch(e) { n = 0; }
                }
                if (this.lpNread && !this.lpNread.isNull()) {
                    try { this.lpNread.writeU32(n); } catch(e) {}
                }
                ret.replace(1);  // micetools mxsram_ReadFile always returns TRUE
                logMsg('RINGEDGE', 'ReadFile(mxsram) req=' + this.reqLen + ' got=' + n + ' pos=' + sramPtrGet(this.h));
            }
        });
    }

    var wfAddr2;
    try { wfAddr2 = Module.getGlobalExportByName('WriteFile'); } catch(e) {}
    if (wfAddr2) {
        Interceptor.attach(wfAddr2, {
            onEnter: function(args) {
                if (fakeSet[args[0].toString()] === 'mxsram') {
                    this.isSram  = true;
                    this.h       = args[0];
                    this.buf     = args[1];
                    this.reqLen  = args[2].toUInt32();
                    this.lpNwrit = args[3];
                }
            },
            onLeave: function(ret) {
                if (!this.isSram) return;
                var pos = sramPtrGet(this.h);
                var n = Math.min(this.reqLen, Math.max(0, SRAM_SIZE - pos));
                if (n > 0 && this.buf && !this.buf.isNull()) {
                    try {
                        sramBuf.add(pos).writeByteArray(this.buf.readByteArray(n));
                        sramBackWrite(pos, n);          // #1 write-through to sram.bin
                        sramPtrSet(this.h, pos + n);
                    } catch(e) { n = 0; }
                }
                if (this.lpNwrit && !this.lpNwrit.isNull()) {
                    try { this.lpNwrit.writeU32(n); } catch(e) {}
                }
                ret.replace(1);  // micetools mxsram_WriteFile always returns TRUE
                logMsg('RINGEDGE', 'WriteFile(mxsram) req=' + this.reqLen + ' wrote=' + n + ' pos=' + sramPtrGet(this.h));
            }
        });
    }

    logMsg('RINGEDGE', 'emulateRingEdgeDevices: jvs_pipe + mxhwreset + mxsuperio + mxsram + mxsmbus ready (micetools compliant; sram.bin + eeprom.bin persistent)');
})();
