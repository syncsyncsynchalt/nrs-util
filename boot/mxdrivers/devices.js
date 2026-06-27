// subsys:      mxdrivers
// persistence: runtime   // network_role=local
// va: —
// ssot:        mxdrivers/FACTS.md
// role:        mxsram/mxsuperio/mxhwreset/jvs_pipe/mxsmbus/columba を CreateFile/NtCreateFile/DeviceIoControl フックでダミー成功。mxsram(micetools mxsram.c) + mxsmbus(AT24C64AN eeprom, SetupAPI 発見) は micetools 準拠で data/nvram/{sram,eeprom}.bin に永続。columba(SEGA DMI 読取) は micetools columba.c/dmi.c 準拠で RINGEDGE2 の DMI を返し board type=3 を解決(amBackup error(-21) 解消)。runtime

// RingEdge デバイスエミュレーション: mxhwreset / mxsuperio / mxsram / jvs_pipe
//
// TeknoParrot はこの4デバイスをエミュレートする。エミュレートしないと CreateFile が
// INVALID_HANDLE_VALUE を返し、ゲームは無効ハンドルへの DeviceIoControl で
// エラーを記録するか、クラッシュする。
//
// 方針: CreateFileA と CreateFileW（Win32）に加え NtCreateFile（native API。
// ゲームはデバイスパスにこれを使う）をフックする。一致するパスにはダミーの event
// ハンドルを返して記録する。ダミーハンドルへの DeviceIoControl はすべてフックし、
// 出力バッファをゼロ埋めして成功を返す。
(function emulateRingEdgeDevices() {
    var NULL_PTR = ptr(0);

    // ダミーの event ハンドルを4つ作る（無名の auto-reset event）。
    // 実 OS ハンドルを使うと、カーネルが未知のハンドル型を拒むのを避けられる。
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
        mxsmbus:   CreateEventA(NULL_PTR, 0, 0, NULL_PTR),  // amEeprom (AT24C64AN) のバッキング
        columba:   CreateEventA(NULL_PTR, 0, 0, NULL_PTR),  // SEGA DMI/SMBIOS 読取（board type 判定）
    };
    logMsg('RINGEDGE', 'fake handles: jvs_pipe=' + FAKE.jvs_pipe +
           ' mxhwreset=' + FAKE.mxhwreset +
           ' mxsuperio=' + FAKE.mxsuperio + ' mxsram=' + FAKE.mxsram +
           ' mxsmbus=' + FAKE.mxsmbus + ' columba=' + FAKE.columba);

    // 高速 lookup 用に、fake ハンドルの文字列表現の集合を作る
    var fakeSet = {};
    Object.keys(FAKE).forEach(function(k) { fakeSet[FAKE[k].toString()] = k; });

    function classify(path) {
        var p = path.toLowerCase();
        if (p.indexOf('teknoparrot_jvs') >= 0) return 'jvs_pipe';
        if (p.indexOf('mxhwreset')       >= 0) return 'mxhwreset';
        if (p.indexOf('mxsuperio')       >= 0) return 'mxsuperio';
        if (p.indexOf('mxsram')          >= 0) return 'mxsram';
        if (p.indexOf('mxsmbus')         >= 0) return 'mxsmbus';
        if (p.indexOf('columba')         >= 0) return 'columba';
        return null;
    }

    // Win32 CreateFileA フック（追加の attach。既存の hookFn が先にログ出力する）
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

    // Win32 CreateFileW フック
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

    // NtCreateFile フック: 診断 + エミュレーション
    // ゲームは一部のデバイスパスで NtCreateFile（ntdll）を直接使い、他のフックが捕える
    // Win32 CreateFile 層をバイパスする。
    var ntcfAddr;
    try { ntcfAddr = Module.getGlobalExportByName('NtCreateFile'); } catch(e) {}
    if (ntcfAddr) {
        Interceptor.attach(ntcfAddr, {
            onEnter: function(args) {
                // args[0] = PHANDLE FileHandle（出力）
                // args[2] = POBJECT_ATTRIBUTES { ULONG Length; HANDLE Root; PUNICODE_STRING Name; ... }
                this.hPtr = args[0];
                this.dev = null;
                this.path = null;
                try {
                    var oa = args[2];
                    var uni = oa.add(8).readPointer();   // PUNICODE_STRING ObjectName
                    var len = uni.readU16();              // Length（バイト数）
                    var buf = uni.add(4).readPointer();  // Buffer（wchar_t*）
                    this.path = buf.readUtf16String(Math.floor(len / 2));
                    this.dev = classify(this.path);
                } catch(e) {}
            },
            onLeave: function(ret) {
                if (this.dev) {
                    // 上書き: *FileHandle に fake ハンドルを書き込み、STATUS_SUCCESS を返す
                    try { this.hPtr.writePointer(FAKE[this.dev]); } catch(e) {}
                    ret.replace(0);  // STATUS_SUCCESS
                    logMsg('RINGEDGE', 'NtCreateFile "' + this.path + '" -> ' + this.dev +
                           ' fake_h=' + FAKE[this.dev]);
                } else if (this.path) {
                    // 診断: CreateFileA/W で捕えられなかったものを記録する
                    // （デバイスパスのみログ。通常ファイルはスキップ）
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

    // SetupAPI フック: MXSMBUS_GUID デバイスを発見可能にする（amEeprom 用）
    // amEepromCreateDeviceFile（nrs FUN_00984910）は SetupDi* でインタフェース GUID から
    // SMBUS デバイスを探し、CreateFileA(DevicePath) を呼ぶ。実デバイスは無いので、DevicePath が
    // "\\.\mxsmbus"（上の CreateFile フックが捕える）の fake インタフェースを1つだけ広告する。
    // 介入するのは MXSMBUS_GUID / 自前の fake HDEVINFO のときだけで、他の SetupDi* 呼び出しは
    // 素通しする（USB/入力の列挙は無傷）。
    // GUID {5C49E1FE-3FEC-4B8D-A4B5-76BE7025D842}（実 mxsmbus.sys で確認済み）。
    //
    // ENABLE_EEPROM ゲート: true のとき下の eeprom エミュレーションが有効になり（amEepromInit
    // が成功、amBackup eeprom レコードの read/write/persist、is broken=0）、MXSMBUS デバイスが
    // 発見可能になる。false のときデバイスは発見不能のまま、amEepromInit は失敗する（-3 を記録、
    // 無害）。eeprom を成功させると、ゲームは「実キャビネット」運用パスへ進む。ATTRACT 前の
    // 自己シャットダウンは app/no_selfshutdown.js で無効化する。
    var ENABLE_EEPROM = true;
    var MXSMBUS_GUID = [0xFE,0xE1,0x49,0x5C, 0xEC,0x3F, 0x8D,0x4B,
                        0xA4,0xB5,0x76,0xBE,0x70,0x25,0xD8,0x42];
    var FAKE_HDEVINFO = ptr('0x5b115b00');  // 自前の fake set 用の番兵 HDEVINFO
    var fakeDevInfoSet = {};
    function guidIsMxsmbus(p) {
        if (!ENABLE_EEPROM) return false;   // ゲート: off のときデバイスは発見不能のまま
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
                // SP_DEVICE_INTERFACE_DATA の最小限の充填: cbSize は残し Flags=SPINT_ACTIVE(1) を設定。
                try { if (this.ifd && !this.ifd.isNull()) this.ifd.add(20).writeU32(1); } catch (e) {}
                ret.replace(1);  // TRUE
            } else {
                ret.replace(0);  // FALSE。これ以上インタフェースは無い（ERROR_NO_MORE_ITEMS）
            }
        });

    // SetupDiGetDeviceInterfaceDetailA(DeviceInfoSet, ifd, DeviceInterfaceDetailData, size, reqSize, DevInfoData)
    hookExport('SetupDiGetDeviceInterfaceDetailA',
        function (args) { this.isMx = fakeDevInfoSet[args[0].toString()] === true; this.detail = args[2]; this.size = args[3].toUInt32(); },
        function (ret) {
            if (!this.isMx) return;
            // SP_DEVICE_INTERFACE_DETAIL_DATA_A: { DWORD cbSize; CHAR DevicePath[]; }
            // パスは +4 から始まる（cbSize は呼び出し側が既に 5 を入れている）。呼び出し側バッファ = 0x400。
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

    // mxsram のファイルバックな SRAM バッファ（micetools dll/drivers/mxsram.c: 1024×2084, 0xFF 初期化）
    // micetools は SRAM_PATH を open_mapped_file で map する（永続）。それを踏襲し、data/nvram/sram.bin
    // から読み込み・書き戻す 2 MB の RAM バッファを使う（mmap 相当の自動同期）。
    var SRAM_SIZE = 1024 * 2084;  // 2,134,016 バイト
    var SRAM_PATH = 'C:\\src\\nrs-util\\data\\nvram\\sram.bin';
    var sramBuf = Memory.alloc(SRAM_SIZE);
    for (var si = 0; si < SRAM_SIZE; si += 65536) {
        sramBuf.add(si).writeByteArray(new Array(Math.min(65536, SRAM_SIZE - si)).fill(0xFF));
    }
    // ハンドルごとのファイルポインタ（micetools: ctx->m_Pointer）。ハンドル文字列をキーにする。
    var sramPtrs = {};
    function sramPtrGet(h)    { var k = h.toString(); return sramPtrs[k] || 0; }
    function sramPtrSet(h, v) { sramPtrs[h.toString()] = v; }

    // #1 永続化: バッキングファイルへの native CreateFileW/ReadFile/WriteFile/SetFilePointer
    // Win32 NativeFunctions（kernel32）。エラー時は volatile + WARN に縮退し、micetools の
    // "SRAM will be memory-backed and not syncronised!" フォールバックに合わせる。
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
        try { _CreateDirectoryW(Memory.allocUtf16String(SRAM_DIR), ptr(0)); } catch (e) {}  // 既存なら無視
        var wpath = Memory.allocUtf16String(SRAM_PATH);
        // OPEN_ALWAYS: 開くか作成する。GetLastError == ERROR_ALREADY_EXISTS → ファイルは既存だった。
        sramBackFile = _CreateFileW(wpath, GENERIC_RW, 0, ptr(0), OPEN_ALWAYS, FILE_ATTR_NORMAL, ptr(0));
        if (sramBackFile.equals(ptr(-1))) {
            logMsg('RINGEDGE', 'mxsram: SRAM will be memory-backed and not syncronised! (open failed)');
            sramBackFile = ptr(-1); return;
        }
        // ファイルサイズで存在を確実に判定する（新規の OPEN_ALWAYS ファイルはサイズ 0）。
        var existedBefore = (_SetFilePointer(sramBackFile, 0, ptr(0), FILE_END) >>> 0) >= SRAM_SIZE;
        var nbuf = Memory.alloc(4);
        if (existedBefore) {
            // 既存イメージを sramBuf に読み込む。
            _SetFilePointer(sramBackFile, 0, ptr(0), FILE_BEGIN);
            var ok = _ReadFile(sramBackFile, sramBuf, SRAM_SIZE, nbuf, ptr(0));
            logMsg('RINGEDGE', 'mxsram: loaded sram.bin (' + (ok ? nbuf.readU32() : 0) + ' bytes)');
        } else {
            // 新規ファイル: 0xFF 初期化済みバッファを永続化する（micetools build_sram → 0xFF）。
            _SetFilePointer(sramBackFile, 0, ptr(0), FILE_BEGIN);
            _WriteFile(sramBackFile, sramBuf, SRAM_SIZE, nbuf, ptr(0));
            logMsg('RINGEDGE', 'mxsram: created blank sram.bin (' + SRAM_SIZE + ' bytes, 0xFF)');
        }
    }
    // sramBuf の領域 [off, off+len) をバッキングファイルへ write-through する。
    function sramBackWrite(off, len) {
        if (sramBackFile.equals(ptr(-1)) || !_WriteFile) return;
        try {
            var nbuf = Memory.alloc(4);
            _SetFilePointer(sramBackFile, off, ptr(0), FILE_BEGIN);
            _WriteFile(sramBackFile, sramBuf.add(off), len, nbuf, ptr(0));
        } catch (e) {}
    }
    sramBackOpen();

    // AT24C64AN EEPROM ストア（micetools smb_at24c64an.c: 8 KB, 0xFF 初期化, ファイルバック）
    // amBackup の STATIC/CREDIT/NETWORK/HISTORY レコード用の amEeprom（SMBUS vaddr 0x57）バッキング。
    var EEPROM_SIZE = 0x2000;  // 8 KB（64 kbit）
    var EEPROM_PATH = 'C:\\src\\nrs-util\\data\\nvram\\eeprom.bin';
    var eepromBuf = Memory.alloc(EEPROM_SIZE);
    eepromBuf.writeByteArray(new Array(EEPROM_SIZE).fill(0xFF));
    var eepromBackFile = ptr(-1);

    // amiCrc32R == 標準 CRC32（poly 0xEDB88320, init/final ~）。micetools lib/ami/amiCrc.c。
    function crc32(arr) {
        var crc = 0xFFFFFFFF;
        for (var i = 0; i < arr.length; i++) {
            crc = (crc ^ arr[i]) >>> 0;
            for (var j = 0; j < 8; j++)
                crc = (crc & 1) ? ((crc >>> 1) ^ 0xEDB88320) >>> 0 : (crc >>> 1) >>> 0;
        }
        return (~crc) >>> 0;
    }
    // AM_SYSDATAwH_STATIC レコード（region/serial）を REG+DUP に有効な CRC 付きで seed する。
    // 空（0xFF）の STATIC だと amlib_storage_init_all が region→0 にリセットし、
    // "serial != SBVA" の再フォーマットパス（FUN_0089d090）に入る → ブート停止。実機には
    // 工場出荷の STATIC レコードがある。micetools build_eeprom を STATIC のみ踏襲する（他は自己修復）。
    // レイアウト: m_Crc[4] Rsv[8] m_Region@0xC m_Rental@0xD Rsv@0xE m_strSerialId[17]@0xF（size 0x20）。
    function seedStatic(off) {
        var rec = new Array(0x20); for (var i = 0; i < 0x20; i++) rec[i] = 0;
        rec[0xC] = 0x01;                     // m_Region = JAPAN（region.js の強制値と一致）
        var serial = 'SBVA-01A99999999';     // "SBVA" で始まる必要あり（バイナリの strncmp チェック）
        for (var s = 0; s < serial.length && s < 16; s++) rec[0xF + s] = serial.charCodeAt(s);
        var crc = crc32(rec.slice(4));       // バイト [4..0x20) の CRC
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
        // ファイルサイズで存在を確実に判定する（NativeFunction 後の GetLastError は Frida 下では
        // 信頼できない）: 新規の OPEN_ALWAYS ファイルはサイズ 0。
        var existed = (_SetFilePointer(eepromBackFile, 0, ptr(0), FILE_END) >>> 0) >= EEPROM_SIZE;
        var nbuf = Memory.alloc(4);
        _SetFilePointer(eepromBackFile, 0, ptr(0), FILE_BEGIN);
        if (existed) {
            var ok = _ReadFile(eepromBackFile, eepromBuf, EEPROM_SIZE, nbuf, ptr(0));
            logMsg('RINGEDGE', 'mxsmbus: loaded eeprom.bin (' + (ok ? nbuf.readU32() : 0) + ' bytes)');
        } else {
            // 新規ファイル: REG(0x000)+DUP(0x200) に STATIC（region/serial）を seed し、永続化する。
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

    // ── columba (SEGA DMI/SMBIOS 物理メモリ読取ドライバ) の DMI テーブル ─────────
    // 正: micetools dll/drivers/columba.c + lib/mice/dmi.c + lib/am/amOemstring.c。
    // nrs.exe の amOemstring/amPlatformGetBoardType(FUN_00988c10) が
    //   CreateFileW("\\.\columba") → DeviceIoControl(IOCTL_COLUMBA_READ=0x9c406104)
    // で物理メモリ(DMI領域)を読み、System Manufacturer と OEM 文字列から board type を決める。
    // columba が無い(本来は SEGA ドライバ)と:
    //   ① OEM 読取が成功せず DAT_01296158 がキャッシュされない → 毎回 columba を開き直す(洪水)
    //   ② board type 不明 → amBackup_getAreaDescriptor(0x982f40) が null → amBackupRecordWriteDup error(-21)
    // RINGEDGE2(本機 v63.01.10) の DMI を返すと board type=3 に解決し、両症状が消える。
    // 物理アドレス: 0xF0000 → "_DMI_" アンカーヘッダ / 0xF1000 → DMI テーブル本体。
    var DMI_HEADER_PHYS = 0xF0000;
    var DMI_TABLES_PHYS = 0xF1000;

    // micetools dmi_append_with_strings 相当: 整形領域(struct)+各文字列(null終端)+末尾null。
    function dmiSection(structBytes, strings) {
        var out = structBytes.slice();
        for (var i = 0; i < strings.length; i++) {
            for (var c = 0; c < strings[i].length; c++) out.push(strings[i].charCodeAt(c) & 0xff);
            out.push(0);                  // 各文字列の null 終端
        }
        out.push(0);                      // セクション末尾の double-null
        return out;
    }
    // micetools dmi_build_default() の MICE_PLATFORM_RINGEDGE2 分岐そのもの。
    // パーサ(amiOemstringLoadStrings)は header->Length で整形領域を飛ばす。System/String は
    // Length==sizeof なので文字列 index がそのまま一致する（Manufacturer=#0, OEM=#0..4）。
    // BIOS は Length=0x12 < struct 22B（micetools と同一の版差。board type には無関係）。
    var dmiBios = dmiSection(
        [0x00, 0x12, 0x00,0x00, 0x01, 0x02, 0x00,0x00, 0x03, 0x00,
         0x1f,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x08, 0x0f, 0xff, 0xff],
        ['American Megatrends Inc.', '080015 ', '07/28/2011']);
    // System(type1): Manufacturer 文字列(#0) = "NEC"（RINGEDGE2 の System Manufacturer）。
    var dmiSystem = dmiSection(
        [0x01, 0x08, 0x01,0x00, 0x01, 0x02, 0x03, 0x04],
        ['NEC', 'To Be Filled By O.E.M.', 'To Be Filled By O.E.M.', 'To Be Filled By O.E.M.']);
    // OEM strings(type11): #2="AAL"(platform id) / #4="AAL2"(board type)。
    // nrs amPlatformGetBoardType は ("AAL"&&"NEC"&&"AAL2") → board type=3 と判定する。
    var dmiStrings = dmiSection(
        [0x0b, 0x05, 0x02,0x00, 0x05],
        ['DAC-BJ02', 'DAC-BJ02', 'AAL', 'Advantech', 'AAL2']);
    var dmiTableBytes = dmiBios.concat(dmiSystem).concat(dmiStrings);
    var dmiLen = dmiTableBytes.length;    // = 0xC0 (192)

    // "_DMI_" アンカー(16B): Signature/Checksum/StructLength@6/StructAddr@8/NumStructs@12。
    // 探索側(amiOemstringLocateDMITable)は "_DMI_" と +6 length / +8 base のみ参照（checksum 不問）。
    var dmiHeaderBytes = [0x5f,0x44,0x4d,0x49,0x5f, 0x00,
                          dmiLen & 0xff, (dmiLen >>> 8) & 0xff,
                          DMI_TABLES_PHYS & 0xff, (DMI_TABLES_PHYS >>> 8) & 0xff,
                          (DMI_TABLES_PHYS >>> 16) & 0xff, (DMI_TABLES_PHYS >>> 24) & 0xff,
                          0x20, 0x00, 0x00, 0x00];

    // 出力ゼロ埋め用の事前確保バッファ（micetools の memset 相当。table 読取は 0x10000B 固定）。
    var dmiZero = Memory.alloc(0x10000);
    dmiZero.writeByteArray(new Array(0x10000).fill(0));
    logMsg('RINGEDGE', 'columba DMI built (' + dmiLen +
           ' B; RINGEDGE2 Manufacturer=NEC platform=AAL board=AAL2 -> boardType 3)');

    // mxsuperio hwmon エミュレーション用の W83791D bank 状態
    var w83791dBank = 0;

    // DeviceIoControl フック（追加の attach）
    // micetools 参照実装に沿った正式な IOCTL ディスパッチ（単なるゼロ埋めではない）。
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

                // mxsram: micetools mxsram_DeviceIoControl に忠実
                // 成功するのは PING / GET_SECTOR_SIZE / GET_DRIVE_GEOMETRY のみ。それ以外
                //（IOCTL_DISK_GET_LENGTH_INFO 含む）は FALSE を返す。lpBytesReturned は
                // 設定する。出力バッファをゼロ埋めするのは GEOMETRY だけ。
                if (dev === 'mxsram') {
                    var okSram = true, nret = 0;
                    if (ioctl === 0x9c406000) {            // IOCTL_MXSRAM_PING → バージョン
                        if (out && !out.isNull() && outLen >= 4) {
                            try { out.writeU32(0x01000001); } catch(e) {}
                        }
                        nret = 4;
                    } else if (ioctl === 0x9c406004) {     // IOCTL_MXSRAM_GET_SECTOR_SIZE → 512（RE1）
                        if (out && !out.isNull() && outLen >= 4) {
                            try { out.writeU32(512); } catch(e) {}
                        }
                        nret = 4;
                    } else if (ioctl === 0x00070000) {     // IOCTL_DISK_GET_DRIVE_GEOMETRY（24 B）
                        if (out && !out.isNull() && outLen >= 24) {
                            try {
                                out.writeByteArray(new Array(24).fill(0));  // memset（geometry のみ）
                                out.writeU32(256);          // Cylinders.LowPart
                                out.add(8).writeU32(12);    // MediaType = FixedMedia
                                out.add(12).writeU32(2);    // TracksPerCylinder
                                out.add(16).writeU32(8);    // SectorsPerTrack
                                out.add(20).writeU32(512);  // BytesPerSector
                            } catch(e) {}
                        }
                        nret = 24;
                    } else {
                        okSram = false;                    // 未処理 → FALSE
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

                // mxsmbus: SMBUS I2C/REQUEST 経由の amEeprom（AT24C64AN @0x57）
                // micetools mxsmbus.c + smb_at24c64an.c。METHOD_BUFFERED: in/out パケット。
                if (dev === 'mxsmbus') {
                    var okSmb = true, nretSmb = 0, dbg = '';
                    if (ioctl === 0x9c406008) {            // IOCTL_MXSMBUS_GET_VERSION
                        if (out && !out.isNull() && outLen >= 4) { try { out.writeU32(0x01020001); } catch(e) {} }
                        nretSmb = 4; dbg = 'GET_VERSION';
                    } else if (ioctl === 0x9c40200c || ioctl === 0x9c402004) {
                        var isI2C = (ioctl === 0x9c40200c);  // I2C(0x27): WORD の addr/code; REQUEST(0x25): BYTE
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
                                    else                out.add(dataOff).writeU8(0);                       // byte read → ready/0 を返す
                                }
                                dbg = (isI2C ? 'I2C' : 'REQ') + ' cmd=' + cmd + ' addr=0x' + vaddr.toString(16) +
                                      ' code=0x' + code.toString(16) + ' n=' + nbytes;
                            }
                        } catch(e) { dbg = 'parse-err ' + e; }
                        nretSmb = outLen;
                    } else {
                        okSmb = false; dbg = 'unhandled';   // 未処理
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

                // columba: SEGA DMI/SMBIOS 物理メモリ読取（micetools columba_DeviceIoControl 準拠）
                // IOCTL_COLUMBA_READ(0x9c406104) のみ処理。AM_COLUMBA_REQUEST(0x10B):
                //   physAddr(LE u64)@0 / elementSize@8 / elementCount@0xc。
                if (dev === 'columba') {
                    var okCol = false, nretCol = 0, dbgCol = '';
                    if (ioctl === 0x9c406104 && this.inBuf && !this.inBuf.isNull() &&
                        out && !out.isNull()) {
                        try {
                            var physLo   = this.inBuf.readU32();           // physAddr.LowPart
                            var elemSize = this.inBuf.add(8).readU32();
                            var elemCnt  = this.inBuf.add(0xc).readU32();
                            var zlen = outLen < 0x10000 ? outLen : 0x10000; // micetools: memset 全体
                            if (zlen > 0) out.writeByteArray(dmiZero.readByteArray(zlen));
                            if (physLo === DMI_HEADER_PHYS) {
                                if (outLen >= dmiHeaderBytes.length) out.writeByteArray(dmiHeaderBytes);
                                nretCol = (elemSize * elemCnt) >>> 0;       // 要求バイト数を返す
                                okCol = true; dbgCol = 'DMI header';
                            } else if (physLo === DMI_TABLES_PHYS) {
                                if (outLen >= dmiLen) out.writeByteArray(dmiTableBytes);
                                nretCol = 0x10000;                          // table 読取は固定 0x10000
                                okCol = true; dbgCol = 'DMI tables';
                            } else {
                                dbgCol = 'unmapped 0x' + physLo.toString(16); // micetools: FALSE
                            }
                        } catch(e) { dbgCol = 'parse-err ' + e; }
                    } else {
                        dbgCol = 'ioctl=0x' + ioctl.toString(16);
                    }
                    if (okCol && this.bytesRet && !this.bytesRet.isNull()) {
                        try { this.bytesRet.writeU32(nretCol); } catch(e) {}
                    }
                    ret.replace(okCol ? 1 : 0);
                    var nc = ++fakeDicCounts[dev];
                    if (nc <= 6 || nc % 100 === 0) {
                        logMsg('RINGEDGE', 'DIC[' + nc + '] columba ' + dbgCol +
                               (okCol ? ' -> ok' : ' -> FALSE'));
                    }
                    return;
                }

                // 他の fake デバイス（mxsuperio 等）: 汎用のゼロ埋め + 成功
                if (out && !out.isNull() && outLen > 0 && outLen <= 4096) {
                    try { out.writeByteArray(new Array(outLen).fill(0)); } catch(e) {}
                }
                if (dev === 'mxsuperio') {
                    if (ioctl === 0x9c406000) {
                        // IOCTL_MXSUPERIO_PING → バージョン 0x01000001
                        if (out && !out.isNull() && outLen >= 4) {
                            try { out.writeU32(0x01000001); } catch(e) {}
                        }
                    } else if (ioctl === 0x9c40200c) {
                        // IOCTL_MXSUPERIO_HWMONITOR_LPC_READ → W83791D レジスタ読み出し
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
                        // IOCTL_MXSUPERIO_HWMONITOR_LPC_WRITE → bank 状態を更新
                        if (this.inBuf && !this.inBuf.isNull() && this.inLen >= 3) {
                            try {
                                var wrReg  = this.inBuf.add(1).readU8();
                                var wrData = this.inBuf.add(2).readU8();
                                if (wrReg === 0x4E) w83791dBank = wrData & 0x07;
                            } catch(e) {}
                        }
                    }
                }
                ret.replace(1);  // TRUE = 成功
                var n = ++fakeDicCounts[dev];
                if (n <= 3 || n % 100 === 0) {
                    logMsg('RINGEDGE', 'DIC[' + n + '] ' + dev +
                           ' ioctl=0x' + ioctl.toString(16) + ' -> ok');
                }
            }
        });
    }

    // mxsram の SetFilePointer / ReadFile / WriteFile フック
    // ゲームは fake ハンドルへのファイル操作で SRAM にアクセスする（micetools のパターン）。
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
                ret.replace(1);  // micetools mxsram_ReadFile は常に TRUE を返す
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
                        sramBackWrite(pos, n);          // #1 sram.bin へ write-through
                        sramPtrSet(this.h, pos + n);
                    } catch(e) { n = 0; }
                }
                if (this.lpNwrit && !this.lpNwrit.isNull()) {
                    try { this.lpNwrit.writeU32(n); } catch(e) {}
                }
                ret.replace(1);  // micetools mxsram_WriteFile は常に TRUE を返す
                logMsg('RINGEDGE', 'WriteFile(mxsram) req=' + this.reqLen + ' wrote=' + n + ' pos=' + sramPtrGet(this.h));
            }
        });
    }

    logMsg('RINGEDGE', 'emulateRingEdgeDevices: jvs_pipe + mxhwreset + mxsuperio + mxsram + mxsmbus ready (micetools compliant; sram.bin + eeprom.bin persistent)');
})();
