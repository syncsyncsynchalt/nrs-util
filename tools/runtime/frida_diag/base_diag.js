
// ─────────────────────────────────────────────────────────────────────────────
// 汎用 Win32 API 観測フック（診断専用 — 本番ランには含まれない）
//
// 使い方: 単体で --pid アタッチ時に読み込む。
//   python frida_monitor.py --pid <PID>  # このファイルは diag/ なので本番ランに混入しない
//
// 依存: logMsg / readWStr / readAStr / hexBuf / hookFn / parseSockAddr は
//       00_base.js（本番スクリプト）で定義される。diag/ 単体実行時は先頭に
//       00_base.js を連結するか、同等のヘルパーを用意すること。
// ─────────────────────────────────────────────────────────────────────────────

// --- File I/O ---
hookFn('CreateFileW',
    function(args) { this.path = readWStr(args[0]); this.acc = args[1].toUInt32(); },
    function(ret)  { logMsg('CreateFileW', '"' + this.path + '" acc=0x' + this.acc.toString(16) + ' h=' + ret); }
);
hookFn('CreateFileA',
    function(args) { this.path = readAStr(args[0]); },
    function(ret)  { logMsg('CreateFileA', '"' + this.path + '" h=' + ret); }
);
hookFn('ReadFile',
    function(args) { this.h = args[0].toString(16); this.buf = args[1]; this.len = args[2].toUInt32(); },
    function(ret)  {
        if (ret.toUInt32() && this.len > 0 && this.len < 256)
            logMsg('ReadFile', 'h=0x' + this.h + ' [' + hexBuf(this.buf, this.len) + ']');
    }
);
hookFn('WriteFile',
    function(args) { this.h = args[0].toString(16); this.buf = args[1]; this.len = args[2].toUInt32(); },
    function(ret)  {
        if (this.len > 0 && this.len < 256)
            logMsg('WriteFile', 'h=0x' + this.h + ' [' + hexBuf(this.buf, this.len) + ']');
    }
);

// --- Network (observation only) ---
hookFn('connect',
    function(args) { this.t = parseSockAddr(args[1]); },
    function(ret)  { logMsg('connect', this.t + ' ret=' + ret); }
);
hookFn('listen',
    function(args) { this.s = args[0].toString(16); },
    function(ret)  { logMsg('listen', 'sock=0x' + this.s + ' ret=' + ret); }
);
hookFn('WSASend',
    function(args) {
        this.nBufs = args[2].toUInt32();
        try {
            var wsaBuf = args[1];
            this.len = wsaBuf.readU32();
            this.buf = wsaBuf.add(4).readPointer();
        } catch(e) { this.len = 0; }
    },
    function(ret) {
        if (this.len > 0 && this.len < 512) {
            var str = ''; try { str = this.buf.readCString().slice(0, 100); } catch(e) {}
            logMsg('WSASend', 'len=' + this.len + ' "' + str + '"');
        }
    }
);
hookFn('WSARecv',
    function(args) {
        try {
            var wsaBuf = args[1];
            this.len = wsaBuf.readU32();
            this.buf = wsaBuf.add(4).readPointer();
        } catch(e) { this.len = 0; }
    },
    function(ret) {
        if (this.len > 0 && this.len < 512) {
            var str = ''; try { str = this.buf.readCString().slice(0, 100); } catch(e) {}
            logMsg('WSARecv', 'len=' + this.len + ' "' + str + '"');
        }
    }
);

// --- Dynamic linking ---
hookFn('GetProcAddress',
    function(args) {
        this.modH = args[0];
        var np = args[1];
        try { this.fn = np.toUInt32() < 65536 ? 'ord#' + np.toUInt32() : readAStr(np); }
        catch(e) { this.fn = '?'; }
    },
    function(ret) {
        if (ret.toUInt32()) {
            var mn = '?';
            try { var m = Process.getModuleByAddress(this.modH); mn = m ? m.name : '?'; } catch(e) {}
            logMsg('GetProcAddress', mn + '!' + this.fn + ' => ' + ret);
        }
    }
);
hookFn('LoadLibraryW',
    function(args) { this.p = readWStr(args[0]); },
    function(ret)  { logMsg('LoadLibraryW', '"' + this.p + '" h=' + ret); }
);
hookFn('LoadLibraryA',
    function(args) { this.p = readAStr(args[0]); },
    function(ret)  { logMsg('LoadLibraryA', '"' + this.p + '" h=' + ret); }
);

// --- Shared memory & IPC ---
hookFn('CreateFileMappingA',
    function(args) {
        this.size = args[4].toUInt32();
        try { this.name = readAStr(args[5]); } catch(e) { this.name = '?'; }
    },
    function(ret) { logMsg('CreateFileMappingA', 'name="' + this.name + '" size=' + this.size + ' h=' + ret); }
);
hookFn('CreateFileMappingW',
    function(args) {
        this.size = args[4].toUInt32();
        try { this.name = readWStr(args[5]); } catch(e) { this.name = '?'; }
    },
    function(ret) { logMsg('CreateFileMappingW', 'name="' + this.name + '" size=' + this.size + ' h=' + ret); }
);
hookFn('OpenFileMappingW',
    function(args) { try { this.name = readWStr(args[2]); } catch(e) { this.name = '?'; } },
    function(ret)  { logMsg('OpenFileMappingW', 'name="' + this.name + '" h=' + ret); }
);
hookFn('MapViewOfFile',
    function(args) { this.h = args[0].toString(16); this.acc = args[1].toUInt32(); },
    function(ret)  { logMsg('MapViewOfFile', 'h=0x' + this.h + ' acc=0x' + this.acc.toString(16) + ' view=' + ret); }
);
hookFn('CreateMutexW',
    function(args) { try { this.n = readWStr(args[2]); } catch(e) { this.n = '?'; } },
    function(ret)  { logMsg('CreateMutexW', '"' + this.n + '"'); }
);
hookFn('CreateNamedPipeW',
    function(args) { this.n = readWStr(args[0]); },
    function(ret)  { logMsg('CreateNamedPipeW', '"' + this.n + '" h=' + ret); }
);

// --- ini / registry ---
hookFn('GetPrivateProfileStringA',
    function(args) { this.s = readAStr(args[0]); this.k = readAStr(args[1]); this.f = readAStr(args[4]); },
    function(ret)  { logMsg('PrivateProfileA', '[' + this.s + '] ' + this.k + ' <- "' + this.f + '"'); }
);
hookFn('GetPrivateProfileStringW',
    function(args) { this.s = readWStr(args[0]); this.k = readWStr(args[1]); this.f = readWStr(args[4]); },
    function(ret)  { logMsg('PrivateProfileW', '[' + this.s + '] ' + this.k + ' <- "' + this.f + '"'); }
);
hookFn('RegOpenKeyExW',
    function(args) { this.k = readWStr(args[1]); },
    function(ret)  { logMsg('RegOpenKeyExW', '"' + this.k + '" ret=' + ret); }
);

// --- Window / display ---
hookFn('SetWindowTextA',
    function(args) { this.t = readAStr(args[1]); },
    function(ret)  { logMsg('SetWindowTextA', '"' + this.t + '"'); }
);
hookFn('SetWindowTextW',
    function(args) { this.t = readWStr(args[1]); },
    function(ret)  { logMsg('SetWindowTextW', '"' + this.t + '"'); }
);

// --- DeviceIoControl (moved from 00_base.js) ---
hookFn('DeviceIoControl',
    function(args) {
        this.h = args[0].toString(16); this.ioctl = args[1].toUInt32();
        this.inBuf = args[2]; this.inLen = args[3].toUInt32();
    },
    function(ret) {
        var hex = (this.inLen > 0 && this.inLen < 64) ? hexBuf(this.inBuf, this.inLen) : '';
        logMsg('DeviceIoControl', 'h=0x' + this.h + ' ioctl=0x' + this.ioctl.toString(16) +
               ' in[' + this.inLen + ']=[' + hex + '] ret=' + ret);
    }
);

// --- Process / threading ---
var vpN = 0;
hookFn('VirtualProtect',
    function(args) { this.a = args[0].toUInt32(); this.sz = args[1].toUInt32(); this.p = args[2].toUInt32(); },
    function(ret)  {
        vpN++;
        if (vpN <= 40 || this.p === 0x40)
            logMsg('VirtualProtect', 'addr=0x' + this.a.toString(16) + ' size=0x' + this.sz.toString(16) +
                   ' prot=0x' + this.p.toString(16));
    }
);
hookFn('CreateThread',
    function(args) { this.start = args[2].toUInt32(); },
    function(ret)  { logMsg('CreateThread', 'start=0x' + this.start.toString(16) + ' h=' + ret); }
);
