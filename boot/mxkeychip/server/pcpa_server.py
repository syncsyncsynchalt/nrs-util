"""
Minimal PCPA server for nrs.exe (NRS RingEdge).

Implements just enough of the PCP/PCPA protocol to let amDongleSetupKeychip
and keychipSM complete without a real keychip:

  Setup sequence (outerSM):
    - keychip.appboot.systemflag=? -> systemflag=00 (no dev mode)
    - keychip.version=? -> version=0001
    -> done_init=1, available=1

  Auth sequence (keychipSM):
    - keychip.ds.compute=<hex>  -> code=54 (ERR_COMMAND = bypass DS28CN01)
    - keychip.ssd.proof=<hex>   -> code=54 (bypass SSD proof)

  Other commands return code=0 (OK) with plausible values.

Wire protocol (server-side):
  S->C: >
  C->S: key1=val1&key2=val2\r\n
  S->C: key=value\r\n>          (response + next prompt combined)

Reference: micetools (Bottersnike/micetools), sega.bsnk.me/ringedge/
"""

import socket
import threading
import time
import sys
import datetime
import ctypes
import ctypes.wintypes
import os
try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    tomllib = None

# ── Cabinet profile (cabinet/default.toml) = identity/network/billing の単一ソース ──
# 見つからない/失敗時は従来のハードコード相当の既定値にフォールバック。
# ★将来ネットワーク: 各筐体で keyid/mainid/serial を distinct にし、network.host を共有ホストへ。
def _load_cabinet():
    cfg = {
        'identity': {'gameid': 'SBVA', 'region': '01', 'platformid': 'AAA', 'systemflag': '00',
                     'keyid': '0000000000000000', 'mainid': '00000000000', 'serial': 'ABG1234567'},
        'network':  {'ip': '192.168.1.209', 'mask': '255.255.255.0', 'gateway': '192.168.1.1',
                     'dns1': '192.168.1.1', 'dns2': '0.0.0.0', 'host': '127.0.0.1'},
        'billing':  {'freeplay': True, 'playlimit': 'FFFFFFFF'},
    }
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        '..', '..', '..', 'cabinet', 'default.toml')
    if tomllib and os.path.isfile(path):
        try:
            with open(path, 'rb') as f:
                loaded = tomllib.load(f)
            for sec, d in cfg.items():
                d.update(loaded.get(sec, {}))
        except Exception as e:  # noqa: BLE001
            print(f'[cabinet] load failed ({e}); using defaults', flush=True)
    return cfg

CFG = _load_cabinet()
ID, NET, BILL = CFG['identity'], CFG['network'], CFG['billing']

PORTS = [40100, 40102, 40104, 40106, 40110, 40111, 40113]
# 40100: mxmaster (foreground process manager)
# 40102: appslot (query_application_status, query_slot_status, check_appdata)
# 40104: amNet (query_dhcp_status, query_nic_status)
# 40106: keychip setup + ds.compute (confirmed by Frida: keychip.ds.compute goes here, NOT 40110)
# 40110: keychip ctrl (ssd.proof, stopcatcher, billing, etc.)
# 40111: keychip data (TBD)
# 40113: mx-catcher service (pause, stopcatcher — direct winsock, not via pcpaOpenClient)

def ts():
    return datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]

def log(port, direction, msg):
    print(f'[{ts()}][PCPA:{port}] {direction} {msg}', flush=True)

# -------------------------------------------------------------------
# Per-request response logic
# -------------------------------------------------------------------

def handle_request(kv, port):
    """
    kv: dict of {key: value} from the parsed client request.
    Returns the PCPA response string (may contain multiple key=value lines separated by \r\n,
    NO trailing \r\n or >).
    The caller appends \r\n>.
    """
    # ---------------------------------------------------------------
    # mxmaster protocol (port 40100): foreground process management
    # The game (nrs.exe) connects to mxmaster as a CLIENT and sends
    # these commands to register itself or query boot state.
    # Reference: micetools/micemaster/callbacks/foreground.c
    # ---------------------------------------------------------------

    # mxmaster.foreground.getcount=N -> echo key + count=0
    if 'mxmaster.foreground.getcount' in kv:
        n = kv['mxmaster.foreground.getcount']
        return f'mxmaster.foreground.getcount={n}\r\ncount=0'

    # mxmaster.foreground.active=0/1/? -> foreground management
    if 'mxmaster.foreground.active' in kv:
        val = kv['mxmaster.foreground.active']
        if val == '?':
            # Real mxmaster starts with m_current=1 (non-develop mode),
            # so the game is always already the foreground app.
            return 'mxmaster.foreground.active=1'
        if val == '1':
            # Game claims foreground. Real mxmaster: if m_current was already 1
            # (set by mxMasterSysProcessesStart), it returns active=1 + code=2.
            # We omit code=2 since the game handles the "already active" case fine.
            return 'mxmaster.foreground.active=1'
        return f'mxmaster.foreground.active={val}'

    # mxmaster.foreground.next=N -> acknowledge
    if 'mxmaster.foreground.next' in kv:
        n = kv['mxmaster.foreground.next']
        return f'mxmaster.foreground.next={n}'

    # mxmaster.foreground.current=? -> currently active slot = 1 (game, non-develop mode)
    if 'mxmaster.foreground.current' in kv:
        return 'mxmaster.foreground.current=1'

    # mxmaster.foreground.fault=? -> no fault
    if 'mxmaster.foreground.fault' in kv:
        return 'mxmaster.foreground.fault=0'

    # mxmaster.foreground.setcount -> acknowledge
    if 'mxmaster.foreground.setcount' in kv:
        n = kv['mxmaster.foreground.setcount']
        cnt = kv.get('count', '0')
        return f'mxmaster.foreground.setcount={n}\r\ncount={cnt}'

    # ---------------------------------------------------------------
    # Auth bypass: DS28CN01 challenge and SSD proof -> code=54 skips verification
    if 'keychip.ds.compute' in kv:
        return 'code=54'
    if 'keychip.ssd.proof' in kv:
        return 'code=54'
    if 'keychip.ssd.hostproof' in kv:
        return 'code=54'

    # Setup sequence
    if 'keychip.appboot.systemflag' in kv:
        return f'keychip.appboot.systemflag={ID["systemflag"]}'   # bit0=develop (cabinet identity)

    if 'keychip.version' in kv:
        return 'keychip.version=0001'             # hex: version=0x0001

    # App-boot info (may be queried later)
    if 'keychip.appboot.gameid' in kv:
        return f'keychip.appboot.gameid={ID["gameid"]}'
    if 'keychip.appboot.region' in kv:
        # region=01=JAPAN. nrs.exe is a JAPAN build: region check
        # FUN_00458fd0/FUN_0045a7f0 require (game_region & dongle_region & 5) != 0.
        # game_region (DAT_016014c4) has bit0 set (JAPAN), so 0x02(USA) & 5 == 0 → Region error.
        # FUN_0048f9c0 decodes the byte as 0x01=JAPAN/0x02=USA/0x08=EXPORT.
        # Matches TeknoParrot profile DongleRegion/PcbRegion=JAPAN.
        return f'keychip.appboot.region={ID["region"]}'        # cabinet identity.region (01=JAPAN)
    if 'keychip.appboot.platformid' in kv:
        return f'keychip.appboot.platformid={ID["platformid"]}'
    if 'keychip.appboot.modeltype' in kv:
        return 'keychip.appboot.modeltype=00'
    if 'keychip.appboot.formattype' in kv:
        return 'keychip.appboot.formattype=00'
    if 'keychip.appboot.networkaddr' in kv:
        # amDongleGetNetworkAddress (req 9). この値は amNet の ip_match_check (0x45a000) が
        #   (mask & nic_ip) == (networkaddr & mask)
        # で nic IP と同一 /24 にあるか検査する参照アドレス。不一致だと network 接続 SM
        # FUN_006fe040 が「接続済み」へ進めず Error 8001 (Network address error)。よって nic IP
        # (NET["ip"]) と同一 /24 にする（cabinet network と整合; 同一 /24 の任意ホストで可）。
        return f'keychip.appboot.networkaddr={NET["gateway"]}'
    if 'keychip.appboot.dvdflag' in kv:
        return 'keychip.appboot.dvdflag=00'
    if 'keychip.appboot.seed' in kv:
        # Binary mode not implemented; return -1 (no seed) so game continues
        return 'keychip.appboot.seed=-1'

    # Crypto (AES) - return zeroed cipher/plaintext
    if 'keychip.encrypt' in kv:
        return 'keychip.encrypt=00000000000000000000000000000000'
    if 'keychip.decrypt' in kv:
        return 'keychip.decrypt=00000000000000000000000000000000'
    if 'keychip.setiv' in kv:
        return 'keychip.setiv=1'

    # Billing
    if 'keychip.billing.keyid' in kv:
        return f'keychip.billing.keyid={ID["keyid"]}'
    if 'keychip.billing.mainid' in kv:
        return f'keychip.billing.mainid={ID["mainid"]}'
    if 'keychip.billing.playcount' in kv:
        return 'keychip.billing.playcount=00000000'
    if 'keychip.billing.playlimit' in kv:
        return f'keychip.billing.playlimit={BILL["playlimit"]}'
    if 'keychip.billing.nearfull' in kv:
        return 'keychip.billing.nearfull=00000000'

    # Trace-data / status
    if 'keychip.tracedata.restore' in kv:
        return 'keychip.tracedata.restore=0'
    if 'keychip.tracedata.put' in kv:
        return 'keychip.tracedata.put=0'
    if 'keychip.tracedata.get' in kv:
        return 'keychip.tracedata.get='
    if 'keychip.tracedata.sectorerase' in kv:
        return 'keychip.tracedata.sectorerase=0'

    # ---------------------------------------------------------------
    # Application/slot manager (port 40102): outerSM and keychipSM queries
    if 'request' in kv:
        req = kv['request']
        if req == 'query_application_status':
            return 'status=0'
        if req == 'query_slot_status':
            return 'status=0'
        if req == 'check_appdata':
            return 'code=0'
        if req == 'query_appdata_status':
            return 'status=0'
        if req == 'query_dhcp_status':
            # PCP fields are '&'-separated. The game's parser pcppChangeRequest (FUN_0098bb30)
            # STOPS at the first \r or \n, so \r\n-separated fields make it register only the first
            # pair (response=query_dhcp_status); 'result'/'dhcp_status' are dropped and the extractor
            # amNetworkResponseCheck (0x9814E0) returns -1 (no 'result'). Use '&' like every other
            # response; the caller appends the \r\n> terminator. dhcp_status=3 = "obtained".
            return f'response=query_dhcp_status&result=0&dhcp_status=3&ip_address={NET["ip"]}&subnetmask={NET["mask"]}&gateway={NET["gateway"]}'
        if req == 'query_nic_status':
            # '&'-separated (see query_dhcp_status). status=1: link up.
            # ip_address triggers bind(ip:23456).
            return f'response=query_nic_status&result=0&status=1&ip_address={NET["ip"]}&subnetmask={NET["mask"]}&gateway={NET["gateway"]}&primary_dns={NET["dns1"]}&secondary_dns={NET["dns2"]}'
        if req == 'get_status':
            # FUN_0098aae0 parses fields separated by '&' on a single line (not \r\n).
            # FUN_00974b00 (get_status parser): finds "status" field via FUN_0098aae0.
            # status=incorrect(3): SM state6 → 3!=2 AND 3<4 → advance to state7.
            # FUN_00975140 patched to 0 in Frida (result= check bypassed).
            return 'response=get_status&result=0&status=incorrect'
        if req == 'set_auth_params':
            # FUN_0098aae0 parses fields separated by '&' on a single line.
            return 'response=set_auth_params&result=0&bbflag=1'
        if req == 'isrelease':
            # HLSM state3 sends this; response parser reads param_1+0x24 ("release" field).
            # Frida HLSM hook also forces param_1+0x24=1 directly when state=4 is entered.
            # release=1 → isrelease result = 1 → state4 succeeds → param_1[2]=1.
            return 'response=isrelease&result=0&release=1'
        if req == 'resume':
            return 'response=resume&result=0'
        if req == 'pause':
            # mx-catcher (port 40113) pause request from HLSM state-9.
            # Frida recv hook also rewrites code=0 to this format as a belt-and-suspenders fix.
            return 'response=pause&result=0'
        if req == 'stopcatcher':
            return 'response=stopcatcher&result=0'
        # Any other request= query: OK
        return 'code=0'

    # Default: OK, no data
    return 'code=0'

# -------------------------------------------------------------------
# Client handler
# -------------------------------------------------------------------

def parse_kv(line):
    """Parse 'key1=val1&key2=val2' into a dict. Values may be '?'."""
    kv = {}
    for pair in line.split('&'):
        pair = pair.strip()
        if not pair:
            continue
        if '=' in pair:
            k, v = pair.split('=', 1)
            kv[k.strip()] = v.strip()
    return kv

def handle_client(conn, addr, port):
    log(port, 'CONN', str(addr))
    buf = b''
    try:
        # Send initial prompt
        conn.sendall(b'>')

        while True:
            try:
                chunk = conn.recv(512)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk

            # Process all complete lines (\n or \r\n terminated)
            while True:
                lf = buf.find(b'\n')
                if lf < 0:
                    break
                line_bytes = buf[:lf]
                buf = buf[lf + 1:]
                line = line_bytes.decode('ascii', errors='replace').strip()
                if not line:
                    continue

                kv = parse_kv(line)
                resp_body = handle_request(kv, port)
                log(port, 'REQ', line)
                log(port, 'RSP', resp_body)

                # Send response + next prompt as one packet
                packet = (resp_body + '\r\n>').encode('ascii')
                conn.sendall(packet)

    except Exception as e:
        log(port, 'ERR', str(e))
    finally:
        log(port, 'DISC', str(addr))
        try:
            conn.close()
        except Exception:
            pass

# -------------------------------------------------------------------
# Server loop
# -------------------------------------------------------------------

def serve(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', port))
        s.listen(10)
        log(port, 'LISTEN', f'127.0.0.1:{port}')
        while True:
            try:
                conn, addr = s.accept()
                t = threading.Thread(target=handle_client, args=(conn, addr, port), daemon=True)
                t.start()
            except OSError as e:
                log(port, 'ACCEPT_ERR', str(e))
                break
    except OSError as e:
        log(port, 'BIND_ERR', str(e))

def _create_tp_jvs_shm():
    """Create TeknoParrot_JvsState shared memory (8 bytes, all zeros).

    The game's amJvs library opens this mapping and reads JVS button state from it.
    Without it, amJvspAckSwInput returns -11 (ENODEV) and the JVS polling thread exits.
    With it present (all zeros = no buttons), amJvspAckSwInput returns 0 (success)
    so the polling loop stays alive for Frida to inject SERVICE/START into outPtr.
    """
    k32 = ctypes.windll.kernel32
    # Set argtypes so INVALID_HANDLE_VALUE is passed as the correct pointer-sized value
    k32.CreateFileMappingW.argtypes = [
        ctypes.c_void_p,          # hFile (INVALID_HANDLE_VALUE = c_void_p(-1))
        ctypes.c_void_p,          # lpFileMappingAttributes (NULL)
        ctypes.wintypes.DWORD,    # flProtect
        ctypes.wintypes.DWORD,    # dwMaximumSizeHigh
        ctypes.wintypes.DWORD,    # dwMaximumSizeLow
        ctypes.c_wchar_p,         # lpName
    ]
    k32.CreateFileMappingW.restype = ctypes.wintypes.HANDLE
    k32.MapViewOfFile.argtypes = [
        ctypes.wintypes.HANDLE,   # hFileMappingObject
        ctypes.wintypes.DWORD,    # dwDesiredAccess
        ctypes.wintypes.DWORD,    # dwFileOffsetHigh
        ctypes.wintypes.DWORD,    # dwFileOffsetLow
        ctypes.c_size_t,          # dwNumberOfBytesToMap
    ]
    k32.MapViewOfFile.restype = ctypes.c_void_p

    # INVALID_HANDLE_VALUE as c_void_p(-1) — correct pointer-sized value on both 32/64-bit
    INVALID_HANDLE = ctypes.c_void_p(-1)
    h = k32.CreateFileMappingW(INVALID_HANDLE, None, 4, 0, 8, 'TeknoParrot_JvsState')
    if not h:
        print(f'[JVS_SHM] CreateFileMappingW failed (err={k32.GetLastError()})')
        return None
    view = k32.MapViewOfFile(h, 0xF001F, 0, 0, 8)  # FILE_MAP_ALL_ACCESS
    if not view:
        print(f'[JVS_SHM] MapViewOfFile failed (err={k32.GetLastError()})')
        return None
    ctypes.memset(view, 0, 8)
    print(f'[JVS_SHM] TeknoParrot_JvsState: 8 bytes at 0x{view:X} (all zeros)')
    return (h, view)  # keep handles alive

if __name__ == '__main__':
    _jvs_shm = _create_tp_jvs_shm()  # must stay alive for the lifetime of this process

    for p in PORTS:
        threading.Thread(target=serve, args=(p,), daemon=True).start()

    print(f'[{ts()}] PCPA keychip server running on ports {PORTS}')
    print('  code=54 -> bypass DS28CN01 auth (per sega.bsnk.me/ringedge/security/)')
    print('  Press Ctrl+C to stop')
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('Stopped.')
