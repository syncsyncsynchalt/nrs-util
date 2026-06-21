"""
nrs.exe (NRS RingEdge) 向けの最小 PCPA サーバ。

本物の keychip 無しで amDongleSetupKeychip と keychipSM を完了させるのに足るだけの
PCP/PCPA プロトコルを実装する:

  Setup sequence (outerSM):
    - keychip.appboot.systemflag=? -> systemflag=00 (dev モード無し)
    - keychip.version=? -> version=0001
    -> done_init=1, available=1

  Auth sequence (keychipSM):
    - keychip.ds.compute=<hex>  -> code=54 (ERR_COMMAND = DS28CN01 をバイパス)
    - keychip.ssd.proof=<hex>   -> code=54 (SSD proof をバイパス)

  その他のコマンドは妥当な値とともに code=0 (OK) を返す。

ワイヤプロトコル (server 側):
  S->C: >
  C->S: key1=val1&key2=val2\r\n
  S->C: key=value\r\n>          (response + 次の prompt を結合)

参照: micetools (Bottersnike/micetools), sega.bsnk.me/ringedge/
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
# 40100: mxmaster (foreground プロセスマネージャ)
# 40102: appslot (query_application_status, query_slot_status, check_appdata)
# 40104: amNet (query_dhcp_status, query_nic_status)
# 40106: keychip setup + ds.compute (Frida で確認: keychip.ds.compute はここへ、40110 ではない)
# 40110: keychip ctrl (ssd.proof, stopcatcher, billing 等)
# 40111: keychip data (未確定)
# 40113: mx-catcher サービス (pause, stopcatcher — pcpaOpenClient 経由でなく直接 winsock)

def ts():
    return datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]

def log(port, direction, msg):
    print(f'[{ts()}][PCPA:{port}] {direction} {msg}', flush=True)

# -------------------------------------------------------------------
# Per-request response logic
# -------------------------------------------------------------------

def handle_request(kv, port):
    """
    kv: パース済みクライアント要求の {key: value} dict。
    PCPA レスポンス文字列を返す（\r\n 区切りの複数 key=value 行を含みうる。
    末尾の \r\n や > は付けない）。
    呼び出し側が \r\n> を付加する。
    """
    # ---------------------------------------------------------------
    # mxmaster プロトコル (port 40100): foreground プロセス管理
    # ゲーム (nrs.exe) は mxmaster へクライアントとして接続し、自身を登録する/
    # boot 状態を問い合わせるためにこれらのコマンドを送る。
    # 参照: micetools/micemaster/callbacks/foreground.c
    # ---------------------------------------------------------------

    # mxmaster.foreground.getcount=N -> key をエコー + count=0
    if 'mxmaster.foreground.getcount' in kv:
        n = kv['mxmaster.foreground.getcount']
        return f'mxmaster.foreground.getcount={n}\r\ncount=0'

    # mxmaster.foreground.active=0/1/? -> foreground 管理
    if 'mxmaster.foreground.active' in kv:
        val = kv['mxmaster.foreground.active']
        if val == '?':
            # 本物の mxmaster は m_current=1（非 develop モード）で始まるので、
            # ゲームは常に既に foreground アプリ。
            return 'mxmaster.foreground.active=1'
        if val == '1':
            # ゲームが foreground を主張。本物の mxmaster: m_current が既に 1 だと
            #（mxMasterSysProcessesStart が設定）active=1 + code=2 を返す。
            # ゲームは「既に active」ケースを問題なく処理するので code=2 は省く。
            return 'mxmaster.foreground.active=1'
        return f'mxmaster.foreground.active={val}'

    # mxmaster.foreground.next=N -> 受理応答
    if 'mxmaster.foreground.next' in kv:
        n = kv['mxmaster.foreground.next']
        return f'mxmaster.foreground.next={n}'

    # mxmaster.foreground.current=? -> 現在 active なスロット = 1（ゲーム、非 develop モード）
    if 'mxmaster.foreground.current' in kv:
        return 'mxmaster.foreground.current=1'

    # mxmaster.foreground.fault=? -> fault 無し
    if 'mxmaster.foreground.fault' in kv:
        return 'mxmaster.foreground.fault=0'

    # mxmaster.foreground.setcount -> 受理応答
    if 'mxmaster.foreground.setcount' in kv:
        n = kv['mxmaster.foreground.setcount']
        cnt = kv.get('count', '0')
        return f'mxmaster.foreground.setcount={n}\r\ncount={cnt}'

    # ---------------------------------------------------------------
    # 認証バイパス: DS28CN01 challenge と SSD proof -> code=54 で検証をスキップ
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

    # App-boot 情報（後で問い合わせられうる）
    if 'keychip.appboot.gameid' in kv:
        return f'keychip.appboot.gameid={ID["gameid"]}'
    if 'keychip.appboot.region' in kv:
        # region=01=JAPAN。nrs.exe は JAPAN ビルド: region チェック
        # FUN_00458fd0/FUN_0045a7f0 は (game_region & dongle_region & 5) != 0 を要求。
        # game_region (DAT_016014c4) は bit0 が立つ (JAPAN) ので、0x02(USA) & 5 == 0 → Region エラー。
        # FUN_0048f9c0 はバイトを 0x01=JAPAN/0x02=USA/0x08=EXPORT としてデコードする。
        # TeknoParrot プロファイルの DongleRegion/PcbRegion=JAPAN に一致。
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
        # binary モードは未実装; ゲームを続行させるため -1（seed 無し）を返す
        return 'keychip.appboot.seed=-1'

    # 暗号 (AES) - ゼロ化した cipher/plaintext を返す
    if 'keychip.encrypt' in kv:
        return 'keychip.encrypt=00000000000000000000000000000000'
    if 'keychip.decrypt' in kv:
        return 'keychip.decrypt=00000000000000000000000000000000'
    if 'keychip.setiv' in kv:
        return 'keychip.setiv=1'

    # 課金 (billing)
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
    # Application/slot マネージャ (port 40102): outerSM と keychipSM の問い合わせ
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
            # '&' 区切り（query_dhcp_status 参照）。status=1: link up。
            # ip_address は bind(ip:23456) を引き起こす。
            return f'response=query_nic_status&result=0&status=1&ip_address={NET["ip"]}&subnetmask={NET["mask"]}&gateway={NET["gateway"]}&primary_dns={NET["dns1"]}&secondary_dns={NET["dns2"]}'
        if req == 'get_status':
            # FUN_0098aae0 は 1 行内の '&' 区切りフィールドをパース（\r\n ではない）。
            # FUN_00974b00 (get_status パーサ): FUN_0098aae0 経由で "status" フィールドを探す。
            # status=incorrect(3): SM state6 → 3!=2 かつ 3<4 → state7 へ進む。
            # FUN_00975140 は Frida で 0 にパッチ済み（result= チェックをバイパス）。
            return 'response=get_status&result=0&status=incorrect'
        if req == 'set_auth_params':
            # FUN_0098aae0 は 1 行内の '&' 区切りフィールドをパースする。
            return 'response=set_auth_params&result=0&bbflag=1'
        if req == 'isrelease':
            # HLSM state3 がこれを送る; レスポンスパーサは param_1+0x24（"release" フィールド）を読む。
            # Frida HLSM フックも state=4 に入るとき param_1+0x24=1 を直接強制する。
            # release=1 → isrelease result = 1 → state4 成功 → param_1[2]=1。
            return 'response=isrelease&result=0&release=1'
        if req == 'resume':
            return 'response=resume&result=0'
        if req == 'pause':
            # HLSM state-9 からの mx-catcher (port 40113) pause 要求。
            # Frida recv フックも念のため code=0 をこの形式へ書き換える。
            return 'response=pause&result=0'
        if req == 'stopcatcher':
            return 'response=stopcatcher&result=0'
        # その他の request= 問い合わせ: OK
        return 'code=0'

    # 既定: OK、データ無し
    return 'code=0'

# -------------------------------------------------------------------
# Client handler
# -------------------------------------------------------------------

def parse_kv(line):
    """'key1=val1&key2=val2' を dict にパースする。値は '?' でありうる。"""
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
        # 最初の prompt を送る
        conn.sendall(b'>')

        while True:
            try:
                chunk = conn.recv(512)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk

            # 完結した行を全て処理（\n または \r\n 終端）
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

                # response + 次の prompt を 1 パケットで送る
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
    """TeknoParrot_JvsState 共有メモリを作成する（8 バイト、全ゼロ）。

    ゲームの amJvs ライブラリはこのマッピングを開いて JVS ボタン状態を読む。
    無いと amJvspAckSwInput は -11 (ENODEV) を返し、JVS ポーリングスレッドが終了する。
    有ると（全ゼロ = ボタン無し）amJvspAckSwInput は 0（成功）を返すので、
    ポーリングループが生き続け、Frida が outPtr へ SERVICE/START を注入できる。
    """
    k32 = ctypes.windll.kernel32
    # INVALID_HANDLE_VALUE を正しいポインタサイズの値で渡すよう argtypes を設定する
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

    # INVALID_HANDLE_VALUE を c_void_p(-1) として — 32/64-bit どちらでも正しいポインタサイズ値
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
    return (h, view)  # handle を生かし続ける

if __name__ == '__main__':
    _jvs_shm = _create_tp_jvs_shm()  # このプロセスの生存中ずっと生かしておく必要あり

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
