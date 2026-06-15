// subsys:      amnet
// persistence: monitor   // network_role=serve
// va: 0x9814E0
// ssot:        amnet/FACTS.md
// role:        amNet 応答抽出 0x5814E0 (amNetworkResponseCheck) の native 成否を観測する診断専用
//              (log-only, no force)。8006 (Network timeout DHCP) は pcpa_server.py の amNet 応答を
//              '&' 区切りに修正したことで native 解決するため、旧 force-patch は撤去した。
//              ret<0 が出たら pcpa amNet 応答フォーマット回帰の疑い。
//
// 根本原因（2026-06-13 確定）: PCP パーサ pcppChangeRequest (FUN_0098bb30 / static 0x98bb30) は '&' を
//   フィールド区切りとし、'\r' または '\n' を見た時点でパースを打ち切る。pcpa_server の amNet 応答だけ
//   '\r\n' 区切りだったため先頭 response ペアのみ登録され、抽出器 amNetworkResponseCheck (static 0x9814E0)
//   が 'result' を見つけられず -1 を返し SM がループ → 8006。'&' 区切りに直して native 成功
//   (ret=0, dhcp_status=3, nic_ready=1) を実機実証（force OFF で 8006 ログ 0 件・HLSM ATTRACT 到達）。
(function monitorAmNet() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'monitorAmNet: nrs.exe not found'); return; }

    var CTX_PTR_VA = 0xCCF448;   // amNet PCPA ctx ptr
    function getCtx() {
        try { return va(CTX_PTR_VA).readPointer(); } catch(e) { return null; }
    }

    var amNetCount = 0;
    try {
        Interceptor.attach(va(0x9814E0), {   // amNetworkResponseCheck (response extractor)
            onLeave: function(ret) {
                amNetCount++;
                if (amNetCount > 6) return;            // 初回数件のみ（log-only, 非 load-bearing）
                var orig = ret.toInt32();
                var ctx = getCtx();
                var dhcp = -1, dReady = -1, nicReady = -1;
                if (ctx && !ctx.isNull()) {
                    try { dhcp = ctx.add(0x30).readS32(); } catch(e) {}
                    try { dReady = ctx.add(0x68).readU8(); } catch(e) {}
                    try { nicReady = ctx.add(0x69).readU8(); } catch(e) {}
                }
                logMsg('amNet', '[#' + amNetCount + '] 0x5814E0 ret=' + orig +
                       ' dhcp_status=' + dhcp + ' dhcp_ready=' + dReady + ' nic_ready=' + nicReady +
                       (orig < 0 ? '  [WARN native fail — pcpa amNet 応答が & 区切りか確認]' : ''));
            }
        });
        logMsg('INIT_AMNET', '0x5814E0 monitor (log-only; amNet served natively via pcpa_server & fix)');
    } catch(e) { logMsg('WARN', 'monitorAmNet: ' + e); }
})();
