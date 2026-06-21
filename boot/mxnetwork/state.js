// subsys:      mxnetwork
// persistence: persistent
// va:          0x6FF1B3, 0x72DCE0
// ssot:        ./FACTS.md
// role:        ネットワーク段ゲート: LAN flag b50c init 0->1(state4/6) + device_status ready(state4/6)。
(function mxnetworkState() {
    patch(0x6FF1B3, [0x01], 'FUN_006ff140 LAN flag b50c init 0->1 (state4/6 の LAN gate; Error 8005)');
    patch(0x72DCE0, retImm(2), 'amlib_device_status_getter -> 2 (ready; state4 network + state6 allnet; Error 8001)');
})();
