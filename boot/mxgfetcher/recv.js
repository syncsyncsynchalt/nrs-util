// subsys:      mxgfetcher
// persistence: runtime
// va: recv (winsock export)
// ssot:        FACTS.md §patchAmGfetcher ; BUGS.md [FIXED] get_status recv completion
// role:        recv() hook sets the script-global getStatusRecvDone when a "response=get_status"
//              packet arrives (port 40113 uses raw winsock, not pcpaRecvResponse). Pairs with
//              amgfetcher/getstatus.js 0x98ADC0 completion fix. Interceptor → reverts on detach.
(function amGfetcherRecv() {
    hookFn('recv',
        function(args) {
            this.buf = args[1]; this.len = args[2].toInt32();
        },
        function(ret) {
            var n = ret.toInt32();
            if (n > 0 && n < 512) {
                var str = ''; try { str = this.buf.readCString().slice(0, 80); } catch(e) {}
                if (str.indexOf('response=get_status') >= 0) {
                    getStatusRecvDone = true;
                    logMsg('recv', 'GETSTATUS_FLAG set: n=' + n + ' "' + str.slice(0,60) + '"');
                } else {
                    logMsg('recv', 'n=' + n + ' "' + str + '"');
                }
            }
        }
    );
})();
