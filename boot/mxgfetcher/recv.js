// subsys:      mxgfetcher
// persistence: runtime
// va: recv (winsock export)
// ssot:        mxgfetcher/FACTS.md
// role:        recv() フックが "response=get_status" パケット到着時にスクリプトグローバルの
//              getStatusRecvDone を立てる（ポート 40113 は pcpaRecvResponse ではなく raw winsock）。
//              amgfetcher/getstatus.js の 0x98ADC0 完了 fix と対。Interceptor → detach で revert。
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
