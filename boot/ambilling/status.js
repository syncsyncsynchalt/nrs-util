// subsys:      ambilling
// persistence: persistent
// va:          0xA065C0
// ssot:        ./FACTS.md
// role:        ALL.Net Plus Billing オフライン: alpbExGetExecStatus -> 5 (idle)。
(function ambillingStatus() {
    patch(0xA065C0, retImm(5), 'alpbExGetExecStatus -> 5 (idle; ALL.Net Plus Billing offline; Error 1000)');
})();
