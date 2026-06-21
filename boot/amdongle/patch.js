// subsys:      amdongle
// persistence: persistent
// va:          0x975E00, 0x457AF0
// ssot:        amdongle/FACTS.md
// role:        amDongleBusy→not-busy(outerSM 前進) + keychipSM state4 DLL-crash helper→ret 0。Persistent。
//
// 0x975E00 amDongleBusy: 戻り 0 = 「init op 完了 / not busy」(TP keychip driver 同等)。nrs の PCPA async 層は
//   init 完了を自発設定しないため自然戻りは 1(busy)。amDongle outerSM の even state(2/4/6) は 0 でないと前進しない。
//   ⚠ この番地は amdongle/diag.js が hook 観測する衝突番地 → load 順は diag.js の後を維持（順序依存）。
// 0x457AF0 keychipSM state4 helper: auth 経路([esi+0x10]!=0)で DLL 内クラッシュ→onLeave 不発。entry→ret 0 で回避。
// 詳細・経緯は amdongle/FACTS.md。
(function bypassAmDongle() {
    patch(0x975E00, RET0, 'amDongleBusy -> not busy (outerSM advances)');
    patch(0x457AF0, RET0, 'keychipSM state4 crash helper -> ret 0');
})();
