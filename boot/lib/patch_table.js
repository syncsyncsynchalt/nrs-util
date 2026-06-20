// subsys:      lib
// persistence: persistent
// va:          (data-driven — addresses live in boot/patches.json, not here)
// ssot:        boot/CONVENTIONS.md (patches.json 規約) ; 各行の ssot フィールド
// role:        データ駆動 pure-byte patch 表(patches.json)を適用。表は launch.py が __PATCH_TABLE__ として注入。
(function applyPatchTable() {
    var T = (typeof __PATCH_TABLE__ !== 'undefined') ? __PATCH_TABLE__ : [];
    if (!T.length) { logMsg('PATCH', 'patch table empty'); return; }
    var ok = 0;
    T.forEach(function (row) {
        try {
            patch(parseInt(row.va, 16), patchBytes(row.bytes), row.subsys + ': ' + (row.note || ''));
            ok++;
        } catch (e) { logMsg('WARN', 'patch table row ' + JSON.stringify(row) + ': ' + e); }
    });
    logMsg('PATCH', 'patch table applied: ' + ok + '/' + T.length + ' rows');
})();
