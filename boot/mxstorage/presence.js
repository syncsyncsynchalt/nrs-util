// subsys:      mxstorage
// persistence: persistent
// va:          0x4FDA50
// ssot:        ./FACTS.md
// role:        ストレージ存在判定: is-DVD-boot -> 0（storage OK）。
(function mxstoragePresence() {
    patch(0x4FDA50, RET0, 'FUN_004fda50 is-DVD-boot -> 0 (storage OK; Error 913, state5)');
})();
