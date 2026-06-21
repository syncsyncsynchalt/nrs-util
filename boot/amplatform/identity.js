// subsys:      amplatform
// persistence: persistent   // network_role=local
// va: 0x981D60, 0x981FF0
// ssot:        amplatform/FACTS.md
// role:        amPlatform GetOsVersion/PlatformId を WindowsXP/AAL に patchCode（platform gate FUN_0045a6f0 回避）。永続

// amPlatform identity: 文字列 getter を patchCode で置き換え、platform gate
// FUN_0045a6f0（PlatformId + OsVersion を読み、不一致なら errCode 2/3 を latch）に
// 実機 RingEdge が返す値を見せる。永続（detach 後も有効）。
(function hookAmPlatform() {
    var nrsBase = null;
    try { nrsBase = Process.getModuleByName('nrs.exe').base; }
    catch(e) { logMsg('WARN', 'amPlatform hook: nrs.exe not found'); return; }

    // amPlatformGetOsVersion(buf,bufLen) / amPlatformGetPlatformId(buf,bufLen): stdcall。
    // char* buf へ文字列を書き込む。下で patchCode 置換する。
    // PlatformId は表示名 "RingEdge" ではなく "AAL"（実機 RingEdge のボード ID）でなければならない:
    // 呼び出し側は "AAL"/"AAM"/"NEC" と比較するため、"RingEdge" は全て不一致になり、SM 終了後に
    // 0x491ACE 経由で Error 0901 "Wrong Platform" になる。
    var APF = {
        amPlatformGetOsVersion:  0x981D60,
        amPlatformGetPlatformId: 0x981FF0,
    };

    // Platform ID: "AAL" は nrs.exe の比較で使われる RingEdge のハードウェアボードコード。
    var PLATFORM_ID  = 'AAL';       // ハードウェアボード ID（"AAL"/"AAM"/"NEC" と比較される）
    var OS_VERSION   = 'WindowsXP'; // OS バージョン文字列

    // patchPlatformFunc: 文字列を返す platform 関数向けの永続 patchCode。
    // fillStr（null 終端）を *[esp+4]（buf 引数）へ書き込み、0 を返す。
    function patchPlatformFunc(name, sva, fillStr) {
        try {
            var strBytes = [];
            for (var i = 0; i < fillStr.length; i++) strBytes.push(fillStr.charCodeAt(i) & 0xFF);
            strBytes.push(0); // null 終端

            // mov eax, [esp+4]
            var code = [0x8B, 0x44, 0x24, 0x04];
            for (var i = 0; i < strBytes.length; i++) {
                if (i === 0) {
                    code.push(0xC6, 0x00, strBytes[i]); // mov byte [eax], val
                } else {
                    code.push(0xC6, 0x40, i, strBytes[i]); // mov byte [eax+i], val
                }
            }
            code.push(0x33, 0xC0);       // xor eax, eax  （0 を返す）
            code.push(0xC2, 0x04, 0x00); // ret 4

            patch(sva, code, name + '="' + fillStr + '"');
        } catch(e) { logMsg('WARN', 'amPlatform patchCode ' + name + ': ' + e); }
    }

    // NOTE: amPlatformGetBoardType (0x982C50) は意図的にパッチしない（してはならない）:
    // この関数は DWORD* を out 引数に取る（0x982F61 のジャンプテーブル用 index 0-3）ため、文字列を
    // 書き込むと index が壊れる。platform gate FUN_0045a6f0 が読むのは PlatformId + OsVersion だけで
    // BoardType は読まない。唯一の利用者 amBackup_getAreaDescriptor (0x982F40) も attract を gate しない。

    patchPlatformFunc('amPlatformGetPlatformId', APF.amPlatformGetPlatformId, PLATFORM_ID);
    patchPlatformFunc('amPlatformGetOsVersion',  APF.amPlatformGetOsVersion,  OS_VERSION);

    logMsg('INIT_AMPLATFORM', 'amPlatform patchCode installed (persistent): platformId="AAL"');
})();
