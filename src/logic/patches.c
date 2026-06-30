/* patches.c — 旧 Frida 実装 boot 各サブシステムの静的バイトパッチ + データ書込みを忠実移植。
 * 正準 = git 履歴の boot/ 各モジュール（persistent 分）。nrs.exe ImageBase 0x400000。
 * これ単体で旧 impl の「attract 到達」静的部分を再現する。動的サブシステム
 * (keychip server / mxdrivers IOCTL emu / rtc / getstatus / identity / region 条件分岐) は別途。 */
#include <windows.h>
#include <stdint.h>
#include "abi.h"

#define IMAGE_BASE 0x400000u

typedef struct { uint32_t va; const uint8_t *b; int n; const char *note; } CodePatch;

/* --- byte patches（静的VA, 上書きバイト） --- */
static const uint8_t P_billing[]   = {0xB8,0x05,0x00,0x00,0x00,0xC3};        /* alpbExGetExecStatus -> 5 */
static const uint8_t RET0[]        = {0x31,0xC0,0xC3};                       /* xor eax,eax;ret */
static const uint8_t RET8_0[]      = {0x31,0xC0,0xC2,0x08,0x00};             /* xor eax,eax;ret 8（__thiscall の 8B スタック引数を callee で掃除） */
static const uint8_t RET1[]        = {0xB8,0x01,0x00,0x00,0x00,0xC3};        /* mov eax,1;ret */
static const uint8_t P_zero1[]     = {0x00};                                 /* imm 0 */
/* P_dipsw2/P_dipsw3 は撤去（dipsw は api.c dipsw_force_ready + mxdev_ioctl で OS 境界エミュ。下の CODE[] 注記参照）。 */
static const uint8_t P_one1[]      = {0x01};                                 /* imm 1 */
static const uint8_t P_ret2[]      = {0xB8,0x02,0x00,0x00,0x00,0xC3};        /* mov eax,2;ret */
static const uint8_t P_extimg[]    = {0x31,0xC0,0x85,0xF6,0x74,0x02,0x89,0x06,0xB0,0x04,0xC3};
static const uint8_t P_alc[]       = {0xB0,0x01,0xC3};                       /* mov al,1;ret */
static const uint8_t NOP6[]        = {0x90,0x90,0x90,0x90,0x90,0x90};
static const uint8_t NOP10[]       = {0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90};
/* amplatform/identity.js: platform getter を固定文字列で置換（mov eax,[esp+4]; mov byte[eax+i],c..; xor eax,eax; ret 4）*/
/* P_platid("AAL")/P_osver("WindowsXP") は撤去。platform は columba DMI、OsVersion は仮想ファイル
   C:\System\SystemVersion.txt（api.c on_create_file/on_read_file）が供給。下の CODE[] 注記参照。 */

static const CodePatch CODE[] = {
    /* ambilling/status.js — billing batch 撤去（2026-06-30, 差分ライブテストで冗長確認）:
       撤去→SYSTEM STARTUP 全 OK→attract 安定到達。boot→attract には billing ready 詐称不要。
       ※実コイン/プレイ(credit)段階で必要になりうるが現状 attract 止まり(P5 network blocker)ゆえ未到達。再発時は復活。 */
    /* {0xA065C0, P_billing, 6, "alpbExGetExecStatus->5 (billing offline)"}, */
    /* amdongle/patch.js — 保持（撤去不可・2026-06-30 ライブ実証）: 撤去すると boot が host.ready 直後に
       ハング（amdongle outerSM が最初期に走り attract 不達）。dongle batch(0x975E00+JL2JMP)は一体で必須。 */
    {0x975E00, RET0, 3, "amDongleBusy->0 (outerSM advances). 撤去不可(early hang)。"},
    {0x457AF0, RET8_0, 5, "delete_directory_recursive nop: blocks keychipSM_FSM case4 recursive dir delete on appdata mismatch. __thiscall(this,arg1,arg2)=callee-clean ゆえ ret 8 必須(関数の 0x457fd1=RET 0x8 / call site 0x4579F4 に add esp 無し)。bare ret はスタック破壊→発火時クラッシュ。(DO NOT REMOVE; facts/bugs.md, facts/amdongle.md)"},
    /* amjvs: forgery 撤去。native JVS 経路（COM4 = mxjvs.c エミュ）を実駆動する方針へ移行（facts/amjvs.md）。
       0x67AFA0(reinit ret)/0x987590(specCheck)/0x9883D3(acksw) と node BSS data write 群は撤去:
       - amJvspInit→FUN_00987550 が specCheck の前提 ctx[0]=1 を自前で立てるため specCheck パッチ不要。
       - discovery スレッド(0x9869f0)が COM4 上でバス列挙し node_count を立てる＝forgery 不要。
       COM 番号は patches_apply 末尾で 0xAE11F0 を cfg->jvs_com にパッチ（既定 COM4）。 */
    /* devices/presence.js */
    /* 0x4F6310 IC Card R/W ready(cardrw_ready_bit1=card_flags>>1&1) RET1 は撤去（2026-06-30, ライブ実証）:
       card serial emu(card.c)が実 handshake を完走させると game 自身が card_flags bit1 を立てる。boot state2
       (amlib_init_sm 0x89a010)は cardrw_ready_bit1()!=0 を無期限ポーリングするので詐称不要。
       差分ライブテスト: 撤去→"CHECKING IC CARD R/W … OK"→attract 到達(5101 不在)。再発(5101/ハング)時は復活させる。 */
    /* {0x4F6310, RET1, 6, "IC Card R/W ready->1 (Error 5101)"}, */
    /* 0x8B3B00 Touch Panel status(touchpanel_status=ctx+0x18) RET1 は撤去（2026-06-30, ライブ実証）:
       touch serial emu(touch.c)が handshake を完走させると game 自身が ctx+0x18=1 を立てる
       (FUN_008b2ad0 default case→"touch panel ok.")。boot state3 は touchpanel_status()!=0 を無期限ポーリング＝詐称不要。
       差分ライブテスト: 撤去→"CHECKING TOUCH PANEL … OK"→attract 到達(5501 不在)。再発(5501)時は復活させる。 */
    /* {0x8B3B00, RET1, 6, "Touch Panel status->1 (Error 5501)"}, */
    /* 0x6F0B80 は保持（撤去不可・2026-06-30 ライブ実証）: USB I/O board(usbio_board_count 0x16b88dc)は vtable USB 列挙
       (FUN_0067cbe0)で検出され COM4 JVS emu(amJvst)とは別経路ゆえ standalone で count=0 のまま。撤去すると boot が
       Error 0910(Wrong Resolution Setting)で停滞し attract に到達しない（差分ライブテストで確認, 951 連鎖が解像度初期化を阻害）。 */
    {0x6F0B80, P_zero1, 1, "USB I/O board errCode imm 0F->00 (Error 951). 撤去不可(0910 停滞)。"},
    /* dipsw byte2->3 / byte3->0x20(board index 2) は撤去: dipsw ctx を api.c dipsw_force_ready が provisioning し、
       read fn の mxsmbus IOCTL(0x9c402004,cmd5) を mxdev_ioctl が応答(index0=0x20)。素の amDipswRead が board index 2
       を算出するため byte patch 不要。詳細 facts/devices.md。再発(errCode 0xa/0xb)時は復活させる。 */
    /* mxnetwork/state.js — network batch 撤去（2026-06-30, 差分ライブテストで冗長確認）:
       撤去→"CHECKING NETWORK … OK"→attract 安定到達。runtime の keychip PCP サーバ＋api.c network_auth_force_ready が
       network 状態を供給するため LAN flag/device_status の静的詐称は不要。8005/8001 不在。再発時は復活。 */
    /* {0x6FF1B3, P_one1, 1, "LAN flag b50c 0->1 (Error 8005)"}, */
    /* {0x72DCE0, P_ret2, 6, "amlib_device_status_getter->2 (Error 8001)"}, */
    /* mxsegaboot/startup.js — extend_image batch 撤去（2026-06-30, 差分ライブテストで冗長確認）:
       撤去→attract 安定到達。"CHECKING EXTEND IMAGE … NG" は元から非ブロッキングで詐称不要。再発時は復活。 */
    /* {0x72B3A0, P_extimg, 11, "extend_image_install_status (state7)"}, */
    /* pras_billing_ready_check 撤去（2026-06-30, billing batch の一部。上記 0xA065C0 と同じ理由で冗長）。 */
    /* {0x701280, P_alc, 3, "pras_billing_ready_check->al=1: billing offline でも ready 強制（alpbEx_billing_ready/enabled 参照。freeplay flag 0x128855A とは別物）"}, */
    /* mxstorage/presence.js — is-DVD-boot 撤去（2026-06-30, 差分ライブテストで冗長確認）:
       撤去→attract 安定到達(913 不在)。standalone は disk boot で素の判定が通る。再発時は復活。 */
    /* {0x4FDA50, RET0, 3, "is-DVD-boot->0 (Error 913)"}, */
    /* mxkeychip/region.js + hlsm region — region batch 撤去（2026-06-30, 差分ライブテストで冗長確認, 6 CODE + 3 DATA=9個）:
       撤去→attract 安定到達、region Error 画面(0x381/0x387/0x38D)は 30s サンプリングで一度も出ず。
       keychip PCP サーバ(host/keychip_server.c)が keychip ハンドシェイクで region を供給し、ゲームの region チェックが
       自然通過＋region globals もゲーム自身が設定するため詐称・DATA 書込み(region=JAPAN)とも不要。lv3 警告ログは
       baseline でも出る良性。※region は本来 network 対戦の matchmaking を gate ＝ P5 network play 実装時は keychip 供給を
       要確認。再発(region Error)時は復活。詳細 facts/devices.md。 */
    /* {0x986A66, NOP6, 6, "region jne->nop (Error 0x381)"}, */
    /* {0x986A74, NOP6, 6, "region jne->nop (Error 0x387 wrong region)"}, */
    /* {0x986A92, NOP6, 6, "region jne->nop (Error 0x38D)"}, */
    /* {0x459109, NOP10, 10, "errCode=4 store nop (FUN_00458fd0)"}, */
    /* {0x45A846, NOP10, 10, "errCode=4 store nop (FUN_0045a7f0)"}, */
    /* {0x6FF980, RET1, 6, "hlsm_region_check->1: HLSM(0x457fe0) の region ゲート（0x210aed0/2/4 参照。keychip region NOP 0x986A.. とは別経路）"}, */
    /* amplatform/identity.js（platform gate FUN_0045a6f0 回避） */
    /* 0x981FF0 amPlatformGetPlatformId->"AAL" は撤去: columba DMI(mxdevices.c build_dmi の OEM
       string index2="AAL")が amOemstringGetOemstring 経由で供給するため素の関数が "AAL" を返す＝冗長。
       詳細 facts/amplatform.md。再発時(Error 0901)は復活させる。 */
    /* 0x981D60 amPlatformGetOsVersion->"WindowsXP" も撤去: gate FUN_0045a6f0 は OsVersion の戻り 0 のみ要求
       （値は捨てる）。原関数は C:\System\SystemVersion.txt を読み非ゼロ parse で戻り 0 を返すので、host が
       同ファイルを仮想供給(api.c)すれば素の関数が戻り 0。standalone 欠損時は -3→errCode 3 なので仮想ファイル必須。
       詳細 facts/amplatform.md。再発(errCode 3)時は復活させる。 */
};

/* jl(0x7C disp8) -> jmp(0xEB disp8): byte0 のみ書換。amdongle outerSM の 3 分岐（dongle batch, 撤去不可）。
   先頭 0=sentinel（skip）で全撤去しても空配列にならない。撤去テスト→early hang ゆえ保持。 */
static const uint32_t JL2JMP[] = { 0 /*sentinel*/, 0x97588A, 0x97595F, 0x975A1F };

typedef struct { uint32_t va; uint32_t val; int size; } DataWrite;
static const DataWrite DATA[] = {
    {0, 0, 0},   /* sentinel（size 0 = skip）。全 DATA を撤去しても空配列にならずビルド可にする番兵。 */
    /* amjvs node BSS の forgery data write は撤去（native discovery が node を満たす）。 */
    /* mxkeychip/region.js — region=JAPAN [TEST 撤去中: region DATA] */
    /* {0x16014C4, 1, 1}, {0x1601744, 1, 1}, {0x1601989, 1, 1}, */
    /* amdebug 系統A のゲート開放(logLevel/logMask)は**ここでは行わない**。
       注入は CREATE_SUSPENDED ＝ patches_apply は entry 前に走るため、resume 後の
       amDebugInit(0x55C500: memset→logLevel=4/mask=0xff) に上書きされ lv5..7 が脱落する。
       → init 完了後に開放する必要があり host/dbglog.c が amDebugInit を hook して実施。 */
};

static void wr(uintptr_t addr, const void *src, int n) {
    DWORD old;
    if (VirtualProtect((void *)addr, n, PAGE_EXECUTE_READWRITE, &old)) {
        memcpy((void *)addr, src, n);
        VirtualProtect((void *)addr, n, old, &old);
        FlushInstructionCache(GetCurrentProcess(), (void *)addr, n);
    }
}

void patches_apply(HostServices *h) {
    uintptr_t base = (uintptr_t)GetModuleHandleW(NULL);   /* nrs.exe */
    char msg[160];

    for (size_t i = 0; i < sizeof CODE / sizeof CODE[0]; i++)
        wr(base + (CODE[i].va - IMAGE_BASE), CODE[i].b, CODE[i].n);

    uint8_t jmp = 0xEB;
    int njl = 0;
    for (size_t i = 0; i < sizeof JL2JMP / sizeof JL2JMP[0]; i++) {
        if (JL2JMP[i] == 0) continue;   /* sentinel/撤去枠は skip */
        wr(base + (JL2JMP[i] - IMAGE_BASE), &jmp, 1);
        njl++;
    }

    int ndata = 0;
    for (size_t i = 0; i < sizeof DATA / sizeof DATA[0]; i++) {
        if (DATA[i].size == 0) continue;   /* sentinel/撤去枠は skip */
        uintptr_t a = base + (DATA[i].va - IMAGE_BASE);
        if (DATA[i].size == 1) { uint8_t v = (uint8_t)DATA[i].val; wr(a, &v, 1); }
        else if (DATA[i].size == 2) { uint16_t v = (uint16_t)DATA[i].val; wr(a, &v, 2); }
        else { uint32_t v = DATA[i].val; wr(a, &v, 4); }
        ndata++;
    }

    /* app/no_selfshutdown.js: 0x6C3F20 が je(0x74) のときだけ jmp(0xEB) 化 */
    {
        uintptr_t a = base + (0x6C3F20 - IMAGE_BASE);
        if (*(volatile uint8_t *)a == 0x74) { uint8_t v = 0xEB; wr(a, &v, 1); }
    }

    /* JVS が開く COM ポート名 "COM4"@0xAE11F0 を cfg->jvs_com にパッチ（単桁 1..9, 既定 9）。
       amJvspInit→amJvstInit(&DAT_00ae11f0)→CreateFileA がこの文字列をそのまま使う（serial_select は touch/card 用）。
       on_create_file 側の is_jvs_com も同じ番号を見るので、ゲームが開くポートとエミュの応答先が一致する。
       元バイトは "COM4\0\0\0\0"（0xAE11F0..F7）＝5バイト書込みは安全。touch=COM1/COM3・card=COM2 と重複しない
       単桁を選ぶ（既定 9）。is_jvs_com は wsprintfW で任意桁対応だが、ここは在地 5バイト枠ゆえ単桁に限定。 */
    {
        int port = (h && h->cfg && h->cfg->jvs_com) ? h->cfg->jvs_com : 9;
        if (port >= 1 && port <= 9) {
            uint8_t s[5] = { 'C', 'O', 'M', (uint8_t)('0' + port), 0 };
            wr(base + (0xAE11F0 - IMAGE_BASE), s, 5);
        }
    }

    int total = (int)(sizeof CODE / sizeof CODE[0]) + njl + ndata + 2;
    wsprintfA(msg, "{\"ev\":\"patches.applied\",\"count\":%d,\"base\":\"%p\"}", total, (void *)base);
    if (h && h->log) h->log("info", msg);
}
