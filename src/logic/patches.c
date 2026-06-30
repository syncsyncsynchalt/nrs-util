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
static const uint8_t P_billing[]   = {0xB8,0x08,0x00,0x00,0x00,0xC3};        /* alpbExGetExecStatus -> 8 (ready, no accounting) */
static const uint8_t RET0[]        = {0x31,0xC0,0xC3};                       /* xor eax,eax;ret */
static const uint8_t RET8_0[]      = {0x31,0xC0,0xC2,0x08,0x00};             /* xor eax,eax;ret 8（__thiscall の 8B スタック引数を callee で掃除） */
static const uint8_t RET1[]        = {0xB8,0x01,0x00,0x00,0x00,0xC3};        /* mov eax,1;ret */
static const uint8_t P_zero1[]     = {0x00};                                 /* imm 0 */
/* P_dipsw2/P_dipsw3 は撤去（dipsw は api.c dipsw_force_ready + mxdev_ioctl で OS 境界エミュ。下の CODE[] 注記参照）。 */
static const uint8_t P_one1[]      = {0x01};                                 /* imm 1 */
static const uint8_t P_ret2[]      = {0xB8,0x02,0x00,0x00,0x00,0xC3};        /* mov eax,2;ret */
static const uint8_t P_extimg[]    = {0x31,0xC0,0x85,0xF6,0x74,0x02,0x89,0x06,0xB0,0x04,0xC3};
static const uint8_t NOP6[]        = {0x90,0x90,0x90,0x90,0x90,0x90};
static const uint8_t NOP10[]       = {0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90};
/* amplatform/identity.js: platform getter を固定文字列で置換（mov eax,[esp+4]; mov byte[eax+i],c..; xor eax,eax; ret 4）*/
/* P_platid("AAL")/P_osver("WindowsXP") は撤去。platform は columba DMI、OsVersion は仮想ファイル
   C:\System\SystemVersion.txt（api.c on_create_file/on_read_file）が供給。下の CODE[] 注記参照。 */

static const CodePatch CODE[] = {
    /* ambilling/status.js */
    /* alpbExGetExecStatus->8: status 8 は alpbEx_billing_poll(0x7000C0) case8 で alpbEx_billing_ready=1 を立てる
       （accounting report は開始しない＝status 2 と違い traffic 無し）。これにより boot SM
       amlib_init_sm_SYSTEM_STARTUP state7 の pras_billing_ready_check(0x701280) が ready!=0 で自然に通る
       → 旧 0x701280 パッチを撤去（25/06/30, A 統合）。alpbEx_billing_enabled は無条件 1 で OFF 経路が無いため
       enabled=0 では回避不可（facts/ambilling.md 全数確認）。残り2 caller(FUN_00700380 credit executor /
       FUN_00700c00 debug dump)は attract で request queue 空＝no-op、status 8 安全。実 credit 計上を
       配線する際は status 8↔5 を再評価（executor の早期 return 挙動が変わる）。 */
    {0xA065C0, P_billing, 6, "alpbExGetExecStatus->8 (billing ready, no accounting; retires 0x701280)"},
    /* amdongle/patch.js */
    {0x975E00, RET0, 3, "amDongleBusy->0 (outerSM advances)"},
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
    /* 0x6F0B80 撤去（2026-06-30, 実 SysMouse 供給で純正化・ライブ実証）: usbio_board_count(0x16b88dc) は
       dinput_create_device(0x67CBE0)が **CreateDevice(GUID_SysMouse)+SetDataFormat(c_dfDIMouse2)+
       SetCooperativeLevel(hwnd@0x1696e0c)** 成功時に +1 する DirectInput マウスの検出数。device2 の正体は
       特定 I/O 基板ではなく **OS のシステムマウス**だった。dinput.diag(api.c) のライブ計装で、開発 PC の実マウス＋
       WGL ウィンドウ(hwnd==FindWindow"WGL")で **count=1・mouse 非null・hwnd 有効** を確認 → 素の usbio_errCode_mapper
       が default(errCode 0xf=951)経路に入らず、byte patch 無しで 951 が出ない。touch/card と同じ「詐称→純正供給」格上げ。
       旧「撤去すると 0910 停滞」は **マウス不在環境**での旧実測（count=0 前提）。fallback: 真のヘッドレス/マウス無し
       環境では count=0 で 951 再発しうる → その場合は本エントリ復活ではなく「ウィンドウ＋システムマウスの供給」で解く。
       詳細 facts/devices.md・amjvs.md。 */
    /* {0x6F0B80, P_zero1, 1, "USB I/O board errCode imm 0F->00 (Error 951)"}, — 実 SysMouse で純正化済（撤去） */
    /* dipsw byte2->3 / byte3->0x20(board index 2) は撤去: dipsw ctx を api.c dipsw_force_ready が provisioning し、
       read fn の mxsmbus IOCTL(0x9c402004,cmd5) を mxdev_ioctl が応答(index0=0x20)。素の amDipswRead が board index 2
       を算出するため byte patch 不要。詳細 facts/devices.md。再発(errCode 0xa/0xb)時は復活させる。 */
    /* mxnetwork/state.js */
    {0x6FF1B3, P_one1, 1, "LAN flag b50c 0->1 (Error 8005)"},
    {0x72DCE0, P_ret2, 6, "amlib_device_status_getter->2 (Error 8001)"},
    /* mxsegaboot/startup.js */
    {0x72B3A0, P_extimg, 11, "extend_image_install_status (state7)"},
    /* 0x701280 pras_billing_ready_check->al=1 は撤去（2026-06-30, A 統合）: 上の alpbExGetExecStatus->8 が
       alpbEx_billing_poll 経由で alpbEx_billing_ready=1 を game 自身に立てさせるため、ready!=0 で本 check が
       自然に通る。詐称不要。再発(state7 ハング)時は alpbExGetExecStatus が 8 を返せているか先に確認。 */
    /* mxstorage/presence.js */
    {0x4FDA50, RET0, 3, "is-DVD-boot->0 (Error 913)"},
    /* mxkeychip/region.js — region check 無効化 */
    {0x986A66, NOP6, 6, "region jne->nop (Error 0x381)"},
    {0x986A74, NOP6, 6, "region jne->nop (Error 0x387 wrong region)"},
    {0x986A92, NOP6, 6, "region jne->nop (Error 0x38D)"},
    /* 0x459109 errCode=4 store NOP (amlib_master_init 0x458fd0) は撤去（2026-06-30, 純正供給経路で実証）:
       EEPROM STATIC を seed し amEepromInit を gamehook detour（host gamehook.c d_eeprom_init）で storage init
       中に provisioning すると、genuine な amBackupRead(STATIC) が region_game_pcb=01 を供給し
       (region_game_pcb & region_dongle & 5)!=0 が自然に通る。ライブ差分実証: 撤去後も amlib_master_init の
       Region error(00,01,05) は出ない。実装 src/logic/driver/mxdevices.c eeprom_seed_static。詳細 facts/mxkeychip.md。 */
    {0x45A846, NOP10, 10, "errCode=4 store nop (FUN_0045a7f0): 第3オペランドが alAbEx/ALL.Net network region(FUN_006ff900)で未供給ゆえ維持。撤去には network region 層が要る（facts/mxkeychip.md ライブ検証）"},
    /* mxgfetcher/getstatus.js 由来だが実体は HLSM の region ゲート */
    {0x6FF980, RET1, 6, "hlsm_region_check->1: HLSM(0x457fe0) の region ゲート（0x210aed0/2/4 参照。keychip region NOP 0x986A.. とは別経路）"},
    /* amplatform/identity.js（platform gate FUN_0045a6f0 回避） */
    /* 0x981FF0 amPlatformGetPlatformId->"AAL" は撤去: columba DMI(mxdevices.c build_dmi の OEM
       string index2="AAL")が amOemstringGetOemstring 経由で供給するため素の関数が "AAL" を返す＝冗長。
       詳細 facts/amplatform.md。再発時(Error 0901)は復活させる。 */
    /* 0x981D60 amPlatformGetOsVersion->"WindowsXP" も撤去: gate FUN_0045a6f0 は OsVersion の戻り 0 のみ要求
       （値は捨てる）。原関数は C:\System\SystemVersion.txt を読み非ゼロ parse で戻り 0 を返すので、host が
       同ファイルを仮想供給(api.c)すれば素の関数が戻り 0。standalone 欠損時は -3→errCode 3 なので仮想ファイル必須。
       詳細 facts/amplatform.md。再発(errCode 3)時は復活させる。 */
};

/* jl(0x7C disp8) -> jmp(0xEB disp8): byte0 のみ書換 */
static const uint32_t JL2JMP[] = { 0x97588A, 0x97595F, 0x975A1F };

typedef struct { uint32_t va; uint32_t val; int size; } DataWrite;
static const DataWrite DATA[] = {
    /* amjvs node BSS の forgery data write は撤去（native discovery が node を満たす）。 */
    /* mxkeychip/region.js — region=JAPAN */
    /* 0x16014C4(region_game_pcb/STATIC) は維持: anti-tamper FUN_0048f9c0 の region-index 整合用
       （EEPROM STATIC seed が genuine 供給するが gate/anti-tamper が直読みするため温存。mxkeychip.md）。 */
    /* 0x16014C4(region_game_pcb/STATIC) は維持: anti-tamper FUN_0048f9c0 の region-index 整合用
       （EEPROM STATIC seed が genuine 供給するが gate/anti-tamper が直読みするため温存。mxkeychip.md）。 */
    {0x16014C4, 1, 1},
    /* 0x1601744(region_cached)/0x1601989(region_dongle) 撤去済（2026-06-30 差分ライブ実証, patches 20→18）:
       両者とも game 自身の writer が genuine 供給を持つ（実体確認）ため DATA write は冗長:
       - 0x1601989 ← FUN_00459220 の FUN_0096f160(&region_dongle) = keychip appboot.region PCP（keychip present 枝。
         standalone は on_keychip_hold で presence 維持・keychip_server が =01 を返す）。gate=amlib_region_gate が直読み。
       - 0x1601744 ← FUN_0045acc0 の `DAT_01601744 = DAT_016014c4`（region_game_pcb/STATIC seed=01 のコピー、amlib_eeprom_ok 成立時）。
       差分実証: patches=20(両 write 有) と patches=18(撤去) でログ error 3件・画面とも完全一致＝撤去でビット等価。
       撤去後も region_dongle=01 維持（`Region error (01,01,00,05)` の第2 operand）＝keychip 供給がライブで効いている証拠。
       （`(01,01,00,05)` の第3 operand=00 は ALL.Net network region 未供給の別件＝0x45A846 維持で errCode 抑止。撤去前から同一。）
       回帰（0903/region error or SYSTEM STARTUP "ERROR."）時は本2行を復活。 */
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
    for (size_t i = 0; i < sizeof JL2JMP / sizeof JL2JMP[0]; i++)
        wr(base + (JL2JMP[i] - IMAGE_BASE), &jmp, 1);

    for (size_t i = 0; i < sizeof DATA / sizeof DATA[0]; i++) {
        uintptr_t a = base + (DATA[i].va - IMAGE_BASE);
        if (DATA[i].size == 1) { uint8_t v = (uint8_t)DATA[i].val; wr(a, &v, 1); }
        else if (DATA[i].size == 2) { uint16_t v = (uint16_t)DATA[i].val; wr(a, &v, 2); }
        else { uint32_t v = DATA[i].val; wr(a, &v, 4); }
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

    int total = (int)(sizeof CODE / sizeof CODE[0]) + (int)(sizeof JL2JMP / sizeof JL2JMP[0])
              + (int)(sizeof DATA / sizeof DATA[0]) + 2;
    wsprintfA(msg, "{\"ev\":\"patches.applied\",\"count\":%d,\"base\":\"%p\"}", total, (void *)base);
    if (h && h->log) h->log("info", msg);
}
