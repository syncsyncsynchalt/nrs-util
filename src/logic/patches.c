/* patches.c — boot 各サブシステムの静的バイトパッチ。nrs.exe ImageBase 0x400000。
 * 動的サブシステム(keychip server / mxdrivers IOCTL / rtc / region 条件分岐 等)は別モジュール。
 * 撤去済パッチとその実証は git log / facts/。 */
#include <windows.h>
#include <stdint.h>
#include "abi.h"

#define IMAGE_BASE 0x400000u

typedef struct { uint32_t va; const uint8_t *b; int n; const char *note; } CodePatch;

/* --- byte patches（静的VA, 上書きバイト） --- */
static const uint8_t P_billing[]   = {0xB8,0x08,0x00,0x00,0x00,0xC3};        /* mov eax,8;ret */
static const uint8_t RET0[]        = {0x31,0xC0,0xC3};                       /* xor eax,eax;ret */
static const uint8_t RET8_0[]      = {0x31,0xC0,0xC2,0x08,0x00};             /* xor eax,eax;ret 8（__thiscall callee-clean）*/
static const uint8_t RET1[]        = {0xB8,0x01,0x00,0x00,0x00,0xC3};        /* mov eax,1;ret */
static const uint8_t P_one1[]      = {0x01};                                 /* imm 1 */
static const uint8_t P_ret2[]      = {0xB8,0x02,0x00,0x00,0x00,0xC3};        /* mov eax,2;ret */
static const uint8_t NOP6[]        = {0x90,0x90,0x90,0x90,0x90,0x90};
static const uint8_t NOP10[]       = {0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90};

static const CodePatch CODE[] = {
    /* status 8 は alpbEx_billing_poll(0x7000C0) case8 で billing_ready=1 を立てる（accounting 無し）→ boot SM
       state7 の pras_billing_ready_check(0x701280) が自然に通る。実 credit 計上を配線する際は status 8↔5 を再評価。 */
    {0xA065C0, P_billing, 6, "alpbExGetExecStatus->8"},
    /* __thiscall(this,arg1,arg2)=callee-clean ゆえ ret 8 必須（call site に add esp 無し、bare ret はスタック破壊→クラッシュ）。
       keychipSM_FSM case4 の appdata 不一致時 recursive dir delete をブロック。DO NOT REMOVE（facts/bugs.md, amdongle.md）。 */
    {0x457AF0, RET8_0, 5, "delete_directory_recursive nop"},
    {0x6FF1B3, P_one1, 1, "LAN flag b50c 0->1 (Error 8005)"},
    {0x72DCE0, P_ret2, 6, "amlib_device_status_getter->2 (Error 8001)"},
    {0x4FDA50, RET0, 3, "is-DVD-boot->0 (Error 913)"},
    {0x986A66, NOP6, 6, "region jne->nop (Error 0x381)"},
    {0x986A74, NOP6, 6, "region jne->nop (Error 0x387 wrong region)"},
    {0x986A92, NOP6, 6, "region jne->nop (Error 0x38D)"},
    /* 第3オペランド=alAbEx/ALL.Net network region(FUN_006ff900)が未供給ゆえ維持。撤去には network region 層が要る。 */
    {0x45A846, NOP10, 10, "errCode=4 store nop (FUN_0045a7f0)"},
    /* HLSM(0x457fe0) の region ゲート（keychip region NOP 0x986A.. とは別経路）。 */
    {0x6FF980, RET1, 6, "hlsm_region_check->1"},
};

/* jl(0x7C disp8) -> jmp(0xEB disp8): byte0 のみ書換 */
static const uint32_t JL2JMP[] = { 0x97588A, 0x97595F, 0x975A1F };

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

    /* self-shutdown 無効化: 0x6C3F20 が je(0x74) のときだけ jmp(0xEB) 化 */
    {
        uintptr_t a = base + (0x6C3F20 - IMAGE_BASE);
        if (*(volatile uint8_t *)a == 0x74) { uint8_t v = 0xEB; wr(a, &v, 1); }
    }

    /* JVS が開く COM ポート名 "COM4"@0xAE11F0 を cfg->jvs_com にパッチ（単桁 1..9, 既定 9）。
       amJvstInit→CreateFileA がこの文字列を使い、on_create_file の is_jvs_com も同番号を見る。
       元バイトは "COM4\0\0\0\0" ゆえ 5バイト書込みは安全（在地枠のため単桁限定）。 */
    {
        int port = (h && h->cfg && h->cfg->jvs_com) ? h->cfg->jvs_com : 9;
        if (port >= 1 && port <= 9) {
            uint8_t s[5] = { 'C', 'O', 'M', (uint8_t)('0' + port), 0 };
            wr(base + (0xAE11F0 - IMAGE_BASE), s, 5);
        }
    }

    int total = (int)(sizeof CODE / sizeof CODE[0]) + (int)(sizeof JL2JMP / sizeof JL2JMP[0]) + 2;
    wsprintfA(msg, "{\"ev\":\"patches.applied\",\"count\":%d,\"base\":\"%p\"}", total, (void *)base);
    if (h && h->log) h->log("info", msg);
}
