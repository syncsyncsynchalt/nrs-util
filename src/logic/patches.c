#include <windows.h>
#include <stdint.h>
#include "abi.h"

#define IMAGE_BASE 0x400000u

typedef struct { uint32_t va; const uint8_t *b; int n; const char *note; } CodePatch;

static const uint8_t P_billing[]   = {0xB8,0x08,0x00,0x00,0x00,0xC3};
static const uint8_t RET0[]        = {0x31,0xC0,0xC3};
static const uint8_t RET8_0[]      = {0x31,0xC0,0xC2,0x08,0x00};
static const uint8_t P_ret2[]      = {0xB8,0x02,0x00,0x00,0x00,0xC3};
static const uint8_t NOP6[]        = {0x90,0x90,0x90,0x90,0x90,0x90};

static const CodePatch CODE[] = {
    {0xA065C0, P_billing, 6, "alpbExGetExecStatus->8"},
    {0x457AF0, RET8_0, 5, "delete_directory_recursive nop"},
    {0x4FDA50, RET0, 3, "is-DVD-boot->0 (Error 913)"},
};

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
    uintptr_t base = (uintptr_t)GetModuleHandleW(NULL);
    char msg[160];

    for (size_t i = 0; i < sizeof CODE / sizeof CODE[0]; i++)
        wr(base + (CODE[i].va - IMAGE_BASE), CODE[i].b, CODE[i].n);

    uint8_t jmp = 0xEB;
    for (size_t i = 0; i < sizeof JL2JMP / sizeof JL2JMP[0]; i++)
        wr(base + (JL2JMP[i] - IMAGE_BASE), &jmp, 1);

    {
        uintptr_t a = base + (0x6C3F20 - IMAGE_BASE);
        if (*(volatile uint8_t *)a == 0x74) { uint8_t v = 0xEB; wr(a, &v, 1); }
    }

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
