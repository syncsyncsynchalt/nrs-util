#include "host.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static NrsConfig g_cfg;
static const char *ACT[ACT_COUNT] = {
    "test", "service", "coin", "start", "up", "down", "left", "right", "jump", "dash", "action"
};

const NrsConfig *config_load(void) {
    static const unsigned short defb[ACT_COUNT] =
        { 0x70, 0x71, 0x35, 0x31, 0x26, 0x28, 0x25, 0x27, 0x5A, 0x58, 0x43 };
    g_cfg.freeplay = 1; g_cfg.test_mode = 0; g_cfg.windowed = 1; g_cfg.jvs_com = 9;
    memcpy(g_cfg.bind, defb, sizeof defb);

    FILE *f = fopen("nrsedge.cfg", "r");
    if (f) {
        char line[160];
        while (fgets(line, sizeof line, f)) {
            char *eq = strchr(line, '=');
            if (!eq) continue;
            *eq = 0;
            char *k = line, *v = eq + 1;
            while (*k == ' ' || *k == '\t') k++;
            int val = atoi(v);
            if (!strcmp(k, "freeplay")) g_cfg.freeplay = val;
            else if (!strcmp(k, "test")) g_cfg.test_mode = val;
            else if (!strcmp(k, "windowed")) g_cfg.windowed = val;
            else if (!strcmp(k, "jvs_com")) g_cfg.jvs_com = val;
            else if (!strncmp(k, "bind.", 5)) {
                for (int i = 0; i < ACT_COUNT; i++)
                    if (!strcmp(k + 5, ACT[i])) g_cfg.bind[i] = (unsigned short)val;
            }
        }
        fclose(f);
    }
    const char *ew = getenv("NRSEDGE_WINDOWED");
    if (ew && *ew) g_cfg.windowed = atoi(ew);
    return &g_cfg;
}
