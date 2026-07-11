/* config.c — 統合 GUI(loader.exe) が書く nrsedge.cfg(key=value) を読み NrsConfig へ。
 * host_init 早期に読み g_host.cfg へ。freeplay/test/windowed と入力バインド(bind.<action>=VK)を供給。 */
#include "host.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static NrsConfig g_cfg;
static const char *ACT[ACT_COUNT] = {
    "test", "service", "coin", "start", "up", "down", "left", "right", "jump", "dash", "action"
};

const NrsConfig *config_load(void) {
    /* 既定バインド: F1/F2/5/1/arrows/Z/X/C、freeplay=ON, windowed=ON */
    static const unsigned short defb[ACT_COUNT] =
        { 0x70, 0x71, 0x35, 0x31, 0x26, 0x28, 0x25, 0x27, 0x5A, 0x58, 0x43 };
    /* jvs_com 既定=9: ゲームの COM マップ（touch=COM1/COM3, card=COM2, 元 JVS=COM4）と重複しない単桁。
       nrsedge.cfg `jvs_com=N`(1..9) で上書き可。1..3 は touch/card と衝突するので避けること。 */
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
    /* env 上書き（診断用）: NRSEDGE_WINDOWED=0 でフルスクリーン化＝windowed_install を抑止し DWM 合成を迂回。
     * loader が cfg に windowed=1 を強制書込みするため、cfg より後で効く env を最終権威にする。
     * DWM 2フレームビート(present.stats の stalls/doubles 多発)の切り分け用。未設定なら cfg 値のまま。 */
    const char *ew = getenv("NRSEDGE_WINDOWED");
    if (ew && *ew) g_cfg.windowed = atoi(ew);
    return &g_cfg;
}
