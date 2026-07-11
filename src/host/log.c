/* 構造化ログ(JSONL)。統合 GUI(loader.exe) が tail する主要な観測チャネル。 */
#include "host.h"
#include "status.h"
#include <stdio.h>

static CRITICAL_SECTION g_log_cs;
static FILE *g_fp = 0;
static int   g_init = 0;

void host_log(const char *level, const char *json_line) {
    if (!g_init) { InitializeCriticalSection(&g_log_cs); g_init = 1; }
    EnterCriticalSection(&g_log_cs);
    if (!g_fp) g_fp = fopen("nrsedge.log", "a");
    if (g_fp) {
        SYSTEMTIME t; GetLocalTime(&t);
        /* 1 行 = {"ts":"HH:MM:SS.mmm","lvl":..,"m":payload}。payload は呼び元の JSON 片。 */
        fprintf(g_fp, "{\"ts\":\"%02d:%02d:%02d.%03d\",\"lvl\":\"%s\",\"m\":%s}\n",
                t.wHour, t.wMinute, t.wSecond, t.wMilliseconds,
                level ? level : "info", json_line ? json_line : "{}");
        fflush(g_fp);
    }
    LeaveCriticalSection(&g_log_cs);
    /* 集約ステータスを更新（nrsedge.status.json）。ログ critical section の外で I/O し
     * ホットなログ経路を直列化しない。status_observe は host_log を呼ばないので再入なし。 */
    status_observe(level, json_line);
}
