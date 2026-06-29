/* status.c — boot フェーズ / エラー数 / サブシステム ready を集約し nrsedge.status.json へ書く。
 *
 * 設計: host_log(log.c) が host・logic 双方の全イベントの単一通過点。そこから status_observe を呼べば
 *   ABI を変えず（HostServices.log は既に host_log を指す）logic を一切触らず集約状態が得られる。
 * status.c は host.dll の一部＝nrs.exe プロセス内で走るので GetCurrentProcessId() = nrs.exe の pid。
 * 書込は tmp→MoveFileEx で原子的に置換。80k 行/セッションなので phase 変化時＋N 行毎にスロットル。 */
#include "host.h"
#include "status.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ---- 集約状態（observe が更新、flush が書出） ---- */
static CRITICAL_SECTION s_cs;
static int   s_init = 0;
static DWORD s_start_tick = 0;
static int   s_since_flush = 0;     /* 前回 flush 以降の観測数（スロットル用） */

static struct {
    char  phase[16];                /* attaching|hooks|logic|gamehooks|ready|exited|error */
    int   ready;
    int   errors;
    int   patches;
    char  last_ev[64];
    char  last_ev_ts[16];
    char  last_err_m[400];          /* 直近エラー/終了イベントの m ペイロード(生 JSON)。空=未発生 */
    char  last_err_ts[16];
} S;

/* 関心のあるサブシステムと現在の状態（"" = 未観測）。ev からの推論で更新。 */
static struct { const char *name; char state[12]; } SUB[] = {
    { "jvs",      "" }, { "keychip",  "" }, { "touch",    "" }, { "eeprom",   "" },
    { "dipsw",    "" }, { "network",  "" }, { "platform", "" }, { "card",     "" },
};
#define NSUB ((int)(sizeof SUB / sizeof SUB[0]))

/* ---- 軽量 JSON 抽出（m ペイロード前提の最小実装） ---- */
static int jget_str(const char *j, const char *key, char *out, int cap){
    char needle[64]; _snprintf(needle, sizeof needle, "\"%s\":\"", key);
    const char *p = strstr(j, needle); if(!p) return 0;
    p += strlen(needle);
    int i=0; while(*p && *p!='"' && i<cap-1){ if(*p=='\\'&&p[1]) p++; out[i++]=*p++; }
    out[i]=0; return 1;
}
static int jget_int(const char *j, const char *key, int *out){
    char needle[64]; _snprintf(needle, sizeof needle, "\"%s\":", key);
    const char *p = strstr(j, needle); if(!p) return 0;
    *out = (int)strtol(p + strlen(needle), NULL, 0); return 1;
}

static void ts_now(char *out, int cap){
    SYSTEMTIME t; GetLocalTime(&t);
    _snprintf(out, cap, "%02d:%02d:%02d.%03d", t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
}

static int phase_rank(const char *p){
    if(!strcmp(p,"attaching")) return 1;
    if(!strcmp(p,"hooks"))     return 2;
    if(!strcmp(p,"logic"))     return 3;
    if(!strcmp(p,"gamehooks")) return 4;
    if(!strcmp(p,"ready"))     return 5;
    if(!strcmp(p,"exited"))    return 9;   /* 終端 */
    if(!strcmp(p,"error"))     return 8;   /* ready 未到達の致命 */
    return 0;
}
/* breadcrumb は時系列で単調。exited/error/ready からの巻き戻しは禁止。 */
static void set_phase(const char *p){
    if(phase_rank(S.phase) >= 9) return;                 /* exited は終端 */
    if(!strcmp(S.phase,"ready") && strcmp(p,"exited") && strcmp(p,"error")) return;
    strncpy(S.phase, p, sizeof S.phase -1); S.phase[sizeof S.phase -1]=0;
}
static void set_sub(const char *name, const char *state){
    for(int i=0;i<NSUB;i++) if(!strcmp(SUB[i].name,name)){
        strncpy(SUB[i].state, state, sizeof SUB[i].state -1);
        SUB[i].state[sizeof SUB[i].state -1]=0; return;
    }
}

/* ---- 原子的書出 ---- */
static void status_flush(void){
    char buf[1600]; int o=0;
    char ts[16]; ts_now(ts, sizeof ts);
    DWORD up = s_start_tick ? (GetTickCount() - s_start_tick) : 0;

    o += _snprintf(buf+o, sizeof buf-o,
        "{\"ts\":\"%s\",\"phase\":\"%s\",\"pid\":%lu,\"ready\":%s,\"errors\":%d,"
        "\"patches\":%d,\"uptime_ms\":%lu,",
        ts, S.phase[0]?S.phase:"attaching", GetCurrentProcessId(),
        S.ready?"true":"false", S.errors, S.patches, up);

    if(S.last_ev[0])
        o += _snprintf(buf+o, sizeof buf-o,
            "\"last_event\":{\"ev\":\"%s\",\"ts\":\"%s\"},", S.last_ev, S.last_ev_ts);
    else
        o += _snprintf(buf+o, sizeof buf-o, "\"last_event\":null,");

    if(S.last_err_m[0])
        o += _snprintf(buf+o, sizeof buf-o,
            "\"last_error\":{\"ts\":\"%s\",\"m\":%s},", S.last_err_ts, S.last_err_m);
    else
        o += _snprintf(buf+o, sizeof buf-o, "\"last_error\":null,");

    o += _snprintf(buf+o, sizeof buf-o, "\"subsys\":{");
    int first=1;
    for(int i=0;i<NSUB;i++){
        if(!SUB[i].state[0]) continue;
        o += _snprintf(buf+o, sizeof buf-o, "%s\"%s\":\"%s\"",
                       first?"":",", SUB[i].name, SUB[i].state);
        first=0;
    }
    o += _snprintf(buf+o, sizeof buf-o, "}}\n");
    if(o<0 || o>=(int)sizeof buf) return;   /* 切詰時は破損 JSON を書かない */

    /* tmp に書いて MoveFileEx で原子置換（同一 dir = ゲーム cwd）。log.c と同じ相対パス。 */
    FILE *f = fopen("nrsedge.status.json.tmp", "wb");
    if(!f) return;
    fwrite(buf, 1, (size_t)o, f);
    fclose(f);
    MoveFileExA("nrsedge.status.json.tmp", "nrsedge.status.json", MOVEFILE_REPLACE_EXISTING);
}

/* ---- 観測（host_log から全行） ---- */
void status_observe(const char *level, const char *json_line){
    if(!s_init){ InitializeCriticalSection(&s_cs); s_start_tick=GetTickCount(); s_init=1; }
    if(!json_line) return;
    EnterCriticalSection(&s_cs);

    char ev[64]=""; jget_str(json_line, "ev", ev, sizeof ev);
    int phase_changed = 0;
    char prev_phase[16]; strncpy(prev_phase, S.phase, sizeof prev_phase); prev_phase[15]=0;

    /* last_event */
    if(ev[0]){ strncpy(S.last_ev, ev, sizeof S.last_ev -1); S.last_ev[sizeof S.last_ev -1]=0;
               ts_now(S.last_ev_ts, sizeof S.last_ev_ts); }

    /* boot フェーズ breadcrumb。phase は「boot がどこまで進んだか」と終端のみを表す。
     * error は host_init が確実に失敗するイベント（host.c が早期 return = host.ready が永遠に来ない）に限る。
     * ゲーム側 error 行や attract の良性エラーは errors カウンタには出すが phase は動かさない（誤った終端判定を防ぐ）。 */
    if      (!strcmp(ev,"host.attach"))   set_phase("attaching");
    else if (!strcmp(ev,"hooks.ok"))      set_phase("hooks");
    else if (!strcmp(ev,"logic.ok"))      set_phase("logic");
    else if (!strcmp(ev,"gamehooks.ok"))  set_phase("gamehooks");
    else if (!strcmp(ev,"host.ready"))  { S.ready=1; set_phase("ready"); }
    else if (!strcmp(ev,"hooks.fail") || !strcmp(ev,"logic.load.fail")) set_phase("error");

    /* 終了イベント（exitlog.c 由来。warn レベルだが errors として数える） */
    int is_exit = (!strcmp(ev,"ExitProcess") || !strcmp(ev,"TerminateProcess")
                || !strcmp(ev,"NtTerminateProcess"));

    /* エラー集計（loader level_of と一致: lvl=error または exit イベント）。phase は動かさない
     * （良性のゲーム error が host.ready 前に来ても boot 失敗と誤判定しない。真の失敗は上の breadcrumb で扱う）。 */
    if((level && !strcmp(level,"error")) || is_exit){
        S.errors++;
        strncpy(S.last_err_m, json_line, sizeof S.last_err_m -1);
        S.last_err_m[sizeof S.last_err_m -1]=0;
        ts_now(S.last_err_ts, sizeof S.last_err_ts);
    }
    if(is_exit) set_phase("exited");

    /* patches.applied の count */
    if(!strcmp(ev,"patches.applied")) jget_int(json_line, "count", &S.patches);

    /* サブシステム readiness 推論（ev 接頭辞）。詳細状態より「どこまで動いたか」を表す。 */
    if(!strcmp(ev,"jvs.open"))                       set_sub("jvs","open");
    else if(!strcmp(ev,"jvs.io"))                    set_sub("jvs","ok");
    if(!strcmp(ev,"keychip.server.up"))              set_sub("keychip","up");
    else if(!strncmp(ev,"keychip",7))                set_sub("keychip","ok");
    if(!strcmp(ev,"touch.open"))                     set_sub("touch","open");
    else if(!strcmp(ev,"touch.read")||!strcmp(ev,"touch.write")) set_sub("touch","ok");
    if(!strcmp(ev,"eeprom.force_ready"))             set_sub("eeprom","ok");
    if(!strcmp(ev,"dipsw.force_ready"))              set_sub("dipsw","ok");
    if(!strncmp(ev,"mxnetwork",9)||!strncmp(ev,"net",3)) set_sub("network","ok");
    if(!strncmp(ev,"card",4))                        set_sub("card","ok");

    phase_changed = strcmp(prev_phase, S.phase)!=0;
    s_since_flush++;

    /* スロットル: phase 変化・エラー/終了・32 行毎に書出。常時毎行は避ける。 */
    if(phase_changed || is_exit || (level && !strcmp(level,"error")) || s_since_flush>=32){
        status_flush();
        s_since_flush = 0;
    }
    LeaveCriticalSection(&s_cs);
}
