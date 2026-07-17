#include "host.h"
#include "status.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static CRITICAL_SECTION s_cs;
static int   s_init = 0;
static DWORD s_start_tick = 0;
static int   s_since_flush = 0;

static struct {
    char  phase[16];
    int   ready;
    int   errors;
    int   patches;
    char  last_ev[64];
    char  last_ev_ts[16];
    char  last_err_m[400];
    char  last_err_ts[16];
} S;

static struct { const char *name; char state[12]; } SUB[] = {
    { "jvs",      "" }, { "keychip",  "" }, { "touch",    "" }, { "eeprom",   "" },
    { "dipsw",    "" }, { "network",  "" }, { "platform", "" }, { "card",     "" },
};
#define NSUB ((int)(sizeof SUB / sizeof SUB[0]))

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
    if(!strcmp(p,"exited"))    return 9;
    if(!strcmp(p,"error"))     return 8;
    return 0;
}
static void set_phase(const char *p){
    if(phase_rank(S.phase) >= 9) return;
    if(!strcmp(S.phase,"ready") && strcmp(p,"exited") && strcmp(p,"error")) return;
    strncpy(S.phase, p, sizeof S.phase -1); S.phase[sizeof S.phase -1]=0;
}
static void set_sub(const char *name, const char *state){
    for(int i=0;i<NSUB;i++) if(!strcmp(SUB[i].name,name)){
        strncpy(SUB[i].state, state, sizeof SUB[i].state -1);
        SUB[i].state[sizeof SUB[i].state -1]=0; return;
    }
}

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
    if(o<0 || o>=(int)sizeof buf) return;

    FILE *f = fopen("nrsedge.status.json.tmp", "wb");
    if(!f) return;
    fwrite(buf, 1, (size_t)o, f);
    fclose(f);
    MoveFileExA("nrsedge.status.json.tmp", "nrsedge.status.json", MOVEFILE_REPLACE_EXISTING);
}

void status_observe(const char *level, const char *json_line){
    if(!s_init){ InitializeCriticalSection(&s_cs); s_start_tick=GetTickCount(); s_init=1; }
    if(!json_line) return;
    EnterCriticalSection(&s_cs);

    char ev[64]=""; jget_str(json_line, "ev", ev, sizeof ev);
    int phase_changed = 0;
    char prev_phase[16]; strncpy(prev_phase, S.phase, sizeof prev_phase); prev_phase[15]=0;

    if(ev[0]){ strncpy(S.last_ev, ev, sizeof S.last_ev -1); S.last_ev[sizeof S.last_ev -1]=0;
               ts_now(S.last_ev_ts, sizeof S.last_ev_ts); }

    if      (!strcmp(ev,"host.attach"))   set_phase("attaching");
    else if (!strcmp(ev,"hooks.ok"))      set_phase("hooks");
    else if (!strcmp(ev,"logic.ok"))      set_phase("logic");
    else if (!strcmp(ev,"gamehooks.ok"))  set_phase("gamehooks");
    else if (!strcmp(ev,"host.ready"))  { S.ready=1; set_phase("ready"); }
    else if (!strcmp(ev,"hooks.fail") || !strcmp(ev,"logic.load.fail")) set_phase("error");

    int is_exit = (!strcmp(ev,"ExitProcess") || !strcmp(ev,"TerminateProcess")
                || !strcmp(ev,"NtTerminateProcess"));

    if((level && !strcmp(level,"error")) || is_exit){
        S.errors++;
        strncpy(S.last_err_m, json_line, sizeof S.last_err_m -1);
        S.last_err_m[sizeof S.last_err_m -1]=0;
        ts_now(S.last_err_ts, sizeof S.last_err_ts);
    }
    if(is_exit) set_phase("exited");

    if(!strcmp(ev,"patches.applied")) jget_int(json_line, "count", &S.patches);

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

    if(phase_changed || is_exit || (level && !strcmp(level,"error")) || s_since_flush>=32){
        status_flush();
        s_since_flush = 0;
    }
    LeaveCriticalSection(&s_cs);
}
