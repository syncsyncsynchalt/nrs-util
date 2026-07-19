#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <richedit.h>
#include <commdlg.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#define HEXRGB(x)  RGB(((x)>>16)&0xFF, ((x)>>8)&0xFF, (x)&0xFF)
static const COLORREF C_BG   = HEXRGB(0x13161b);
static const COLORREF C_BG2  = HEXRGB(0x1c212a);
static const COLORREF C_FG   = HEXRGB(0xd8d8d8);
static const COLORREF C_ACC  = HEXRGB(0x99aadd);

typedef enum { L_ERROR, L_WARN, L_PCPA, L_DEV, L_SETUP, L_IO, L_INFO } Level;
static COLORREF level_color(Level l){
    switch(l){
        case L_ERROR: return HEXRGB(0xff5f5f);
        case L_WARN:  return HEXRGB(0xffb454);
        case L_PCPA:  return HEXRGB(0x5fb0ff);
        case L_DEV:   return HEXRGB(0xffd24a);
        case L_SETUP: return HEXRGB(0x7bd66b);
        case L_IO:    return HEXRGB(0x6a6a6a);
        default:      return HEXRGB(0xd8d8d8);
    }
}

static wchar_t G_GAME_DIR[MAX_PATH], G_GAME_EXE[MAX_PATH];
static wchar_t G_HOST_DLL[MAX_PATH], G_LOGIC_DLL[MAX_PATH], G_CFG[MAX_PATH], G_LOG[MAX_PATH];
static wchar_t G_STATUS[MAX_PATH];
static wchar_t G_LOGPTR[MAX_PATH];
static wchar_t G_CARDCTL[MAX_PATH];
static wchar_t G_CARDS_DIR[MAX_PATH];

#define CARD_IMG_BYTES 0x1008
#define CARD_UID_OFF   0x04

#define NACT 11
static const char *ACTIONS[NACT] =
    { "test","service","coin","start","up","down","left","right","jump","dash","action" };
static int  g_bind[NACT]   = { 0x70,0x71,0x35,0x31,0x26,0x28,0x25,0x27,0x5A,0x58,0x43 };
static const int DEF_BIND[NACT] = { 0x70,0x71,0x35,0x31,0x26,0x28,0x25,0x27,0x5A,0x58,0x43 };

static void vkname(int vk, wchar_t *out, int cap){
    switch(vk){
        case 0x70: wcsncpy(out,L"F1",cap); return;   case 0x71: wcsncpy(out,L"F2",cap); return;
        case 0x35: wcsncpy(out,L"5",cap);  return;    case 0x31: wcsncpy(out,L"1",cap);  return;
        case 0x26: wcsncpy(out,L"Up",cap); return;    case 0x28: wcsncpy(out,L"Down",cap); return;
        case 0x25: wcsncpy(out,L"Left",cap);return;   case 0x27: wcsncpy(out,L"Right",cap);return;
        case 0x5A: wcsncpy(out,L"Z",cap);  return;    case 0x58: wcsncpy(out,L"X",cap);  return;
        case 0x43: wcsncpy(out,L"C",cap);  return;    case 0x0D: wcsncpy(out,L"Enter",cap);return;
        case 0x20: wcsncpy(out,L"Space",cap);return;
    }
    if((vk>='A'&&vk<='Z')||(vk>='0'&&vk<='9')){ out[0]=(wchar_t)vk; out[1]=0; return; }
    _snwprintf(out, cap, L"VK_0x%02X", vk);
}

enum {
    ID_LAUNCH=100, ID_STOP, ID_RELAUNCH,
    ID_FREEPLAY, ID_TEST, ID_WINDOWED,
    ID_STATUS, ID_TAB,
    ID_FILTER=200, ID_HIDEIO, ID_ERRONLY, ID_SEARCH, ID_SEARCHNEXT, ID_RESUME,
    ID_PAUSE, ID_CLEAR, ID_EXPORT, ID_LOG, ID_LOGSTATUS, ID_LBL_FILTER, ID_LBL_SEARCH,
    ID_BIND_LBL=300,
    ID_BIND_BTN=320,
    ID_BIND_IND=340,
    ID_ANALOG=400, ID_GAME, ID_SAVE, ID_CAP, ID_INPUT_HELP,
    ID_CARD_NEW=500, ID_CARD_LOAD, ID_CARD_INSERT, ID_CARD_EJECT, ID_CARD_SAVEAS, ID_CARD_REFRESH,
    ID_CARD_TYPE, ID_CARD_HEX, ID_CARD_LOG, ID_CARD_FIELDS, ID_CARD_HELP,
};
#define WM_APP_LOGLINE (WM_APP+1)
#define WM_APP_STATUS  (WM_APP+2)
#define WM_APP_RUNSTATE (WM_APP+3)
#define WM_APP_LOGCLEAR (WM_APP+5)

static HWND g_main, g_tab, g_status, g_log, g_logstatus, g_resume;
static HWND g_filter, g_search, g_cap, g_analog, g_game;
static HWND g_bindlbl[NACT], g_bindind[NACT];
static HWND g_card_hex, g_card_log, g_card_fields, g_card_type;
static wchar_t g_card_path[MAX_PATH];
static int  g_card_present = 0;
static int  g_card_gen = 0;
static HFONT g_font, g_fontUI;
static HBRUSH g_brBG, g_brBG2;
static int  g_busy = 0;
static int  g_running = 0;
static int  g_capture_act = -1;
static int  g_prev_down[256];
static COLORREF g_status_color;
static volatile LONG g_log_gen = 0;

#define NRS_MUTEX_GUI  L"Local\\nrs_edge_gui_singleton"
#define NRS_MUTEX_RUN  L"Local\\nrs_edge_launch_lock"
#define NRS_JOB_NAME   L"Local\\nrs_edge_job"
static HANDLE g_job = NULL;

typedef struct { char ts[16]; char src[64]; Level lvl; char *msg; } Entry;
static Entry  *g_ent;
static size_t  g_ent_n, g_ent_cap;
static int     g_errors;
static int     g_paused = 0;

static wchar_t* u8tow(const char *s){
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *w = (wchar_t*)malloc((size_t)n*sizeof(wchar_t));
    if(w) MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}
static char* wtou8(const wchar_t *w){
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    char *s = (char*)malloc((size_t)n);
    if(s) WideCharToMultiByte(CP_UTF8, 0, w, -1, s, n, NULL, NULL);
    return s;
}
static void nowts(char *out, int cap){
    time_t t = time(NULL); struct tm lt; localtime_s(&lt, &t);
    strftime(out, (size_t)cap, "%H:%M:%S", &lt);
}

static void resolve_paths(void){
    wchar_t exe[MAX_PATH]; GetModuleFileNameW(NULL, exe, MAX_PATH);
    wchar_t repo[MAX_PATH]; wcscpy(repo, exe);
    for(int i=0;i<3;i++){ wchar_t *p=wcsrchr(repo,L'\\'); if(p)*p=0; }

    wchar_t gdir[MAX_PATH];
    if(GetEnvironmentVariableW(L"NRS_GAME_DIR", gdir, MAX_PATH)==0) wcscpy(gdir, L"C:\\src\\bbs");
    wcscpy(G_GAME_DIR, gdir);
    _snwprintf(G_GAME_EXE,  MAX_PATH, L"%s\\nrs.exe", gdir);
    _snwprintf(G_CFG,      MAX_PATH, L"%s\\nrsedge.cfg", gdir);
    _snwprintf(G_LOG,      MAX_PATH, L"%s\\nrsedge.log", gdir);
    _snwprintf(G_LOGPTR,   MAX_PATH, L"%s\\nrsedge.logpath", gdir);
    FILE *pf=_wfopen(G_LOGPTR, L"r");
    if(pf){ wchar_t ln[MAX_PATH]; if(fgetws(ln,MAX_PATH,pf)){ ln[wcscspn(ln,L"\r\n")]=0; if(ln[0]) wcscpy(G_LOG,ln); } fclose(pf); }
    _snwprintf(G_STATUS,   MAX_PATH, L"%s\\nrsedge.status.json", gdir);
    _snwprintf(G_CARDCTL,  MAX_PATH, L"%s\\nrsedge.card.json", gdir);
    _snwprintf(G_CARDS_DIR,MAX_PATH, L"%s\\cards", gdir);
    _snwprintf(G_HOST_DLL, MAX_PATH, L"%s\\build\\Debug\\host.dll",  repo);
    _snwprintf(G_LOGIC_DLL,MAX_PATH, L"%s\\build\\Debug\\logic.dll", repo);
}

static int g_freeplay=1, g_test=0;
static const int g_windowed=1;
static void load_cfg(void){
    FILE *f = _wfopen(G_CFG, L"r"); if(!f) return;
    char ln[256];
    while(fgets(ln, sizeof ln, f)){
        char *eq = strchr(ln, '='); if(!eq) continue;
        *eq=0; char *k=ln, *v=eq+1; int val=atoi(v);
        if(strncmp(k,"bind.",5)==0){
            for(int i=0;i<NACT;i++) if(strcmp(k+5,ACTIONS[i])==0){ g_bind[i]=val; break; }
        } else if(strcmp(k,"freeplay")==0) g_freeplay=val;
        else if(strcmp(k,"test")==0)       g_test=val;
    }
    fclose(f);
}
static void write_cfg(void){
    FILE *f = _wfopen(G_CFG, L"w"); if(!f) return;
    fprintf(f, "freeplay=%d\n", g_freeplay);
    fprintf(f, "test=%d\n",     g_test);
    fprintf(f, "windowed=%d\n", g_windowed);
    for(int i=0;i<NACT;i++) fprintf(f, "bind.%s=%d\n", ACTIONS[i], g_bind[i]);
    fclose(f);
}

typedef struct { char key[48]; char val[256]; } KV;
static int parse_obj(const char *s, KV *out, int maxn){
    int n=0;
    while(*s && n<maxn){
        while(*s==' '||*s=='\t'||*s==','||*s=='\n'||*s=='\r') s++;
        if(*s=='}'||!*s) break;
        if(*s!='"') { s++; continue; }
        s++; int ki=0;
        while(*s && *s!='"' && ki<47) out[n].key[ki++]=*s++;
        out[n].key[ki]=0; if(*s=='"') s++;
        while(*s==' '||*s==':'||*s=='\t') s++;
        int vi=0;
        if(*s=='"'){
            s++;
            while(*s && *s!='"'){ if(*s=='\\'&&s[1]){ if(vi<255)out[n].val[vi++]=*s++; } if(vi<255)out[n].val[vi++]=*s++; }
            if(*s=='"') s++;
        } else {
            int depth=0;
            while(*s){
                char c=*s;
                if(c=='{'||c=='[') depth++;
                else if(c=='}'||c==']'){ if(depth==0) break; depth--; }
                else if(c==','&&depth==0) break;
                if(vi<255) out[n].val[vi++]=c;
                s++;
            }
            while(vi>0&&(out[n].val[vi-1]==' ')) vi--;
        }
        out[n].val[vi]=0;
        n++;
    }
    return n;
}
static void parse_line(const char *line, char *ts, char *lvl, char *mraw, int cap){
    ts[0]=lvl[0]=mraw[0]=0;
    const char *b = strchr(line,'{'); if(!b) return;
    KV top[16]; int n = parse_obj(b+1, top, 16);
    for(int i=0;i<n;i++){
        if(strcmp(top[i].key,"ts")==0)  strncpy(ts,  top[i].val, 15);
        else if(strcmp(top[i].key,"lvl")==0) strncpy(lvl, top[i].val, 15);
        else if(strcmp(top[i].key,"m")==0)   strncpy(mraw, top[i].val, (size_t)cap-1);
    }
}

static int has_ci(const char *h, const char *n){
    size_t ln=strlen(n);
    for(; *h; h++){ if(_strnicmp(h,n,ln)==0) return 1; }
    return 0;
}
static Level level_of(const char *lvl, const char *ev, const char *msg){
    char buf[1024]; _snprintf(buf,sizeof buf,"%s %s",ev,msg);
    if(strcmp(lvl,"error")==0) return L_ERROR;
    if(has_ci(buf,"error")||has_ci(buf,"fail")||has_ci(buf,"exception")||has_ci(buf,"deadlock")||has_ci(buf,"crash"))
        return L_ERROR;
    if(strcmp(ev,"ExitProcess")==0||strcmp(ev,"TerminateProcess")==0||strcmp(ev,"NtTerminateProcess")==0)
        return L_ERROR;
    if(strcmp(lvl,"warn")==0) return L_WARN;
    if(strncmp(ev,"input.state",11)==0||strncmp(ev,"jvs.tick",8)==0||strncmp(ev,"sys.ovr",7)==0) return L_IO;
    if(strncmp(ev,"keychip",7)==0||strncmp(ev,"pcp",3)==0) return L_PCPA;
    if(strncmp(ev,"jvs",3)==0||strncmp(ev,"mxdev",5)==0||strncmp(ev,"columba",7)==0) return L_DEV;
    if(strncmp(ev,"host",4)==0||strncmp(ev,"hooks",5)==0||strncmp(ev,"patches",7)==0||strncmp(ev,"logic",5)==0
       ||strncmp(ev,"gamehooks",9)==0||strncmp(ev,"windowed",8)==0||strncmp(ev,"reload",6)==0) return L_SETUP;
    return L_INFO;
}

static int g_autoscroll = 1;
static void update_resume_btn(void);
static void update_counts(void);

/* ---- 仮想ログビュー ----
   データは g_ent[] のまま。表示は「フィルタ通過エントリの index 配列 g_view」を持ち、
   WM_PAINT で可視行だけ TextOut する。スクロール=先頭 index の増減、フィルタ適用=
   g_view の再構築のみなので、行数に依存せず常に即応。 */
static int    *g_view;
static size_t  g_view_n, g_view_cap;
static char    g_flt[128];               /* filter 文字列(UTF-8, キャッシュ) */
static int     g_hideio, g_erronly;      /* チェックボックス状態のキャッシュ */
static size_t  g_top;                    /* 先頭可視行 (g_view index) */
static int     g_hpos;                   /* 水平スクロール位置 (文字数) */
static int     g_lineh = 16, g_charw = 8;
static size_t  g_sel_a = (size_t)-1, g_sel_b = (size_t)-1;  /* 行選択範囲 (g_view index) */
static int     g_dirty = 0;              /* 追記あり: タイマーでまとめて再描画 */
static size_t  g_maxchars = 80;

static void fmt_entry(const Entry *e, char *out, int cap){
    _snprintf(out, cap, "[%-12.12s] [%-22.22s] %s", e->ts, e->src, e->msg);
}
static int passes(const Entry *e){
    if(g_hideio && e->lvl==L_IO) return 0;
    if(g_erronly && e->lvl!=L_ERROR) return 0;
    /* filter: 空白区切りトークン。全て AND、'-' 前置は除外。src/msg を対象に部分一致。 */
    if(g_flt[0]){
        char tmp[128]; strncpy(tmp,g_flt,sizeof tmp-1); tmp[sizeof tmp-1]=0;
        char *save=NULL;
        for(char *tok=strtok_s(tmp," ",&save); tok; tok=strtok_s(NULL," ",&save)){
            int neg = (tok[0]=='-'); const char *t = neg? tok+1 : tok;
            if(!*t) continue;
            int m = has_ci(e->src,t)||has_ci(e->msg,t);
            if(neg ? m : !m) return 0;
        }
    }
    return 1;
}

static int logview_vis(void){
    RECT rc; GetClientRect(g_log,&rc);
    int v = rc.bottom / g_lineh;
    return v>0 ? v : 1;
}
static size_t logview_max_top(void){
    size_t vis=(size_t)logview_vis();
    return g_view_n>vis ? g_view_n-vis : 0;
}
static void logview_update_scroll(void){
    if(!g_log) return;
    SCROLLINFO si; si.cbSize=sizeof si; si.fMask=SIF_RANGE|SIF_PAGE|SIF_POS; si.nMin=0;
    si.nMax=(int)(g_view_n?g_view_n-1:0); si.nPage=(UINT)logview_vis(); si.nPos=(int)g_top;
    SetScrollInfo(g_log,SB_VERT,&si,TRUE);
    RECT rc; GetClientRect(g_log,&rc);
    si.nMax=(int)g_maxchars; si.nPage=(UINT)(rc.right>0? rc.right/g_charw : 1); si.nPos=g_hpos;
    SetScrollInfo(g_log,SB_HORZ,&si,TRUE);
}
static void logview_flush(void){
    if(!g_dirty || !g_log) return;
    g_dirty=0;
    if(g_autoscroll) g_top=logview_max_top();
    logview_update_scroll();
    InvalidateRect(g_log,NULL,FALSE);
    update_counts();
}
static void log_scroll_to_end(void){
    g_top=logview_max_top();
    logview_update_scroll();
    InvalidateRect(g_log,NULL,FALSE);
}
static void view_push(size_t ent_idx){
    if(g_view_n==g_view_cap){
        g_view_cap = g_view_cap? g_view_cap*2 : 8192;
        g_view = (int*)realloc(g_view, g_view_cap*sizeof(int));
    }
    g_view[g_view_n++]=(int)ent_idx;
    size_t chars = 42+strlen(g_ent[ent_idx].msg);
    if(chars>g_maxchars) g_maxchars=chars;
    g_dirty=1;
}
static void view_rebuild(void){
    g_view_n=0; g_maxchars=80;
    for(size_t i=0;i<g_ent_n;i++) if(passes(&g_ent[i])) view_push(i);
    g_sel_a=g_sel_b=(size_t)-1;
    { size_t mt=logview_max_top(); if(g_top>mt) g_top=mt; }
    g_dirty=1;
    logview_flush();
}
static void logview_user_scroll(size_t t){
    size_t maxt=logview_max_top();
    if(t>maxt) t=maxt;
    g_top=t;
    if(g_autoscroll){ g_autoscroll=0; update_resume_btn(); }
    logview_update_scroll();
    InvalidateRect(g_log,NULL,FALSE);
}
static void logview_copy(void){
    if(g_sel_a==(size_t)-1 || !g_view_n) return;
    size_t lo=g_sel_a<g_sel_b?g_sel_a:g_sel_b, hi=g_sel_a<g_sel_b?g_sel_b:g_sel_a;
    if(hi>=g_view_n) hi=g_view_n-1;
    size_t cap=8192, len=0;
    char *buf=(char*)malloc(cap); if(!buf) return;
    for(size_t vi=lo; vi<=hi; vi++){
        char line[1300]; fmt_entry(&g_ent[g_view[vi]], line, sizeof line);
        size_t l=strlen(line);
        if(len+l+3>cap){ while(len+l+3>cap) cap*=2; buf=(char*)realloc(buf,cap); if(!buf) return; }
        memcpy(buf+len,line,l); len+=l; buf[len++]='\r'; buf[len++]='\n';
    }
    buf[len]=0;
    wchar_t *w=u8tow(buf); free(buf);
    if(w && OpenClipboard(g_log)){
        EmptyClipboard();
        size_t bytes=(wcslen(w)+1)*sizeof(wchar_t);
        HGLOBAL hg=GlobalAlloc(GMEM_MOVEABLE,bytes);
        if(hg){ void *p=GlobalLock(hg); memcpy(p,w,bytes); GlobalUnlock(hg);
                SetClipboardData(CF_UNICODETEXT,hg); }
        CloseClipboard();
    }
    free(w);
}
static void logview_paint(HWND h){
    PAINTSTRUCT ps; HDC dc=BeginPaint(h,&ps);
    RECT rc; GetClientRect(h,&rc);
    HDC mem=CreateCompatibleDC(dc);
    HBITMAP bmp=CreateCompatibleBitmap(dc,rc.right,rc.bottom);
    HBITMAP ob=(HBITMAP)SelectObject(mem,bmp);
    FillRect(mem,&rc,g_brBG);
    HFONT of=(HFONT)SelectObject(mem,g_font);
    SetBkMode(mem,TRANSPARENT);
    int vis=logview_vis();
    size_t lo=g_sel_a<g_sel_b?g_sel_a:g_sel_b, hi=g_sel_a<g_sel_b?g_sel_b:g_sel_a;
    for(int i=0;i<vis;i++){
        size_t vi=g_top+(size_t)i; if(vi>=g_view_n) break;
        const Entry *e=&g_ent[g_view[vi]];
        if(g_sel_a!=(size_t)-1 && vi>=lo && vi<=hi){
            RECT lr={0,i*g_lineh,rc.right,(i+1)*g_lineh};
            HBRUSH sb=CreateSolidBrush(HEXRGB(0x2d3a55)); FillRect(mem,&lr,sb); DeleteObject(sb);
        }
        char line[1300]; fmt_entry(e,line,sizeof line);
        wchar_t w[1300]; int n=MultiByteToWideChar(CP_UTF8,0,line,-1,w,1300);
        SetTextColor(mem,level_color(e->lvl));
        TextOutW(mem, 2-g_hpos*g_charw, i*g_lineh, w, n?n-1:0);
    }
    SelectObject(mem,of);
    BitBlt(dc,0,0,rc.right,rc.bottom,mem,0,0,SRCCOPY);
    SelectObject(mem,ob); DeleteObject(bmp); DeleteDC(mem);
    EndPaint(h,&ps);
}
/* フィルタ文字列を差し替えて再構築（編集ボックスの表示も同期） */
static void logview_apply_filter(const char *u8){
    strncpy(g_flt, u8, sizeof g_flt-1); g_flt[sizeof g_flt-1]=0;
    wchar_t *w=u8tow(g_flt); if(w){ SetWindowTextW(g_filter, w); free(w); }
    view_rebuild();
}
/* 右クリック: クリック行の ev(=src) を軸にワンクリック隔離／除外。RE のサブシステム分離導線。 */
static void logview_context_menu(POINT screenPt, const char *src){
    HMENU m=CreatePopupMenu(); if(!m) return;
    if(src && src[0]){
        wchar_t *ws=u8tow(src); wchar_t item[160];
        if(ws){
            _snwprintf(item,160,L"「%s」だけ表示",ws); AppendMenuW(m,MF_STRING,1,item);
            _snwprintf(item,160,L"「%s」を除外",ws);   AppendMenuW(m,MF_STRING,2,item);
            free(ws);
        }
    }
    if(g_flt[0]) AppendMenuW(m,MF_STRING,3,L"フィルタ解除");
    AppendMenuW(m,MF_SEPARATOR,0,NULL);
    AppendMenuW(m,(g_sel_a==(size_t)-1?MF_GRAYED:0)|MF_STRING,4,L"選択行をコピー");
    int cmd=(int)TrackPopupMenu(m,TPM_RETURNCMD|TPM_RIGHTBUTTON|TPM_TOPALIGN,
                                screenPt.x,screenPt.y,0,g_main,NULL);
    DestroyMenu(m);
    if(cmd==1 && src){ logview_apply_filter(src); }
    else if(cmd==2 && src){
        char nf[128];
        if(g_flt[0]) _snprintf(nf,sizeof nf,"%s -%s", g_flt, src);
        else         _snprintf(nf,sizeof nf,"-%s", src);
        logview_apply_filter(nf);
    }
    else if(cmd==3){ logview_apply_filter(""); }
    else if(cmd==4){ logview_copy(); }
}
static LRESULT CALLBACK LogViewProc(HWND h, UINT msg, WPARAM wp, LPARAM lp){
    switch(msg){
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: logview_paint(h); return 0;
    case WM_SIZE:
        if(g_autoscroll) g_top=logview_max_top();
        logview_update_scroll();
        return 0;
    case WM_VSCROLL: {
        size_t t=g_top; size_t vis=(size_t)logview_vis();
        switch(LOWORD(wp)){
            case SB_LINEUP:   t = t? t-1 : 0; break;
            case SB_LINEDOWN: t = t+1; break;
            case SB_PAGEUP:   t = t>vis? t-vis : 0; break;
            case SB_PAGEDOWN: t = t+vis; break;
            case SB_TOP:      t = 0; break;
            case SB_BOTTOM:   t = logview_max_top(); break;
            case SB_THUMBTRACK: case SB_THUMBPOSITION: {
                SCROLLINFO si; si.cbSize=sizeof si; si.fMask=SIF_TRACKPOS;
                GetScrollInfo(h,SB_VERT,&si); t=(size_t)si.nTrackPos; break;
            }
            default: return 0;
        }
        logview_user_scroll(t);
        return 0;
    }
    case WM_HSCROLL: {
        RECT rc; GetClientRect(h,&rc); int page=rc.right/g_charw; if(page<1)page=1;
        int p=g_hpos;
        switch(LOWORD(wp)){
            case SB_LINEUP:   p-=4; break;
            case SB_LINEDOWN: p+=4; break;
            case SB_PAGEUP:   p-=page; break;
            case SB_PAGEDOWN: p+=page; break;
            case SB_THUMBTRACK: case SB_THUMBPOSITION: {
                SCROLLINFO si; si.cbSize=sizeof si; si.fMask=SIF_TRACKPOS;
                GetScrollInfo(h,SB_HORZ,&si); p=si.nTrackPos; break;
            }
            default: return 0;
        }
        if(p<0)p=0; if(p>(int)g_maxchars)p=(int)g_maxchars;
        g_hpos=p; logview_update_scroll(); InvalidateRect(h,NULL,FALSE);
        return 0;
    }
    case WM_MOUSEWHEEL: {
        static int acc; acc += GET_WHEEL_DELTA_WPARAM(wp);
        int lines=acc/(WHEEL_DELTA/3); acc-=lines*(WHEEL_DELTA/3);
        if(lines){
            size_t t=g_top;
            if(lines>0) t = t>(size_t)lines? t-(size_t)lines : 0;
            else        t = t+(size_t)(-lines);
            logview_user_scroll(t);
        }
        return 0;
    }
    case WM_GETDLGCODE: return DLGC_WANTARROWS;
    case WM_CONTEXTMENU: {
        POINT pt; size_t vi;
        if(lp==(LPARAM)-1){                       /* キーボード(Shift+F10) */
            vi = (g_sel_a!=(size_t)-1)? g_sel_a : g_top;
            RECT rc; GetClientRect(h,&rc); pt.x=rc.left+8; pt.y=rc.top+8;
            ClientToScreen(h,&pt);
        } else {
            pt.x=(short)LOWORD(lp); pt.y=(short)HIWORD(lp);
            POINT cp=pt; ScreenToClient(h,&cp);
            vi = g_top + (size_t)(cp.y<0?0:cp.y/g_lineh);
            /* 選択外を右クリックしたらその行へ選択を移す（選択内なら維持=複数行コピー用） */
            size_t lo=g_sel_a<g_sel_b?g_sel_a:g_sel_b, hi=g_sel_a<g_sel_b?g_sel_b:g_sel_a;
            int inside=(g_sel_a!=(size_t)-1 && vi>=lo && vi<=hi);
            if(g_view_n && vi<g_view_n && !inside){ g_sel_a=g_sel_b=vi; InvalidateRect(h,NULL,FALSE); }
        }
        char src[64]=""; int have=(g_view_n && vi<g_view_n);
        if(have){ strncpy(src,g_ent[g_view[vi]].src,sizeof src-1); src[sizeof src-1]=0; }
        logview_context_menu(pt, have?src:NULL);
        return 0;
    }
    case WM_LBUTTONDOWN: {
        SetFocus(h); SetCapture(h);
        if(g_view_n){
            size_t vi=g_top+(size_t)((int)(short)HIWORD(lp)/g_lineh);
            if(vi>=g_view_n) vi=g_view_n-1;
            g_sel_a=g_sel_b=vi;
        } else g_sel_a=g_sel_b=(size_t)-1;
        if(g_autoscroll){ g_autoscroll=0; update_resume_btn(); }
        InvalidateRect(h,NULL,FALSE);
        return 0;
    }
    case WM_MOUSEMOVE:
        if(GetCapture()==h && g_view_n && g_sel_a!=(size_t)-1){
            int y=(int)(short)HIWORD(lp);
            long long vi=(long long)g_top + (y<0? -1 : y/g_lineh);
            if(vi<0)vi=0; if(vi>=(long long)g_view_n)vi=(long long)g_view_n-1;
            if((size_t)vi!=g_sel_b){ g_sel_b=(size_t)vi; InvalidateRect(h,NULL,FALSE); }
        }
        return 0;
    case WM_LBUTTONUP: if(GetCapture()==h) ReleaseCapture(); return 0;
    case WM_KEYDOWN: {
        int ctrl=(GetKeyState(VK_CONTROL)&0x8000)!=0;
        size_t vis=(size_t)logview_vis();
        switch(wp){
            case 'C': if(ctrl) logview_copy(); return 0;
            case 'A': if(ctrl && g_view_n){ g_sel_a=0; g_sel_b=g_view_n-1; InvalidateRect(h,NULL,FALSE); } return 0;
            case VK_UP:    logview_user_scroll(g_top? g_top-1:0); return 0;
            case VK_DOWN:  logview_user_scroll(g_top+1); return 0;
            case VK_PRIOR: logview_user_scroll(g_top>vis? g_top-vis:0); return 0;
            case VK_NEXT:  logview_user_scroll(g_top+vis); return 0;
            case VK_HOME:  if(ctrl) logview_user_scroll(0); return 0;
            case VK_END:   if(ctrl) logview_user_scroll(logview_max_top()); return 0;
        }
        return 0;
    }
    }
    return DefWindowProcW(h,msg,wp,lp);
}

static void re_append_colored(HWND re, const wchar_t *wtext, COLORREF color){
    int end=GetWindowTextLengthW(re);
    SendMessageW(re, EM_SETSEL, end, end);
    CHARFORMAT2W cf; ZeroMemory(&cf,sizeof cf);
    cf.cbSize=sizeof cf; cf.dwMask=CFM_COLOR; cf.crTextColor=color;
    SendMessageW(re, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    SendMessageW(re, EM_REPLACESEL, FALSE, (LPARAM)wtext);
    SendMessageW(re, WM_VSCROLL, SB_BOTTOM, 0);
}

static void position_resume(void){
    if(!g_resume || !g_log) return;
    RECT lr; GetWindowRect(g_log, &lr);
    int rw=200, rh=24;
    SetWindowPos(g_resume, HWND_TOP, lr.right-rw-24, lr.bottom-rh-8, rw, rh, SWP_NOACTIVATE);
}
static LRESULT CALLBACK ResumeProc(HWND h, UINT msg, WPARAM wp, LPARAM lp){
    switch(msg){
        case WM_PAINT: {
            PAINTSTRUCT ps; HDC dc=BeginPaint(h,&ps);
            RECT rc; GetClientRect(h,&rc);
            HBRUSH br=CreateSolidBrush(HEXRGB(0x3a7bd5)); FillRect(dc,&rc,br); DeleteObject(br);
            SetBkMode(dc,TRANSPARENT); SetTextColor(dc,RGB(255,255,255));
            HFONT of=(HFONT)SelectObject(dc,g_fontUI);
            DrawTextW(dc, L"▼ 自動スクロール再開", -1, &rc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
            SelectObject(dc,of);
            EndPaint(h,&ps); return 0;
        }
        case WM_LBUTTONUP:
            g_autoscroll=1; log_scroll_to_end(); update_resume_btn();
            return 0;
    }
    return DefWindowProcW(h,msg,wp,lp);
}

static void update_counts(void){
    char buf[MAX_PATH+128]; char *logu=wtou8(G_LOG);
    _snprintf(buf,sizeof buf," %s  総数 %zu / 表示 %zu / エラー %d%s",
              logu, g_ent_n, g_view_n, g_errors, g_paused?"  [停止中]":"");
    free(logu);
    wchar_t *w=u8tow(buf); SetWindowTextW(g_logstatus, w); free(w);
}

static void update_test_row(const char *mraw){
    KV kv[40]; int n=parse_obj(mraw, kv, 40);
    char pressed[256]=""; int node643=0, ax=0, ay=0;
    for(int a=0;a<NACT;a++){
        for(int i=0;i<n;i++) if(strcmp(kv[i].key,ACTIONS[a])==0 && atoi(kv[i].val)==1){
            if(pressed[0]) strcat_s(pressed,sizeof pressed,"+");
            strcat_s(pressed,sizeof pressed,ACTIONS[a]); break;
        }
    }
    for(int i=0;i<n;i++){
        if(strcmp(kv[i].key,"node643")==0) node643=(int)strtol(kv[i].val,NULL,0);
        else if(strcmp(kv[i].key,"ax")==0) ax=(int)strtol(kv[i].val,NULL,0);
        else if(strcmp(kv[i].key,"ay")==0) ay=(int)strtol(kv[i].val,NULL,0);
    }
    char buf[400]; _snprintf(buf,sizeof buf,"game-side: %s  node+0x643=%#x  ax=%04X ay=%04X",
                             pressed[0]?pressed:"none", node643, ax, ay);
    wchar_t *w=u8tow(buf); SetWindowTextW(g_game,w); free(w);
}

static void ingest(const char *raw){
    char line[2048]; strncpy(line, raw, sizeof line -1); line[sizeof line-1]=0;
    size_t L=strlen(line); while(L&&(line[L-1]=='\n'||line[L-1]=='\r'||line[L-1]==' ')) line[--L]=0;
    if(!L) return;

    char ts[16], lvl[16], mraw[1024]; parse_line(line, ts, lvl, mraw, sizeof mraw);
    char ev[256]=""; char msg[1200]="";
    if(mraw[0]){
        KV kv[40]; int n=parse_obj(mraw, kv, 40);
        for(int i=0;i<n;i++) if(strcmp(kv[i].key,"ev")==0){ strncpy(ev,kv[i].val,255); break; }
        for(int i=0;i<n;i++){
            if(strcmp(kv[i].key,"ev")==0) continue;
            if(msg[0]) strcat_s(msg,sizeof msg,"  ");
            char kvp[300]; _snprintf(kvp,sizeof kvp,"%s=%s",kv[i].key,kv[i].val);
            strcat_s(msg,sizeof msg,kvp);
        }
    } else {
        strncpy(msg, line, sizeof msg-1);
    }
    if(!lvl[0]) strcpy(lvl,"info");
    if(!ts[0])  nowts(ts,sizeof ts);

    if(strcmp(ev,"input.state")==0 && mraw[0]) update_test_row(mraw);

    if(g_ent_n==g_ent_cap){
        g_ent_cap = g_ent_cap? g_ent_cap*2 : 4096;
        g_ent = (Entry*)realloc(g_ent, g_ent_cap*sizeof(Entry));
    }
    Entry *e=&g_ent[g_ent_n++];
    strncpy(e->ts, ts[0]?ts:" ", 15); e->ts[15]=0;
    strncpy(e->src, ev[0]?ev:lvl, 63); e->src[63]=0;
    e->lvl = level_of(lvl, ev, msg);
    e->msg = _strdup(msg);
    if(e->lvl==L_ERROR) g_errors++;

    if(g_ent_n>80000){
        size_t drop=20000; for(size_t i=0;i<drop;i++) free(g_ent[i].msg);
        memmove(g_ent, g_ent+drop, (g_ent_n-drop)*sizeof(Entry)); g_ent_n-=drop;
        view_rebuild();  /* g_view の index がずれるため作り直し */
    } else if(!g_paused && passes(e)){
        view_push(g_ent_n-1);  /* 実描画はタイマーの logview_flush でまとめて行う */
    }

    if(g_card_log && strncmp(e->src, "card", 4)==0){
        char line[1200]; fmt_entry(e, line, sizeof line);
        strcat_s(line, sizeof line, "\r\n");
        wchar_t *w=u8tow(line); re_append_colored(g_card_log, w, level_color(e->lvl)); free(w);
    }
}

static void emit(const char *ev, const char *msg, const char *lvl){
    char ts[16]; nowts(ts,sizeof ts);
    char esc[1024]; int j=0;
    for(const char *p=msg; *p && j<1020; p++){ if(*p=='"'||*p=='\\') esc[j++]='\\'; esc[j++]=*p; }
    esc[j]=0;
    char *line=(char*)malloc(1400);
    _snprintf(line,1400,"{\"ts\":\"%s\",\"lvl\":\"%s\",\"m\":{\"ev\":\"%s\",\"msg\":\"%s\"}}",
              ts, lvl, ev, esc);
    PostMessageW(g_main, WM_APP_LOGLINE, 0, (LPARAM)line);
}

static DWORD WINAPI tail_thread(LPVOID arg){
    (void)arg;
    LONGLONG pos=0; int first=1;
    /* NRS_TAIL_SKIP = spawn 元(CLI)が見ていた旧ログ。初見のファイルがそれと別なら
       既に新ランのログなので先頭から読む。同じなら旧ログの洪水を避け末尾から追従。 */
    { wchar_t skip[MAX_PATH];
      if(GetEnvironmentVariableW(L"NRS_TAIL_SKIP",skip,MAX_PATH)>0 && _wcsicmp(skip,G_LOG)!=0) first=0; }
    LONG seen_gen=g_log_gen;
    wchar_t cur[MAX_PATH]; wcscpy(cur, G_LOG);
    char carry[2048]; int carry_n=0;
    for(;;){
        LONG gen=g_log_gen;
        if(gen!=seen_gen){
            seen_gen=gen; wcscpy(cur, G_LOG);
            pos=0; carry_n=0; first=0;
            PostMessageW(g_main, WM_APP_LOGCLEAR, 0, 0);
        }
        { FILE *pf=_wfopen(G_LOGPTR, L"r");
          if(pf){ wchar_t pl[MAX_PATH];
              if(fgetws(pl,MAX_PATH,pf)){ pl[wcscspn(pl,L"\r\n")]=0;
                  if(pl[0] && _wcsicmp(pl,cur)!=0 && GetFileAttributesW(pl)!=INVALID_FILE_ATTRIBUTES){
                      wcscpy(cur,pl); pos=0; carry_n=0; first=0;
                      PostMessageW(g_main, WM_APP_LOGCLEAR, 0, 0);
                  } }
              fclose(pf); } }
        HANDLE h=CreateFileW(cur, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                             NULL, OPEN_EXISTING, 0, NULL);
        if(h!=INVALID_HANDLE_VALUE){
            LARGE_INTEGER sz; GetFileSizeEx(h,&sz);
            if(first){ pos=sz.QuadPart; first=0; }
            if(sz.QuadPart < pos){ pos=0; carry_n=0; }
            LARGE_INTEGER mv; mv.QuadPart=pos; SetFilePointerEx(h,mv,NULL,FILE_BEGIN);
            char buf[8192]; DWORD rd;
            while(ReadFile(h,buf,sizeof buf,&rd,NULL) && rd>0){
                pos += rd;
                /* 完成行をチャンク単位でまとめて 1 PostMessage。1 行=1 投函だと
                   バースト時にメッセージキュー上限(10000)を溢れて行を取りこぼす。 */
                char *batch=(char*)malloc((size_t)carry_n+rd+2); size_t bn=0;
                for(DWORD i=0;i<rd;i++){
                    char c=buf[i];
                    if(c=='\n'){
                        memcpy(batch+bn,carry,(size_t)carry_n); bn+=(size_t)carry_n;
                        batch[bn++]='\n';
                        carry_n=0;
                    } else if(carry_n<(int)sizeof carry-1){
                        carry[carry_n++]=c;
                    }
                }
                if(bn){ batch[bn]=0;
                        if(!PostMessageW(g_main, WM_APP_LOGLINE, 0, (LPARAM)batch)) free(batch); }
                else free(batch);
            }
            CloseHandle(h);
        }
        Sleep(120);
    }
    return 0;
}

static void set_status(COLORREF col, const char *u8){
    char *line=_strdup(u8);
    PostMessageW(g_main, WM_APP_STATUS, (WPARAM)col, (LPARAM)line);
}

static const char* inject(HANDLE proc, const wchar_t *dll_abspath){
    char path[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, dll_abspath, -1, path, MAX_PATH, NULL, NULL);
    SIZE_T len = strlen(path) + 1;
    void *remote = VirtualAllocEx(proc, 0, len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if(!remote) return "VirtualAllocEx 失敗";
    if(!WriteProcessMemory(proc, remote, path, len, 0)) return "WriteProcessMemory 失敗";
    FARPROC loadlib = GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA");
    HANDLE th = CreateRemoteThread(proc, 0, 0, (LPTHREAD_START_ROUTINE)loadlib, remote, 0, 0);
    if(!th) return "CreateRemoteThread 失敗";
    WaitForSingleObject(th, INFINITE);
    CloseHandle(th);
    return NULL;
}

typedef struct { int ok; DWORD pid; char err[200]; } LaunchResult;

static int proc_running(const wchar_t *name);  /* 定義は後方(1141付近) */

static void core_launch(LaunchResult *r){
    r->ok=0; r->pid=0; r->err[0]=0;
    wchar_t hostdll[MAX_PATH], logicdll[MAX_PATH];
    _snwprintf(hostdll, MAX_PATH, L"%s\\host.dll",  G_GAME_DIR); CopyFileW(G_HOST_DLL, hostdll, FALSE);
    _snwprintf(logicdll,MAX_PATH, L"%s\\logic.dll", G_GAME_DIR); CopyFileW(G_LOGIC_DLL,logicdll,FALSE);

    wchar_t ldir[MAX_PATH]; _snwprintf(ldir,MAX_PATH,L"%s\\logs",G_GAME_DIR); CreateDirectoryW(ldir,NULL);
    SYSTEMTIME t; GetLocalTime(&t);
    _snwprintf(G_LOG,MAX_PATH,L"%s\\nrsedge-%04d%02d%02d-%02d%02d%02d-%03d.log",
               ldir,t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond,t.wMilliseconds);
    SetEnvironmentVariableW(L"NRS_LOG_FILE", G_LOG);
    FILE *pf=_wfopen(G_LOGPTR,L"w"); if(pf){ fputws(G_LOG,pf); fclose(pf); }
    HANDLE h=CreateFileW(G_LOG,GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,0,NULL);
    if(h!=INVALID_HANDLE_VALUE) CloseHandle(h);
    DeleteFileW(G_STATUS);
    InterlockedIncrement(&g_log_gen);

    STARTUPINFOW si; ZeroMemory(&si,sizeof si); si.cb=sizeof si;
    PROCESS_INFORMATION pi; ZeroMemory(&pi,sizeof pi);
    if(!CreateProcessW(G_GAME_EXE, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED|CREATE_NO_WINDOW,
                       NULL, G_GAME_DIR, &si, &pi)){
        _snprintf(r->err,sizeof r->err,"CreateProcess err=%lu", GetLastError());
        return;
    }
    const char *err = inject(pi.hProcess, hostdll);
    if(err){
        _snprintf(r->err,sizeof r->err,"注入 %s", err);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return;
    }
    { HANDLE jb=g_job; int owned=0;
      if(!jb){ jb=OpenJobObjectW(JOB_OBJECT_ALL_ACCESS, FALSE, NRS_JOB_NAME); owned=1; }
      if(jb){ AssignProcessToJobObject(jb, pi.hProcess); if(owned) CloseHandle(jb); } }

    ResumeThread(pi.hThread);
    r->pid = pi.dwProcessId; r->ok = 1;
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
}

static int core_stop(void){
    STARTUPINFOW si; ZeroMemory(&si,sizeof si); si.cb=sizeof si;
    PROCESS_INFORMATION pi; ZeroMemory(&pi,sizeof pi);
    wchar_t cmd[]=L"taskkill /F /IM nrs.exe";
    DWORD code=1;
    if(CreateProcessW(NULL,cmd,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){
        WaitForSingleObject(pi.hProcess,5000); GetExitCodeProcess(pi.hProcess,&code);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    DeleteFileW(G_STATUS);
    return code==0;
}

static int run_loader(void){
    /* nrs.exe 単一化: CLI(cmd_start) と同じ run mutex で直列化し、
       既に走っていれば二重起動しない。GUI ボタンは "実行中" として扱う(return 1)。 */
    HANDLE runlock = CreateMutexW(NULL, FALSE, NRS_MUTEX_RUN);
    if(runlock) WaitForSingleObject(runlock, 10000);
    if(proc_running(L"nrs.exe")){
        if(runlock){ ReleaseMutex(runlock); CloseHandle(runlock); }
        emit("loader", "既に nrs.exe が起動中のため二重起動を抑止", "warn");
        set_status(HEXRGB(0xffb454), "既に起動済み");
        return 1;
    }
    LaunchResult r; core_launch(&r);
    if(runlock){ ReleaseMutex(runlock); CloseHandle(runlock); }
    if(!r.ok){
        char buf[260]; _snprintf(buf,sizeof buf,"起動失敗: %s", r.err);
        emit("loader", buf, "error"); set_status(HEXRGB(0xff5f5f), buf);
        return 0;
    }
    char ok[128]; _snprintf(ok,sizeof ok,"host.dll 注入完了 pid=%lu", r.pid);
    emit("loader", ok, "info");
    set_status(HEXRGB(0x7bd66b), "起動: nrs.exe + host.dll 注入");
    return 1;
}

static void do_stop(void){
    core_stop();
    set_status(HEXRGB(0xffb454),"終了: nrs.exe kill");
}

static DWORD WINAPI th_launch(LPVOID a){ (void)a; if(!run_loader()) PostMessageW(g_main, WM_APP_RUNSTATE, 0, 0); g_busy=0; return 0; }
static DWORD WINAPI th_stop(LPVOID a){ (void)a; do_stop(); g_busy=0; return 0; }

static void start_worker(LPTHREAD_START_ROUTINE fn){
    if(g_busy){ set_status(HEXRGB(0xffb454),"処理中… しばらくお待ちください"); return; }
    g_busy=1;
    HANDLE h=CreateThread(NULL,0,fn,NULL,0,NULL); if(h) CloseHandle(h);
}

static void set_run_button(int running){
    g_running = running;
    HWND b = GetDlgItem(g_main, ID_LAUNCH);
    SetWindowTextW(b, running ? L"■ 終了" : L"▶ 起動");
    InvalidateRect(b, NULL, TRUE);
}

static int key_down(int vk){ return vk && (GetAsyncKeyState(vk)&0x8000)!=0; }

static void poll_keys(void){
    if(g_capture_act>=0){
        for(int vk=0x08; vk<=0xFE; vk++){
            int down = (GetAsyncKeyState(vk)&0x8000)!=0;
            if(down && !g_prev_down[vk] && vk!=VK_LBUTTON && vk!=VK_RBUTTON){
                g_bind[g_capture_act]=vk;
                wchar_t nm[32]; vkname(vk,nm,32);
                SetWindowTextW(g_bindlbl[g_capture_act], nm);
                char buf[128]; char *nu=wtou8(nm);
                _snprintf(buf,sizeof buf,"'%s' = %s (VK 0x%02X)", ACTIONS[g_capture_act], nu, vk); free(nu);
                wchar_t *w=u8tow(buf); SetWindowTextW(g_cap,w); free(w);
                g_capture_act=-1; write_cfg();
                break;
            }
            g_prev_down[vk]=down;
        }
        return;
    }
    for(int a=0;a<NACT;a++){
        COLORREF c = key_down(g_bind[a])? HEXRGB(0x3fe06a) : HEXRGB(0x444444);
        SetWindowLongPtrW(g_bindind[a], GWLP_USERDATA, (LONG_PTR)c);
        InvalidateRect(g_bindind[a], NULL, FALSE);
    }
    int lx = key_down(g_bind[6])?0x0000 : (key_down(g_bind[7])?0xFFFF:0x8000);
    int ly = key_down(g_bind[4])?0x0000 : (key_down(g_bind[5])?0xFFFF:0x8000);
    char buf[128]; _snprintf(buf,sizeof buf,"analog X=%04X Y=%04X  (GUI 直接ポーリング・ゲーム不要)",lx,ly);
    wchar_t *w=u8tow(buf); SetWindowTextW(g_analog,w); free(w);
}

static void search_next(void){
    wchar_t t[128]; GetWindowTextW(g_search,t,128); if(!t[0] || !g_view_n) return;
    static size_t from=0;
    if(from>=g_view_n) from=0;
    char *f=wtou8(t);
    size_t hit=(size_t)-1;
    for(size_t k=0;k<g_view_n;k++){
        size_t vi=(from+k)%g_view_n;
        const Entry *e=&g_ent[g_view[vi]];
        if(has_ci(e->src,f)||has_ci(e->msg,f)){ hit=vi; break; }
    }
    free(f);
    if(hit==(size_t)-1){ SetWindowTextW(g_logstatus, L"検索: 見つかりません"); return; }
    from=hit+1;
    g_sel_a=g_sel_b=hit;
    if(g_autoscroll){ g_autoscroll=0; update_resume_btn(); }
    { size_t vis=(size_t)logview_vis();
      size_t top = hit>vis/2 ? hit-vis/2 : 0;
      size_t mt=logview_max_top(); if(top>mt) top=mt;
      g_top=top; }
    logview_update_scroll();
    InvalidateRect(g_log,NULL,FALSE);
}
static void export_jsonl(void){
    wchar_t path[MAX_PATH]=L"";
    OPENFILENAMEW ofn; ZeroMemory(&ofn,sizeof ofn); ofn.lStructSize=sizeof ofn;
    ofn.hwndOwner=g_main; ofn.lpstrFilter=L"JSON Lines\0*.jsonl\0All\0*.*\0";
    ofn.lpstrFile=path; ofn.nMaxFile=MAX_PATH; ofn.lpstrDefExt=L"jsonl";
    ofn.Flags=OFN_OVERWRITEPROMPT;
    if(!GetSaveFileNameW(&ofn)) return;
    FILE *f=_wfopen(path,L"wb"); if(!f) return;
    int cnt=0;
    for(size_t i=0;i<g_ent_n;i++){ if(!passes(&g_ent[i])) continue;
        char esc[1200]; int j=0;
        for(char *p=g_ent[i].msg; *p && j<1190; p++){ if(*p=='"'||*p=='\\') esc[j++]='\\'; esc[j++]=*p; }
        esc[j]=0;
        fprintf(f,"{\"ts\":\"%s\",\"src\":\"%s\",\"lvl\":%d,\"msg\":\"%s\"}\n",
                g_ent[i].ts, g_ent[i].src, g_ent[i].lvl, esc);
        cnt++;
    }
    fclose(f);
    char *pu=wtou8(path); char buf[MAX_PATH+64]; _snprintf(buf,sizeof buf,"書出 %d 行 -> %s",cnt,pu); free(pu);
    wchar_t *w=u8tow(buf); SetWindowTextW(g_logstatus,w); free(w);
}
static void log_clear(void){
    for(size_t i=0;i<g_ent_n;i++) free(g_ent[i].msg);
    g_ent_n=0; g_errors=0;
    g_view_n=0; g_top=0; g_hpos=0; g_maxchars=80; g_sel_a=g_sel_b=(size_t)-1; g_dirty=0;
    logview_update_scroll();
    InvalidateRect(g_log, NULL, TRUE);
    update_counts();
}

static int card_type_selected(void){
    int sel=(int)SendMessageW(g_card_type, CB_GETCURSEL, 0, 0);
    switch(sel){ case 1: return 0x36; case 2: return 0xC9; default: return 0xFF; }
}
static int card_type_capacity(int type){ return type==0x36?1984 : type==0xC9?960 : 4032; }

static void card_write_control(int present){
    g_card_gen++;
    FILE *f=_wfopen(G_CARDCTL, L"w"); if(!f) return;
    char *pu=wtou8(g_card_path); char esc[700]; int j=0;
    for(char *p=pu; *p && j<690; p++){ if(*p=='\\'||*p=='"') esc[j++]='\\'; esc[j++]=*p; }
    esc[j]=0; free(pu);
    fprintf(f, "{\"present\":%d,\"image\":\"%s\",\"type\":%d,\"gen\":%d}\n",
            present, esc, card_type_selected(), g_card_gen);
    fclose(f);
    g_card_present=present;
}

static void card_update_fields(unsigned uid, int n){
    int type=card_type_selected();
    char buf[800];
    if(g_card_path[0]){
        char *pu=wtou8(g_card_path);
        _snprintf(buf, sizeof buf,
            "パス: %s\r\nサイズ: %d B\r\nUID (@+0x04 BE): %08X\r\n種別: 0x%02X (%d B)\r\n状態: %s",
            pu, n, uid, type, card_type_capacity(type), g_card_present?"挿入中":"取出済");
        free(pu);
    } else {
        _snprintf(buf, sizeof buf, "（カード未選択）\r\n〔新規作成〕または〔読込〕でカードを用意してください。");
    }
    wchar_t *w=u8tow(buf); SetWindowTextW(g_card_fields, w); free(w);
}

static void card_render_hex(void){
    unsigned char data[CARD_IMG_BYTES]; int n=0;
    if(g_card_path[0]){
        FILE *f=_wfopen(g_card_path, L"rb");
        if(f){ n=(int)fread(data,1,sizeof data,f); fclose(f); }
    }
    if(n<=0){ SetWindowTextW(g_card_hex, L""); card_update_fields(0,0); return; }
    size_t cap=(size_t)(n/16+2)*92 + 64;
    char *t=(char*)malloc(cap); size_t o=0;
    for(int i=0;i<n;i+=16){
        o+=(size_t)_snprintf(t+o,cap-o,"%04X  ",i);
        for(int j=0;j<16;j++){
            if(i+j<n) o+=(size_t)_snprintf(t+o,cap-o,"%02X ",data[i+j]);
            else      o+=(size_t)_snprintf(t+o,cap-o,"   ");
            if(j==7 && o<cap-1) t[o++]=' ';
        }
        if(o<cap-2){ t[o++]=' '; t[o++]='|'; }
        for(int j=0;j<16 && i+j<n && o<cap-1;j++){ unsigned char ch=data[i+j]; t[o++]=(ch>=0x20&&ch<0x7f)?(char)ch:'.'; }
        o+=(size_t)_snprintf(t+o,cap-o,"|\r\n");
    }
    t[o]=0;
    wchar_t *w=u8tow(t); SetWindowTextW(g_card_hex, w); free(w); free(t);
    unsigned uid=((unsigned)data[CARD_UID_OFF]<<24)|((unsigned)data[CARD_UID_OFF+1]<<16)
               | ((unsigned)data[CARD_UID_OFF+2]<<8)|data[CARD_UID_OFF+3];
    card_update_fields(uid, n);
}

static int card_new_file(const wchar_t *path){
    unsigned char img[CARD_IMG_BYTES]; memset(img,0,sizeof img);
    srand((unsigned)time(NULL) ^ GetTickCount());
    unsigned uid=(((unsigned)rand())<<17) ^ (((unsigned)rand())<<2) ^ GetTickCount();
    img[CARD_UID_OFF+0]=(uid>>24)&0xFF; img[CARD_UID_OFF+1]=(uid>>16)&0xFF;
    img[CARD_UID_OFF+2]=(uid>>8)&0xFF;  img[CARD_UID_OFF+3]=uid&0xFF;
    FILE *f=_wfopen(path, L"wb"); if(!f) return 0;
    int n=(int)fwrite(img,1,sizeof img,f); fclose(f);
    return n==CARD_IMG_BYTES;
}

static int card_pick_file(int save, wchar_t *path){
    path[0]=0;
    OPENFILENAMEW ofn; ZeroMemory(&ofn,sizeof ofn); ofn.lStructSize=sizeof ofn;
    ofn.hwndOwner=g_main; ofn.lpstrFilter=L"カードイメージ\0*.bin\0すべて\0*.*\0";
    ofn.lpstrFile=path; ofn.nMaxFile=MAX_PATH; ofn.lpstrDefExt=L"bin";
    ofn.lpstrInitialDir=G_CARDS_DIR;
    ofn.Flags = save ? OFN_OVERWRITEPROMPT : (OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST);
    return save ? GetSaveFileNameW(&ofn) : GetOpenFileNameW(&ofn);
}

static HWND mk(const wchar_t *cls, const wchar_t *txt, DWORD style, int id, HFONT font){
    HWND h=CreateWindowExW(0, cls, txt, WS_CHILD|WS_VISIBLE|style, 0,0,10,10,
                           g_main, (HMENU)(INT_PTR)id, GetModuleHandleW(NULL), NULL);
    SendMessageW(h, WM_SETFONT, (WPARAM)font, TRUE);
    return h;
}

static void build_ui(void){
    mk(L"BUTTON", L"▶ 起動", BS_OWNERDRAW, ID_LAUNCH, g_fontUI);
    HWND c;
    c=mk(L"BUTTON",L"FreePlay",     BS_AUTOCHECKBOX, ID_FREEPLAY, g_fontUI); SendMessageW(c,BM_SETCHECK,g_freeplay?BST_CHECKED:BST_UNCHECKED,0);
    c=mk(L"BUTTON",L"TEST モード",BS_AUTOCHECKBOX, ID_TEST, g_fontUI);     SendMessageW(c,BM_SETCHECK,g_test?BST_CHECKED:BST_UNCHECKED,0);
    g_status = mk(L"STATIC", L"待機中", SS_RIGHT, ID_STATUS, g_fontUI);
    g_status_color = C_ACC;

    g_tab = mk(WC_TABCONTROLW, L"", 0, ID_TAB, g_fontUI);
    TCITEMW ti; ti.mask=TCIF_TEXT;
    ti.pszText=(LPWSTR)L"ログ";              SendMessageW(g_tab, TCM_INSERTITEMW, 0, (LPARAM)&ti);
    ti.pszText=(LPWSTR)L"入力設定"; SendMessageW(g_tab, TCM_INSERTITEMW, 1, (LPARAM)&ti);
    ti.pszText=(LPWSTR)L"カード";        SendMessageW(g_tab, TCM_INSERTITEMW, 2, (LPARAM)&ti);

    mk(L"STATIC", L"Filter:", SS_RIGHT, ID_LBL_FILTER, g_fontUI);
    g_filter = mk(L"EDIT", L"", WS_BORDER|ES_AUTOHSCROLL, ID_FILTER, g_fontUI);
    mk(L"BUTTON", L"I/O 抑制", BS_AUTOCHECKBOX, ID_HIDEIO, g_fontUI);
    mk(L"BUTTON", L"エラーのみ", BS_AUTOCHECKBOX, ID_ERRONLY, g_fontUI);
    mk(L"STATIC", L"検索:", SS_RIGHT, ID_LBL_SEARCH, g_fontUI);
    g_search = mk(L"EDIT", L"", WS_BORDER|ES_AUTOHSCROLL, ID_SEARCH, g_fontUI);
    mk(L"BUTTON", L"次へ", BS_PUSHBUTTON, ID_SEARCHNEXT, g_fontUI);
    mk(L"BUTTON", L"一時停止", BS_AUTOCHECKBOX, ID_PAUSE, g_fontUI);
    mk(L"BUTTON", L"クリア", BS_PUSHBUTTON, ID_CLEAR, g_fontUI);
    mk(L"BUTTON", L"JSONL書出", BS_PUSHBUTTON, ID_EXPORT, g_fontUI);

    /* 仮想ログビュー（折返し無効: 1 エントリ=1 行、横スクロールあり） */
    g_log = CreateWindowExW(0, L"nrsLogView", L"",
        WS_CHILD|WS_VISIBLE|WS_VSCROLL|WS_HSCROLL,
        0,0,10,10, g_main, (HMENU)ID_LOG, GetModuleHandleW(NULL), NULL);
    { HDC dc=GetDC(g_log); HFONT of=(HFONT)SelectObject(dc,g_font);
      TEXTMETRICW tm; if(GetTextMetricsW(dc,&tm)) g_lineh=tm.tmHeight+1;
      SIZE sz; if(GetTextExtentPoint32W(dc,L"0",1,&sz)&&sz.cx) g_charw=sz.cx;
      SelectObject(dc,of); ReleaseDC(g_log,dc); }
    g_logstatus = mk(L"STATIC", L"", SS_LEFT, ID_LOGSTATUS, g_fontUI);
    g_resume = CreateWindowExW(WS_EX_TOOLWINDOW|WS_EX_NOACTIVATE, L"nrsResume", L"",
        WS_POPUP, 0,0,200,24, g_main, NULL, GetModuleHandleW(NULL), NULL);

    mk(L"STATIC",
       L"キーバインド（「変更」を押して新しいキーを押下）／ ライブ入力テスト（点灯=押下中）",
       SS_LEFT, ID_INPUT_HELP, g_fontUI);
    for(int i=0;i<NACT;i++){
        wchar_t *aw=u8tow(ACTIONS[i]);
        mk(L"STATIC", aw, SS_LEFT, 700+i, g_font);  free(aw);
        wchar_t nm[32]; vkname(g_bind[i],nm,32);
        g_bindlbl[i]=mk(L"STATIC", nm, SS_CENTER, ID_BIND_LBL+i, g_font);
        mk(L"BUTTON", L"変更", BS_PUSHBUTTON, ID_BIND_BTN+i, g_fontUI);
        g_bindind[i]=mk(L"STATIC", L"●", SS_CENTER|SS_NOTIFY, ID_BIND_IND+i, g_font);
        SetWindowLongPtrW(g_bindind[i], GWLP_USERDATA, (LONG_PTR)HEXRGB(0x444444));
    }
    g_analog=mk(L"STATIC", L"analog X=8000 Y=8000", SS_LEFT, ID_ANALOG, g_font);
    g_game  =mk(L"STATIC", L"game-side: (nrs.exe 起動時にゲームが受け取った入力)", SS_LEFT, ID_GAME, g_font);
    mk(L"BUTTON", L"保存（nrsedge.cfg）", BS_OWNERDRAW, ID_SAVE, g_fontUI);
    g_cap   =mk(L"STATIC", L"", SS_LEFT, ID_CAP, g_fontUI);

    mk(L"STATIC", L"カードの抜き差し・新規作成・保存・データ可視化・カードログ抽出", SS_LEFT, ID_CARD_HELP, g_fontUI);
    mk(L"BUTTON", L"新規作成", BS_PUSHBUTTON, ID_CARD_NEW, g_fontUI);
    mk(L"BUTTON", L"読込",     BS_PUSHBUTTON, ID_CARD_LOAD, g_fontUI);
    g_card_type = mk(L"COMBOBOX", L"", CBS_DROPDOWNLIST|WS_VSCROLL, ID_CARD_TYPE, g_fontUI);
    SendMessageW(g_card_type, CB_ADDSTRING, 0, (LPARAM)L"4032B (0xFF)");
    SendMessageW(g_card_type, CB_ADDSTRING, 0, (LPARAM)L"1984B (0x36)");
    SendMessageW(g_card_type, CB_ADDSTRING, 0, (LPARAM)L"960B (0xC9)");
    SendMessageW(g_card_type, CB_SETCURSEL, 0, 0);
    mk(L"BUTTON", L"挿入",     BS_PUSHBUTTON, ID_CARD_INSERT, g_fontUI);
    mk(L"BUTTON", L"取り出し", BS_PUSHBUTTON, ID_CARD_EJECT, g_fontUI);
    mk(L"BUTTON", L"別名保存", BS_PUSHBUTTON, ID_CARD_SAVEAS, g_fontUI);
    mk(L"BUTTON", L"更新",     BS_PUSHBUTTON, ID_CARD_REFRESH, g_fontUI);
    g_card_fields = mk(L"STATIC", L"（カード未選択）", SS_LEFT, ID_CARD_FIELDS, g_font);

    g_card_hex = CreateWindowExW(0, MSFTEDIT_CLASS, L"",
        WS_CHILD|WS_VISIBLE|WS_CLIPSIBLINGS|WS_VSCROLL|WS_HSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
        0,0,10,10, g_main, (HMENU)ID_CARD_HEX, GetModuleHandleW(NULL), NULL);
    SendMessageW(g_card_hex, WM_SETFONT, (WPARAM)g_font, TRUE);
    SendMessageW(g_card_hex, EM_SETBKGNDCOLOR, 0, (LPARAM)C_BG);
    SendMessageW(g_card_hex, EM_EXLIMITTEXT, 0, (LPARAM)0x7FFFFFFF);
    { CHARFORMAT2W cf; ZeroMemory(&cf,sizeof cf); cf.cbSize=sizeof cf; cf.dwMask=CFM_COLOR; cf.crTextColor=C_FG;
      SendMessageW(g_card_hex, EM_SETCHARFORMAT, SCF_DEFAULT, (LPARAM)&cf); }

    g_card_log = CreateWindowExW(0, MSFTEDIT_CLASS, L"",
        WS_CHILD|WS_VISIBLE|WS_CLIPSIBLINGS|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
        0,0,10,10, g_main, (HMENU)ID_CARD_LOG, GetModuleHandleW(NULL), NULL);
    SendMessageW(g_card_log, WM_SETFONT, (WPARAM)g_font, TRUE);
    SendMessageW(g_card_log, EM_SETBKGNDCOLOR, 0, (LPARAM)C_BG);
    SendMessageW(g_card_log, EM_EXLIMITTEXT, 0, (LPARAM)0x7FFFFFFF);
}

static RECT tab_display(void){
    RECT rc; GetClientRect(g_tab,&rc); TabCtrl_AdjustRect(g_tab,FALSE,&rc);
    POINT tl={rc.left,rc.top}, br={rc.right,rc.bottom};
    ClientToScreen(g_tab,&tl); ClientToScreen(g_tab,&br);
    ScreenToClient(g_main,&tl); ScreenToClient(g_main,&br);
    RECT r={tl.x,tl.y,br.x,br.y}; return r;
}
static void mv(int id,int x,int y,int w,int h){ MoveWindow(GetDlgItem(g_main,id),x,y,w,h,TRUE); }

static void update_resume_btn(void){
    int show = (TabCtrl_GetCurSel(g_tab)==0 && !g_autoscroll);
    if(show){ position_resume(); ShowWindow(g_resume, SW_SHOWNOACTIVATE); }
    else ShowWindow(g_resume, SW_HIDE);
}

static void show_page(int page){
    int log_ids[]={ID_LBL_FILTER,ID_FILTER,ID_HIDEIO,ID_ERRONLY,ID_LBL_SEARCH,ID_SEARCH,
                   ID_SEARCHNEXT,ID_PAUSE,ID_CLEAR,ID_EXPORT,ID_LOG,ID_LOGSTATUS};
    for(int i=0;i<(int)(sizeof log_ids/sizeof*log_ids);i++)
        ShowWindow(GetDlgItem(g_main,log_ids[i]), page==0?SW_SHOW:SW_HIDE);
    update_resume_btn();
    ShowWindow(GetDlgItem(g_main,ID_INPUT_HELP), page==1?SW_SHOW:SW_HIDE);
    ShowWindow(g_analog,page==1?SW_SHOW:SW_HIDE);
    ShowWindow(g_game,page==1?SW_SHOW:SW_HIDE);
    ShowWindow(g_cap,page==1?SW_SHOW:SW_HIDE);
    ShowWindow(GetDlgItem(g_main,ID_SAVE),page==1?SW_SHOW:SW_HIDE);
    for(int i=0;i<NACT;i++){
        ShowWindow(GetDlgItem(g_main,700+i),page==1?SW_SHOW:SW_HIDE);
        ShowWindow(g_bindlbl[i],page==1?SW_SHOW:SW_HIDE);
        ShowWindow(GetDlgItem(g_main,ID_BIND_BTN+i),page==1?SW_SHOW:SW_HIDE);
        ShowWindow(g_bindind[i],page==1?SW_SHOW:SW_HIDE);
    }
    int card_ids[]={ID_CARD_HELP,ID_CARD_NEW,ID_CARD_LOAD,ID_CARD_TYPE,ID_CARD_INSERT,
                    ID_CARD_EJECT,ID_CARD_SAVEAS,ID_CARD_REFRESH,ID_CARD_FIELDS,ID_CARD_HEX,ID_CARD_LOG};
    for(int i=0;i<(int)(sizeof card_ids/sizeof*card_ids);i++)
        ShowWindow(GetDlgItem(g_main,card_ids[i]), page==2?SW_SHOW:SW_HIDE);
}

static void layout(void){
    RECT rc; GetClientRect(g_main,&rc);
    int W=rc.right;
    int x=8,y=8,bh=26;
    mv(ID_LAUNCH,x,y,80,bh); x+=92;
    mv(ID_FREEPLAY,x,y,86,bh); x+=92; mv(ID_TEST,x,y,100,bh); x+=104;
    mv(ID_STATUS, x, y+4, W-x-12, 18);
    MoveWindow(g_tab,4,44,W-8,rc.bottom-48,TRUE);
    RECT p=tab_display();
    int lx=p.left+4, ly=p.top+4;
    mv(ID_LBL_FILTER,lx,ly+4,46,18); lx+=50; mv(ID_FILTER,lx,ly,150,22); lx+=158;
    mv(ID_HIDEIO,lx,ly,80,22); lx+=84; mv(ID_ERRONLY,lx,ly,90,22); lx+=98;
    mv(ID_LBL_SEARCH,lx,ly+4,40,18); lx+=42; mv(ID_SEARCH,lx,ly,110,22); lx+=116;
    mv(ID_SEARCHNEXT,lx,ly,48,22); lx+=54;
    mv(ID_PAUSE,lx,ly,80,22); lx+=84; mv(ID_CLEAR,lx,ly,60,22); lx+=66; mv(ID_EXPORT,lx,ly,86,22);
    int top2=ly+30;
    int lw=(p.right-p.left)-8, lh=(p.bottom-top2)-26;
    MoveWindow(g_log, p.left+4, top2, lw, lh, TRUE);
    mv(ID_LOGSTATUS, p.left+4, p.bottom-22, (p.right-p.left)-8, 20);
    update_resume_btn();
    mv(ID_INPUT_HELP, p.left+10, p.top+8, (p.right-p.left)-20, 20);
    int gy=p.top+38;
    for(int i=0;i<NACT;i++){
        int row=gy+i*28;
        mv(700+i, p.left+12, row, 90, 22);
        MoveWindow(g_bindlbl[i], p.left+108, row, 80, 22, TRUE);
        mv(ID_BIND_BTN+i, p.left+196, row, 50, 22);
        MoveWindow(g_bindind[i], p.left+260, row, 40, 22, TRUE);
    }
    int by=gy+NACT*28+8;
    MoveWindow(g_analog, p.left+12, by, (p.right-p.left)-24, 20, TRUE); by+=24;
    MoveWindow(g_game,   p.left+12, by, (p.right-p.left)-24, 20, TRUE); by+=26;
    mv(ID_SAVE, p.left+12, by, 180, 26); by+=30;
    MoveWindow(g_cap,    p.left+12, by, (p.right-p.left)-24, 20, TRUE);

    int cw=(p.right-p.left);
    int cx=p.left+6, cy=p.top+6;
    mv(ID_CARD_HELP, cx, cy, cw-12, 18); cy+=24;
    mv(ID_CARD_NEW,    cx, cy, 80, 24); cx+=86;
    mv(ID_CARD_LOAD,   cx, cy, 60, 24); cx+=66;
    mv(ID_CARD_TYPE,   cx, cy, 120,200); cx+=128;
    mv(ID_CARD_INSERT, cx, cy, 60, 24); cx+=66;
    mv(ID_CARD_EJECT,  cx, cy, 76, 24); cx+=82;
    mv(ID_CARD_SAVEAS, cx, cy, 76, 24); cx+=82;
    mv(ID_CARD_REFRESH,cx, cy, 60, 24);
    cy+=32;
    mv(ID_CARD_FIELDS, p.left+6, cy, cw-12, 80); cy+=86;
    int half=(cw-18)/2;
    int ch2=(p.bottom-cy)-6;
    MoveWindow(g_card_hex, p.left+6,         cy, half, ch2, TRUE);
    MoveWindow(g_card_log, p.left+6+half+6,  cy, half, ch2, TRUE);
}

static void draw_owner_button(LPDRAWITEMSTRUCT d){
    COLORREF bg, fg;
    switch(d->CtlID){
        case ID_LAUNCH: if(g_running){ bg=HEXRGB(0xdd5555); fg=RGB(255,255,255); }
                        else        { bg=HEXRGB(0x22dd66); fg=RGB(0,0,0);       }
                        break;
        case ID_SAVE:   bg=HEXRGB(0x22dd66); fg=RGB(0,0,0); break;
        default:        bg=C_BG2; fg=C_FG; break;
    }
    if(d->itemState & ODS_SELECTED) bg=RGB(GetRValue(bg)*3/4,GetGValue(bg)*3/4,GetBValue(bg)*3/4);
    HBRUSH br=CreateSolidBrush(bg); FillRect(d->hDC,&d->rcItem,br); DeleteObject(br);
    wchar_t txt[64]; GetWindowTextW(d->hwndItem,txt,64);
    SetBkMode(d->hDC,TRANSPARENT); SetTextColor(d->hDC,fg);
    HFONT of=(HFONT)SelectObject(d->hDC,g_fontUI);
    DrawTextW(d->hDC,txt,-1,&d->rcItem,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    SelectObject(d->hDC,of);
}

static LRESULT CALLBACK WndProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp){
    switch(msg){
    case WM_CREATE:
        return 0;
    case WM_SIZE: layout(); return 0;
    case WM_MOVE: if(IsWindowVisible(g_resume)) position_resume(); return 0;

    case WM_CTLCOLORSTATIC: {
        HDC dc=(HDC)wp; HWND c=(HWND)lp; int id=GetDlgCtrlID(c);
        SetBkColor(dc, C_BG2);
        COLORREF fg=C_FG;
        if(id==ID_STATUS) fg=g_status_color;
        else if(id==ID_LOGSTATUS) fg=C_FG;
        else if(id==ID_INPUT_HELP) fg=C_ACC;
        else if(id==ID_ANALOG) fg=HEXRGB(0x5fb0ff);
        else if(id==ID_GAME)   fg=HEXRGB(0x7bd66b);
        else if(id==ID_CAP)    fg=HEXRGB(0xffff99);
        else if(id>=ID_BIND_LBL && id<ID_BIND_LBL+NACT) fg=HEXRGB(0xffd24a);
        else if(id>=ID_BIND_IND && id<ID_BIND_IND+NACT){ fg=(COLORREF)GetWindowLongPtrW(c,GWLP_USERDATA); }
        SetTextColor(dc, fg);
        return (LRESULT)g_brBG2;
    }
    case WM_CTLCOLOREDIT: {
        HDC dc=(HDC)wp; SetBkColor(dc,C_BG); SetTextColor(dc,C_FG); return (LRESULT)g_brBG;
    }
    case WM_CTLCOLORBTN: {
        HDC dc=(HDC)wp; SetBkColor(dc,C_BG2); SetTextColor(dc,C_FG); return (LRESULT)g_brBG2;
    }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT d=(LPDRAWITEMSTRUCT)lp;
        if(d->CtlType==ODT_BUTTON){ draw_owner_button(d); return TRUE; }
        break;
    }

    case WM_NOTIFY: {
        LPNMHDR nh=(LPNMHDR)lp;
        if(nh->idFrom==ID_TAB && nh->code==TCN_SELCHANGE){
            show_page(TabCtrl_GetCurSel(g_tab)); layout();
        }
        return 0;
    }

    case WM_COMMAND: {
        int id=LOWORD(wp), code=HIWORD(wp);
        if(id==ID_LAUNCH){
            if(g_busy){ set_status(HEXRGB(0xffb454),"処理中… しばらくお待ちください"); return 0; }
            if(!g_running){
                write_cfg(); set_status(C_ACC,"起動中…");
                set_run_button(1);
                start_worker(th_launch);
            } else {
                set_status(C_ACC,"終了中…");
                set_run_button(0);
                start_worker(th_stop);
            }
        }
        else if(id==ID_FREEPLAY){ g_freeplay=SendMessageW((HWND)lp,BM_GETCHECK,0,0)==BST_CHECKED; write_cfg(); }
        else if(id==ID_TEST){ g_test=SendMessageW((HWND)lp,BM_GETCHECK,0,0)==BST_CHECKED; write_cfg(); }
        else if(id==ID_FILTER && code==EN_CHANGE){
            wchar_t fw[128]; GetWindowTextW(g_filter, fw, 128);
            char *f=wtou8(fw); strncpy(g_flt, f, sizeof g_flt-1); g_flt[sizeof g_flt-1]=0; free(f);
            view_rebuild();
        }
        else if(id==ID_HIDEIO || id==ID_ERRONLY){
            g_hideio = SendMessageW(GetDlgItem(g_main,ID_HIDEIO), BM_GETCHECK,0,0)==BST_CHECKED;
            g_erronly= SendMessageW(GetDlgItem(g_main,ID_ERRONLY),BM_GETCHECK,0,0)==BST_CHECKED;
            view_rebuild();
        }
        else if(id==ID_SEARCHNEXT){ search_next(); }
        else if(id==ID_PAUSE){ g_paused=SendMessageW((HWND)lp,BM_GETCHECK,0,0)==BST_CHECKED; if(!g_paused) view_rebuild(); }
        else if(id==ID_CLEAR){ log_clear(); }
        else if(id==ID_EXPORT){ export_jsonl(); }
        else if(id==ID_SAVE){ write_cfg(); SetWindowTextW(g_cap, L"保存しました（再起動で反映）"); }
        else if(id==ID_CARD_NEW){
            CreateDirectoryW(G_CARDS_DIR, NULL);
            wchar_t path[MAX_PATH];
            if(card_pick_file(1, path) && card_new_file(path)){
                wcsncpy(g_card_path, path, MAX_PATH-1); g_card_path[MAX_PATH-1]=0;
                card_render_hex();
                emit("card.new", "new card created", "info");
            }
        }
        else if(id==ID_CARD_LOAD){
            wchar_t path[MAX_PATH];
            if(card_pick_file(0, path)){
                wcsncpy(g_card_path, path, MAX_PATH-1); g_card_path[MAX_PATH-1]=0;
                card_render_hex();
                if(g_card_present) card_write_control(1);
            }
        }
        else if(id==ID_CARD_INSERT){
            if(!g_card_path[0]){ emit("card.insert", "no active card (新規作成/読込してください)", "warn"); }
            else { card_write_control(1); card_update_fields(0,CARD_IMG_BYTES); card_render_hex(); }
        }
        else if(id==ID_CARD_EJECT){
            card_write_control(0); card_render_hex();
        }
        else if(id==ID_CARD_SAVEAS){
            if(!g_card_path[0]){ emit("card.saveas", "no active card", "warn"); }
            else { wchar_t path[MAX_PATH];
                if(card_pick_file(1, path)) CopyFileW(g_card_path, path, FALSE); }
        }
        else if(id==ID_CARD_REFRESH){ card_render_hex(); }
        else if(id>=ID_BIND_BTN && id<ID_BIND_BTN+NACT){
            g_capture_act=id-ID_BIND_BTN;
            for(int vk=0;vk<256;vk++) g_prev_down[vk]=(GetAsyncKeyState(vk)&0x8000)!=0;
            char buf[128]; _snprintf(buf,sizeof buf,"'%s' の新キーを押してください…",ACTIONS[g_capture_act]);
            wchar_t *w=u8tow(buf); SetWindowTextW(g_cap,w); free(w);
        }
        return 0;
    }

    case WM_APP_LOGLINE: {
        char *batch=(char*)lp;
        if(batch){
            char *p=batch;
            while(*p){
                char *nl=strchr(p,'\n');
                if(nl) *nl=0;
                ingest(p);
                if(!nl) break;
                p=nl+1;
            }
            free(batch);
            /* フラッド中は WM_TIMER(最低優先度)が届かないため、ここでも間引いて flush */
            { static DWORD last; DWORD now=GetTickCount();
              if(now-last>50){ last=now; logview_flush(); } }
        }
        return 0;
    }
    case WM_APP_RUNSTATE:
        set_run_button((int)wp);
        return 0;
    case WM_APP_LOGCLEAR:
        log_clear();
        return 0;
    case WM_APP_STATUS: {
        g_status_color=(COLORREF)wp; char *t=(char*)lp;
        if(t){ wchar_t *w=u8tow(t); SetWindowTextW(g_status,w); free(w); free(t); }
        InvalidateRect(g_status,NULL,TRUE);
        return 0;
    }

    case WM_TIMER:
        if(wp==1){ poll_keys(); logview_flush(); }
        return 0;

    case WM_DESTROY:
        core_stop();
        PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hw,msg,wp,lp);
}

static HANDLE g_out = NULL;
static void out_setup(void){
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if(h && h!=INVALID_HANDLE_VALUE){ g_out=h; return; }
    if(AttachConsole(ATTACH_PARENT_PROCESS)){
        h = GetStdHandle(STD_OUTPUT_HANDLE);
        if(h && h!=INVALID_HANDLE_VALUE){ g_out=h; return; }
        g_out = CreateFileW(L"CONOUT$", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    }
}
static void out(const char *s){
    if(!g_out || g_out==INVALID_HANDLE_VALUE) return;
    DWORD w; WriteFile(g_out, s, (DWORD)strlen(s), &w, NULL);
}
static void outf(const char *fmt, ...){
    char b[2048]; va_list ap; va_start(ap,fmt); _vsnprintf(b,sizeof b,fmt,ap); va_end(ap); out(b);
}

static const char* arg_val(int argc, char **argv, const char *key){
    size_t kl=strlen(key);
    for(int i=1;i<argc;i++){
        if(strncmp(argv[i],key,kl)!=0) continue;
        if(argv[i][kl]=='=') return argv[i]+kl+1;
        if(argv[i][kl]!=0) continue;
        if(i+1<argc && argv[i+1][0]!='-') return argv[i+1];
        return "";
    }
    return NULL;
}

static int sj_str(const char *j, const char *key, char *out_, int cap){
    char needle[64]; _snprintf(needle,sizeof needle,"\"%s\":\"",key);
    const char *p=strstr(j,needle); if(!p) return 0; p+=strlen(needle);
    int i=0; while(*p && *p!='"' && i<cap-1){ if(*p=='\\'&&p[1]) p++; out_[i++]=*p++; } out_[i]=0; return 1;
}

static char* read_all(const wchar_t *path){
    FILE *f=_wfopen(path,L"rb"); if(!f) return NULL;
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    if(n<0){ fclose(f); return NULL; }
    char *b=(char*)malloc((size_t)n+1); if(!b){ fclose(f); return NULL; }
    size_t rd=fread(b,1,(size_t)n,f); b[rd]=0; fclose(f); return b;
}

static int proc_running(const wchar_t *name){
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snap==INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe; pe.dwSize=sizeof pe; int found=0;
    if(Process32FirstW(snap,&pe)){
        do { if(_wcsicmp(pe.szExeFile,name)==0){ found=1; break; } } while(Process32NextW(snap,&pe));
    }
    CloseHandle(snap); return found;
}

static int read_phase(char *phase, int cap, char **out_json){
    char *j=read_all(G_STATUS); if(out_json) *out_json=j;
    if(!j){ phase[0]=0; return 0; }
    if(!sj_str(j,"phase",phase,cap)) phase[0]=0;
    if(!out_json) free(j);
    return 1;
}
static void print_status_json(void){
    char *j=read_all(G_STATUS);
    if(j){ out(j); size_t n=strlen(j); if(n && j[n-1]!='\n') out("\n"); free(j); }
    else  outf("{\"phase\":\"none\",\"running\":%s}\n", proc_running(L"nrs.exe")?"true":"false");
}

static Level cat_from_str(const char *c){
    if(!strcmp(c,"error")) return L_ERROR;
    if(!strcmp(c,"warn"))  return L_WARN;
    if(!strcmp(c,"io"))    return L_IO;
    if(!strcmp(c,"pcpa")||!strcmp(c,"keychip")) return L_PCPA;
    if(!strcmp(c,"dev"))   return L_DEV;
    if(!strcmp(c,"setup")) return L_SETUP;
    if(!strcmp(c,"info"))  return L_INFO;
    return (Level)-1;
}
static const char* subsys_of(const char *ev){
    if(!strncmp(ev,"jvs",3)) return "jvs";
    if(!strncmp(ev,"keychip",7)||!strncmp(ev,"pcp",3)) return "keychip";
    if(!strncmp(ev,"touch",5)) return "touch";
    if(!strncmp(ev,"eeprom",6)) return "eeprom";
    if(!strncmp(ev,"dipsw",5)) return "dipsw";
    if(!strncmp(ev,"mxnetwork",9)||!strncmp(ev,"net",3)) return "network";
    if(!strncmp(ev,"card",4)) return "card";
    if(!strncmp(ev,"mxdev",5)||!strncmp(ev,"columba",7)) return "mxdev";
    if(!strncmp(ev,"host",4)||!strncmp(ev,"hooks",5)||!strncmp(ev,"logic",5)
       ||!strncmp(ev,"gamehooks",9)||!strncmp(ev,"patches",7)||!strncmp(ev,"reload",6)) return "host";
    return "other";
}

/* 窓を Z オーダー最前面へ浮上させる（フォアグラウンド奪取＝アクティブ化はしない。
   SWP_NOACTIVATE 付きなので、背景プロセスから起動しても Windows のフォアグラウンド制限に
   引っかからず Z オーダーだけ上げられる＝ユーザーのフォーカスは奪わない）。 */
static void gui_raise(HWND hw){
    if(!hw) return;
    if(IsIconic(hw)) ShowWindow(hw, SW_RESTORE);
    SetWindowPos(hw, HWND_TOPMOST,   0,0,0,0, SWP_NOMOVE|SWP_NOSIZE|SWP_NOACTIVATE);
    SetWindowPos(hw, HWND_NOTOPMOST, 0,0,0,0, SWP_NOMOVE|SWP_NOSIZE|SWP_NOACTIVATE);
}

static void cli_ensure_gui(int raise){
    HWND hw = FindWindowW(L"nrsEdgePanel", NULL);
    if(hw){
        if(IsIconic(hw)) ShowWindow(hw, SW_RESTORE);
        if(raise) gui_raise(hw);
        return;
    }
    wchar_t exe[MAX_PATH]; GetModuleFileNameW(NULL, exe, MAX_PATH);
    SetEnvironmentVariableW(L"NRS_TAIL_SKIP", G_LOG);
    STARTUPINFOW si; ZeroMemory(&si,sizeof si); si.cb=sizeof si;
    PROCESS_INFORMATION pi; ZeroMemory(&pi,sizeof pi);
    DWORD flags = DETACHED_PROCESS | CREATE_BREAKAWAY_FROM_JOB;
    BOOL ok = CreateProcessW(exe, NULL, NULL, NULL, FALSE, flags, NULL, NULL, &si, &pi);
    if(!ok) ok = CreateProcessW(exe, NULL, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &si, &pi);
    if(ok){
        /* 新規 spawn した GUI は、背景プロセス(loader CLI)が生成主なので Windows の
           フォアグラウンド制限でアクティブ化されず裏に開く。窓が出るまで待って必ず浮上させる。
           窓生成完了まで待つことで cmd_start の二重 spawn レース(既存窓未生成のまま再 spawn)も
           解消される（後続 cli_ensure_gui の FindWindow が確実にヒットする）。 */
        WaitForInputIdle(pi.hProcess, 3000);
        for(int i=0; i<40 && !(hw=FindWindowW(L"nrsEdgePanel",NULL)); i++) Sleep(50);
        gui_raise(hw);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    SetEnvironmentVariableW(L"NRS_TAIL_SKIP", NULL);
}

static int wait_for_job(DWORD ms){
    DWORD t0=GetTickCount();
    for(;;){
        HANDLE j=OpenJobObjectW(JOB_OBJECT_QUERY, FALSE, NRS_JOB_NAME);
        if(j){ CloseHandle(j); return 1; }
        if(GetTickCount()-t0 > ms) return 0;
        Sleep(50);
    }
}

static int cmd_start(int argc, char **argv){
    const char *gd=arg_val(argc,argv,"--game-dir");
    if(gd && gd[0]){ wchar_t *w=u8tow(gd); SetEnvironmentVariableW(L"NRS_GAME_DIR",w); free(w); resolve_paths(); }
    const char *fp=arg_val(argc,argv,"--freeplay"); if(fp&&fp[0]) g_freeplay=atoi(fp);
    const char *tm=arg_val(argc,argv,"--test");     if(tm&&tm[0]) g_test=atoi(tm);
    write_cfg();

    HANDLE runlock = CreateMutexW(NULL, FALSE, NRS_MUTEX_RUN);
    if(runlock) WaitForSingleObject(runlock, 10000);

    if(proc_running(L"nrs.exe")){
        if(runlock){ ReleaseMutex(runlock); CloseHandle(runlock); }
        cli_ensure_gui(1); outf("{\"result\":\"already_running\"}\n"); return 0;
    }

    cli_ensure_gui(1);
    wait_for_job(3000);

    LaunchResult r; core_launch(&r);
    if(runlock){ ReleaseMutex(runlock); CloseHandle(runlock); }
    if(!r.ok){ outf("{\"result\":\"launch_failed\",\"error\":\"%s\"}\n", r.err); return 3; }

    const char *wv=arg_val(argc,argv,"--wait");
    if(!wv){ outf("{\"result\":\"started\",\"pid\":%lu}\n", r.pid); return 0; }
    int secs = wv[0]? atoi(wv) : 60; if(secs<=0) secs=60;

    DWORD t0=GetTickCount();
    for(;;){
        Sleep(200);
        char phase[16]=""; read_phase(phase,sizeof phase,NULL);
        if(!strcmp(phase,"ready"))  { print_status_json(); return 0; }
        if(!strcmp(phase,"exited")||!strcmp(phase,"error")){ print_status_json(); return 4; }
        if(!proc_running(L"nrs.exe")){ print_status_json(); return 4; }
        if((GetTickCount()-t0) > (DWORD)secs*1000){ print_status_json(); return 2; }
    }
}

static int cmd_stop(int argc, char **argv){ (void)argc;(void)argv;
    int killed=core_stop();
    outf("{\"result\":\"%s\"}\n", killed?"stopped":"not_running");
    return 0;
}

static int cmd_status(int argc, char **argv){ (void)argc;(void)argv;
    int running=proc_running(L"nrs.exe");
    char phase[16]=""; char *j=NULL; int have=read_phase(phase,sizeof phase,&j);
    if(have && j){ out(j); size_t n=strlen(j); if(n&&j[n-1]!='\n') out("\n"); free(j); }
    else outf("{\"phase\":\"none\",\"running\":%s}\n", running?"true":"false");
    if(!running) return 6;
    if(!strcmp(phase,"ready")) return 0;
    return 5;
}

static int cmd_wait(int argc, char **argv){
    const char *ev=arg_val(argc,argv,"--event");
    if(!ev||!ev[0]){ outf("{\"error\":\"--event required\"}\n"); return 1; }
    const char *tv=arg_val(argc,argv,"--timeout"); int secs=tv&&tv[0]?atoi(tv):60; if(secs<=0)secs=60;
    char needle[128]; _snprintf(needle,sizeof needle,"\"ev\":\"%s\"", ev);
    DWORD t0=GetTickCount();
    for(;;){
        char *j=read_all(G_LOG);
        if(j){ char *hit=strstr(j,needle); free(j); if(hit){ outf("{\"result\":\"found\",\"ev\":\"%s\"}\n",ev); return 0; } }
        if((GetTickCount()-t0) > (DWORD)secs*1000){ outf("{\"result\":\"timeout\",\"ev\":\"%s\"}\n",ev); return 1; }
        Sleep(200);
    }
}

static int cmd_logs(int argc, char **argv){
    const char *tv=arg_val(argc,argv,"--tail");   int tail = tv&&tv[0]?atoi(tv):0;
    const char *sv=arg_val(argc,argv,"--subsys");
    const char *cv=arg_val(argc,argv,"--cat");     Level catL = cv? cat_from_str(cv) : (Level)-1;
    const char *gv=arg_val(argc,argv,"--grep");
    char *j=read_all(G_LOG); if(!j){ outf("{\"error\":\"no log at %ls\"}\n", G_LOG); return 0; }

    char **lines=NULL; int n=0, cap=0;
    char *save=NULL, *ln=strtok_s(j,"\n",&save);
    for(; ln; ln=strtok_s(NULL,"\n",&save)){
        char ts[16],lvl[16],mraw[1024]; parse_line(ln,ts,lvl,mraw,sizeof mraw);
        char ev[256]="", msg[1200]="";
        if(mraw[0]){
            KV kv[40]; int k=parse_obj(mraw,kv,40);
            for(int i=0;i<k;i++) if(!strcmp(kv[i].key,"ev")){ strncpy(ev,kv[i].val,255); break; }
            for(int i=0;i<k;i++){ if(!strcmp(kv[i].key,"ev")) continue;
                if(msg[0]) strcat_s(msg,sizeof msg,"  ");
                char p[300]; _snprintf(p,sizeof p,"%s=%s",kv[i].key,kv[i].val); strcat_s(msg,sizeof msg,p); }
        } else { strncpy(msg,ln,sizeof msg-1); }
        if(!lvl[0]) strcpy(lvl,"info");
        Level L=level_of(lvl,ev,msg);
        if((int)catL>=0 && L!=catL) continue;
        if(sv && sv[0] && strcmp(subsys_of(ev),sv)!=0) continue;
        if(gv && gv[0] && !has_ci(ev,gv) && !has_ci(msg,gv)) continue;
        char outl[1400]; _snprintf(outl,sizeof outl,"[%s] [%s] %s\n", ts[0]?ts:"-", ev[0]?ev:lvl, msg);
        if(n==cap){ cap=cap?cap*2:256; lines=(char**)realloc(lines,(size_t)cap*sizeof(char*)); }
        lines[n++]=_strdup(outl);
    }
    int start = (tail>0 && n>tail)? n-tail : 0;
    for(int i=start;i<n;i++){ out(lines[i]); free(lines[i]); }
    for(int i=0;i<start;i++) free(lines[i]);
    free(lines); free(j);
    return 0;
}

static void print_help(void){
    out(
      "nrs-edge loader — headless control (dual-mode; 引数無し=GUI)\n"
      "  loader.exe start [--wait[=SEC]] [--freeplay 0|1] [--test 0|1] [--game-dir DIR]\n"
      "      起動+注入。ログ窓(GUI)を必ず表示（不在なら spawn・既存は前面へ復帰し自動追従）。\n"
      "      --wait で status.json を ready/exited まで待つ。\n"
      "      exit: 0=ready 2=timeout 3=launch失敗 4=早期exit\n"
      "  loader.exe stop                       nrs.exe を taskkill\n"
      "  loader.exe restart [--wait[=SEC]]     stop→start\n"
      "  loader.exe status [--json]            集約状態を出力 (0=ready 5=未ready 6=未起動)\n"
      "  loader.exe wait --event EV [--timeout=SEC]   ev 出現まで待つ (0=found 1=timeout)\n"
      "  loader.exe logs [--tail N] [--subsys S] [--cat C] [--grep STR]\n"
      "      C= error|warn|io|pcpa|dev|setup|info   S= jvs|keychip|touch|host|...\n");
}

static int cli_main(void){
    out_setup();
    resolve_paths();
    load_cfg();
    int argc=__argc;
    char **argv=(char**)malloc(sizeof(char*)*(size_t)argc);
    for(int i=0;i<argc;i++) argv[i]=wtou8(__wargv[i]);

    const char *verb=argv[1];
    int rc=0;
    int is_help = !strcmp(verb,"help")||!strcmp(verb,"--help")||!strcmp(verb,"-h");
    if(!is_help && strcmp(verb,"stop")!=0) cli_ensure_gui(0);
    if      (!strcmp(verb,"start"))   rc=cmd_start(argc,argv);
    else if (!strcmp(verb,"stop"))    rc=cmd_stop(argc,argv);
    else if (!strcmp(verb,"restart")){ core_stop(); Sleep(600); rc=cmd_start(argc,argv); }
    else if (!strcmp(verb,"status"))  rc=cmd_status(argc,argv);
    else if (!strcmp(verb,"wait"))    rc=cmd_wait(argc,argv);
    else if (!strcmp(verb,"logs"))    rc=cmd_logs(argc,argv);
    else if (is_help){ print_help(); }
    else { outf("unknown verb: %s\n", verb); print_help(); rc=64; }

    for(int i=0;i<argc;i++) free(argv[i]);
    free(argv);
    return rc;
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR cmd, int show){
    (void)hPrev;(void)cmd;(void)show;
    if(__argc>1) return cli_main();

    HANDLE gui_mtx = CreateMutexW(NULL, TRUE, NRS_MUTEX_GUI);
    if(gui_mtx && GetLastError()==ERROR_ALREADY_EXISTS){
        HWND hw=FindWindowW(L"nrsEdgePanel", NULL);
        if(hw){ if(IsIconic(hw)) ShowWindow(hw, SW_RESTORE); SetForegroundWindow(hw); }
        CloseHandle(gui_mtx);
        return 0;
    }
    g_job = CreateJobObjectW(NULL, NRS_JOB_NAME);
    if(g_job){
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jel; ZeroMemory(&jel,sizeof jel);
        jel.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(g_job, JobObjectExtendedLimitInformation, &jel, sizeof jel);
    }

    resolve_paths();
    load_cfg();
    LoadLibraryW(L"Msftedit.dll");
    INITCOMMONCONTROLSEX ic={sizeof ic, ICC_TAB_CLASSES|ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&ic);

    g_brBG  = CreateSolidBrush(C_BG);
    g_brBG2 = CreateSolidBrush(C_BG2);
    g_font  = CreateFontW(-13,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,0,FIXED_PITCH|FF_MODERN,L"Consolas");
    g_fontUI= CreateFontW(-13,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,0,0,L"Meiryo UI");

    WNDCLASSW wc; ZeroMemory(&wc,sizeof wc);
    wc.lpfnWndProc=WndProc; wc.hInstance=hInst; wc.lpszClassName=L"nrsEdgePanel";
    wc.hbrBackground=g_brBG; wc.hCursor=LoadCursorW(NULL,(LPCWSTR)IDC_ARROW);
    RegisterClassW(&wc);
    WNDCLASSW rc2; ZeroMemory(&rc2,sizeof rc2);
    rc2.lpfnWndProc=ResumeProc; rc2.hInstance=hInst; rc2.lpszClassName=L"nrsResume";
    rc2.hCursor=LoadCursorW(NULL,(LPCWSTR)IDC_HAND);
    RegisterClassW(&rc2);
    WNDCLASSW lv; ZeroMemory(&lv,sizeof lv);
    lv.lpfnWndProc=LogViewProc; lv.hInstance=hInst; lv.lpszClassName=L"nrsLogView";
    lv.hCursor=LoadCursorW(NULL,(LPCWSTR)IDC_ARROW);
    RegisterClassW(&lv);

    g_main=CreateWindowExW(0, L"nrsEdgePanel", L"nrs-edge control panel",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,CW_USEDEFAULT, 1200,780,
        NULL,NULL,hInst,NULL);

    build_ui();
    layout();
    show_page(0);
    ShowWindow(g_main, SW_SHOW); UpdateWindow(g_main);

    SetTimer(g_main, 1, 50, NULL);
    CreateThread(NULL,0,tail_thread,NULL,0,NULL);

    MSG m;
    while(GetMessageW(&m,NULL,0,0)>0){ TranslateMessage(&m); DispatchMessageW(&m); }
    return 0;
}
