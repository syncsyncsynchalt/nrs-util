/* loader.c — nrs-edge 統合ツール（単一 exe・外部依存ゼロ・静的CRT）。
 *
 * 旧 loader.exe(CLI 注入) + 旧 control_panel.exe(GUI) + 旧 run.ps1 の inject/tail を一本化:
 *   - nrs.exe 起動/終了の単一トグルボタン（押すと ▶起動⇄■終了。host.dll を in-process で suspend→inject→resume。別 exe 不要）
 *   - FreePlay / TEST モード / Windowed チェック（nrsedge.cfg に書き host が反映）
 *   - ログタブ: 自前 tail / フィルタ / I/O 抑制 / エラーのみ / 検索 / 自動スクロール / 一時停止 / クリア / JSONL書出 / 色分け / 件数
 *   - 入力タブ: キーバインド編集（変更ボタン→次に押したキー）＋ ライブ入力テスト（GetAsyncKeyState 直読）
 *
 * 注入は本プロセス内で完結（旧: loader.exe を子プロセス起動しパイプ捕捉 → 廃止）。
 *
 * tkinter → Win32 の写像:
 *   Text+tag       → RichEdit(MSFTEDIT) + CHARFORMAT2(CFM_COLOR)
 *   after(0, fn)   → PostMessage（ワーカースレッド→UIスレッドのマーシャリング）
 *   ダークテーマ   → WM_CTLCOLOR* で自前塗り（BG/FG）
 *   <Key> 捕捉     → タイマでの GetAsyncKeyState 全VK走査（フォーカス非依存）
 */
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

/* ---- 配色（Python の _CAT/_BG/_FG と同値） ---- */
#define HEXRGB(x)  RGB(((x)>>16)&0xFF, ((x)>>8)&0xFF, (x)&0xFF)
static const COLORREF C_BG   = HEXRGB(0x13161b);
static const COLORREF C_BG2  = HEXRGB(0x1c212a);
static const COLORREF C_FG   = HEXRGB(0xd8d8d8);
static const COLORREF C_ACC  = HEXRGB(0x99aadd);  /* #9ad 見出し/待機 */

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

/* ---- パス/定数（Python 冒頭と同値。REPO は exe から2つ上 = リポジトリルート想定外でも env で上書き可） ---- */
static wchar_t G_GAME_DIR[MAX_PATH], G_GAME_EXE[MAX_PATH];
static wchar_t G_HOST_DLL[MAX_PATH], G_LOGIC_DLL[MAX_PATH], G_CFG[MAX_PATH], G_LOG[MAX_PATH];
static wchar_t G_STATUS[MAX_PATH];   /* nrsedge.status.json（host が集約状態を書く。CLI が 1 ショット読取） */

/* 入力アクションと既定バインド（VK）。順序は Python の ACTIONS と一致。 */
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
    /* A-Z / 0-9 は文字そのもの、それ以外は VK_0xNN */
    if((vk>='A'&&vk<='Z')||(vk>='0'&&vk<='9')){ out[0]=(wchar_t)vk; out[1]=0; return; }
    _snwprintf(out, cap, L"VK_0x%02X", vk);
}

/* ---- 制御ID ---- */
enum {
    ID_LAUNCH=100, ID_STOP, ID_RELAUNCH, /* STOP/RELAUNCH は廃止・予約（起動ボタンがトグル化） */
    ID_FREEPLAY, ID_TEST, ID_WINDOWED,   /* WINDOWED は廃止・予約（ウインドウモード固定） */
    ID_STATUS, ID_TAB,
    ID_FILTER=200, ID_HIDEIO, ID_ERRONLY, ID_SEARCH, ID_SEARCHNEXT, ID_AUTOSCROLL,
    ID_PAUSE, ID_CLEAR, ID_EXPORT, ID_LOG, ID_LOGSTATUS, ID_LBL_FILTER, ID_LBL_SEARCH,
    ID_BIND_LBL=300,   /* +i */
    ID_BIND_BTN=320,   /* +i */
    ID_BIND_IND=340,   /* +i */
    ID_ANALOG=400, ID_GAME, ID_SAVE, ID_CAP, ID_INPUT_HELP,
};
/* ワーカースレッド→UIスレッドのカスタムメッセージ */
#define WM_APP_LOGLINE (WM_APP+1)   /* lParam = UTF-8 char* (1行、要 free) */
#define WM_APP_STATUS  (WM_APP+2)   /* wParam = COLORREF, lParam = UTF-8 char* (要 free) */
#define WM_APP_RUNSTATE (WM_APP+3)  /* wParam = 0/1 → 起動ボタンの running 状態を同期 */

/* ---- グローバル UI ハンドル ---- */
static HWND g_main, g_tab, g_status, g_log, g_logstatus;
static HWND g_filter, g_search, g_cap, g_analog, g_game;
static HWND g_bindlbl[NACT], g_bindind[NACT];
static HFONT g_font, g_fontUI;
static HBRUSH g_brBG, g_brBG2;
static int  g_busy = 0;           /* 起動/終了の in-flight ガード */
static int  g_running = 0;         /* ▶起動ボタンの状態（0=待機/起動可, 1=実行中/終了可） */
static int  g_capture_act = -1;   /* キャプチャ中アクション index (-1=非捕捉) */
static int  g_prev_down[256];     /* キャプチャ用: 直前フレームの VK 押下状態 */
static COLORREF g_status_color;

/* ---- ログエントリ蓄積（フィルタ再描画のため保持） ---- */
typedef struct { char ts[16]; char src[64]; Level lvl; char *msg; } Entry;
static Entry  *g_ent;
static size_t  g_ent_n, g_ent_cap;
static int     g_errors, g_shown, g_disp;
static int     g_paused = 0;

/* ============================================================ utils */

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

/* ============================================================ config */

static void resolve_paths(void){
    wchar_t exe[MAX_PATH]; GetModuleFileNameW(NULL, exe, MAX_PATH);
    /* exe = <repo>\build\Debug\loader.exe → repo = 3つ上 */
    wchar_t repo[MAX_PATH]; wcscpy(repo, exe);
    for(int i=0;i<3;i++){ wchar_t *p=wcsrchr(repo,L'\\'); if(p)*p=0; }

    wchar_t gdir[MAX_PATH];
    if(GetEnvironmentVariableW(L"NRS_GAME_DIR", gdir, MAX_PATH)==0) wcscpy(gdir, L"C:\\src\\bbs");
    wcscpy(G_GAME_DIR, gdir);
    _snwprintf(G_GAME_EXE,  MAX_PATH, L"%s\\nrs.exe", gdir);
    _snwprintf(G_CFG,      MAX_PATH, L"%s\\nrsedge.cfg", gdir);
    _snwprintf(G_LOG,      MAX_PATH, L"%s\\nrsedge.log", gdir);
    _snwprintf(G_STATUS,   MAX_PATH, L"%s\\nrsedge.status.json", gdir);
    _snwprintf(G_HOST_DLL, MAX_PATH, L"%s\\build\\Debug\\host.dll",  repo);
    _snwprintf(G_LOGIC_DLL,MAX_PATH, L"%s\\build\\Debug\\logic.dll", repo);
}

/* nrsedge.cfg を読み freeplay/test と bind.* を反映。欠落は既定のまま。
 * windowed は UI 廃止＝ウインドウモード固定。cfg からは読まず（=stale な windowed=0 を無視）常に 1 を書き戻す。 */
static int g_freeplay=1, g_test=0;
static const int g_windowed=1;
static void load_cfg(void){
    FILE *f = _wfopen(G_CFG, L"r"); if(!f) return;
    char ln[256];
    while(fgets(ln, sizeof ln, f)){
        char *eq = strchr(ln, '='); if(!eq) continue;
        *eq=0; char *k=ln, *v=eq+1; int val=atoi(v);
        /* 末尾改行/空白除去は atoi/strncmp 用途では不要 */
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

/* ============================================================ JSON（host が書く JSONL の最小パーサ） */

/* 文字列/数値どちらも raw トークンとして取り出す。obj は '{' の次を指す。
 * 浅いオブジェクト前提だが、値が {} [] "" を含んでも depth 追跡で破綻しない。 */
typedef struct { char key[48]; char val[256]; } KV;
static int parse_obj(const char *s, KV *out, int maxn){
    int n=0;
    while(*s && n<maxn){
        while(*s==' '||*s=='\t'||*s==','||*s=='\n'||*s=='\r') s++;
        if(*s=='}'||!*s) break;
        if(*s!='"') { s++; continue; }
        s++; int ki=0;                                  /* key */
        while(*s && *s!='"' && ki<47) out[n].key[ki++]=*s++;
        out[n].key[ki]=0; if(*s=='"') s++;
        while(*s==' '||*s==':'||*s=='\t') s++;
        int vi=0;                                       /* value */
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
/* 行全体（top-level）から ts / lvl / m(raw object) を取り出す。 */
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

/* ============================================================ レベル分類（Python level_of と同義） */

static int has_ci(const char *h, const char *n){ /* 大小無視の部分一致 */
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

/* ============================================================ RichEdit ヘルパ */

static void log_append_colored(const wchar_t *wtext, COLORREF color){
    int end = GetWindowTextLengthW(g_log);
    SendMessageW(g_log, EM_SETSEL, end, end);
    CHARFORMAT2W cf; ZeroMemory(&cf,sizeof cf);
    cf.cbSize=sizeof cf; cf.dwMask=CFM_COLOR; cf.crTextColor=color;
    SendMessageW(g_log, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    SendMessageW(g_log, EM_REPLACESEL, FALSE, (LPARAM)wtext);
}
static int autoscroll_on(void){ return (int)SendMessageW(GetDlgItem(g_main,ID_AUTOSCROLL),BM_GETCHECK,0,0)==BST_CHECKED; }
static void log_scroll_end(void){ if(autoscroll_on()) SendMessageW(g_log, WM_VSCROLL, SB_BOTTOM, 0); }

/* ============================================================ フィルタ / 整形 / 描画 */

static void fmt_entry(const Entry *e, char *out, int cap){
    _snprintf(out, cap, "[%-12.12s] [%-22.22s] %s", e->ts, e->src, e->msg);
}
static int passes(const Entry *e){
    int hideio = SendMessageW(GetDlgItem(g_main,ID_HIDEIO),BM_GETCHECK,0,0)==BST_CHECKED;
    int erronly= SendMessageW(GetDlgItem(g_main,ID_ERRONLY),BM_GETCHECK,0,0)==BST_CHECKED;
    if(hideio && e->lvl==L_IO) return 0;
    if(erronly && e->lvl!=L_ERROR) return 0;
    wchar_t fw[128]; GetWindowTextW(g_filter, fw, 128);
    if(fw[0]){
        char *f = wtou8(fw); int ok = (has_ci(e->src,f)||has_ci(e->msg,f)); free(f);
        if(!ok) return 0;
    }
    return 1;
}
static void log_append_entry(const Entry *e){
    char line[1200]; fmt_entry(e, line, sizeof line);
    strcat_s(line, sizeof line, "\r\n");
    wchar_t *w = u8tow(line);
    log_append_colored(w, level_color(e->lvl)); free(w);
    g_disp++; g_shown++;
    log_scroll_end();
}
static void update_counts(void);
static void log_rerender(void){
    SendMessageW(g_log, WM_SETREDRAW, FALSE, 0);
    SetWindowTextW(g_log, L"");
    g_disp=0; g_shown=0;
    /* 末尾 8000 件のみ（Python と同じ表示上限） */
    size_t start = 0, vis=0;
    for(size_t i=g_ent_n; i>0; i--){ if(passes(&g_ent[i-1])){ vis++; if(vis>=8000){ start=i-1; break; } } }
    for(size_t i=start; i<g_ent_n; i++){
        if(!passes(&g_ent[i])) continue;
        char line[1200]; fmt_entry(&g_ent[i], line, sizeof line);
        strcat_s(line, sizeof line, "\r\n");
        wchar_t *w=u8tow(line); log_append_colored(w, level_color(g_ent[i].lvl)); free(w);
        g_disp++; g_shown++;
    }
    SendMessageW(g_log, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_log, NULL, TRUE);
    log_scroll_end();
    update_counts();
}

static void update_counts(void){
    char buf[MAX_PATH+128]; char *logu=wtou8(G_LOG);
    _snprintf(buf,sizeof buf," %s  総数 %zu / 表示 %d / エラー %d%s",
              logu, g_ent_n, g_shown, g_errors, g_paused?"  [停止中]":"");
    free(logu);
    wchar_t *w=u8tow(buf); SetWindowTextW(g_logstatus, w); free(w);
}

/* 入力タブ game-side 行更新（input.state イベント時のみ） */
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

/* ============================================================ 1行取り込み（tail / emit 共通） */

static void ingest(const char *raw){
    char line[2048]; strncpy(line, raw, sizeof line -1); line[sizeof line-1]=0;
    /* trim */
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
        strncpy(msg, line, sizeof msg-1);     /* JSON でない行はそのまま */
    }
    if(!lvl[0]) strcpy(lvl,"info");
    if(!ts[0])  nowts(ts,sizeof ts);

    if(strcmp(ev,"input.state")==0 && mraw[0]) update_test_row(mraw);

    /* 蓄積（80000 件で前詰めトリム） */
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
    }
    if(!g_paused && passes(e)) log_append_entry(e);
}

/* GUI 自身のイベント（loader 出力等）を JSONL 経路へ合流（PostMessage で UI スレッドへ）。 */
static void emit(const char *ev, const char *msg, const char *lvl){
    char ts[16]; nowts(ts,sizeof ts);
    /* msg の " と \ を最小エスケープ */
    char esc[1024]; int j=0;
    for(const char *p=msg; *p && j<1020; p++){ if(*p=='"'||*p=='\\') esc[j++]='\\'; esc[j++]=*p; }
    esc[j]=0;
    char *line=(char*)malloc(1400);
    _snprintf(line,1400,"{\"ts\":\"%s\",\"lvl\":\"%s\",\"m\":{\"ev\":\"%s\",\"msg\":\"%s\"}}",
              ts, lvl, ev, esc);
    PostMessageW(g_main, WM_APP_LOGLINE, 0, (LPARAM)line);
}

/* ============================================================ tail スレッド */

static DWORD WINAPI tail_thread(LPVOID arg){
    (void)arg;
    LONGLONG pos=0;
    char carry[2048]; int carry_n=0;
    for(;;){
        HANDLE h=CreateFileW(G_LOG, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                             NULL, OPEN_EXISTING, 0, NULL);
        if(h!=INVALID_HANDLE_VALUE){
            LARGE_INTEGER sz; GetFileSizeEx(h,&sz);
            if(sz.QuadPart < pos){ pos=0; carry_n=0; }   /* ローテーション/truncate */
            LARGE_INTEGER mv; mv.QuadPart=pos; SetFilePointerEx(h,mv,NULL,FILE_BEGIN);
            char buf[8192]; DWORD rd;
            while(ReadFile(h,buf,sizeof buf,&rd,NULL) && rd>0){
                pos += rd;
                for(DWORD i=0;i<rd;i++){
                    char c=buf[i];
                    if(c=='\n'){
                        carry[carry_n]=0;
                        char *line=_strdup(carry);
                        PostMessageW(g_main, WM_APP_LOGLINE, 0, (LPARAM)line);
                        carry_n=0;
                    } else if(carry_n<(int)sizeof carry-1){
                        carry[carry_n++]=c;
                    }
                }
            }
            CloseHandle(h);
        }
        Sleep(120);
    }
    return 0;
}

/* ============================================================ 起動 / 終了 / 再起動 */

static void set_status(COLORREF col, const char *u8){
    char *line=_strdup(u8);
    PostMessageW(g_main, WM_APP_STATUS, (WPARAM)col, (LPARAM)line);
}

/* dll_abspath を proc に LoadLibrary 注入。成功で NULL、失敗で理由(英/和)文字列を返す。
 * 旧 loader.c(CLI) の inject() を関数化（戻り値で各段の成否を報告できる形へ）。 */
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
    return NULL;   /* LoadLibraryA が host.dll をロード＝注入完了 */
}

/* 起動結果（GUI/CLI 共通）。core_* は GUI globals(emit/set_status/HWND) に依存しない純粋層。 */
typedef struct { int ok; DWORD pid; char err[200]; } LaunchResult;

/* nrs.exe を SUSPENDED 起動 → host.dll 注入 → resume（in-process）。GUI 非依存。
 * SUSPENDED の理由: host のフックをゲーム早期初期化（CrackProof / device open）より前に設置するため。
 * resume はフック設置後（＝注入成功後）。CREATE_NO_WINDOW: nrs.exe は CUI のため空コンソール窓を隠す
 * （コンソール自体は割り当てられ fd1/2 は有効＝dbglog.c の __write フックは機能）。 */
static void core_launch(LaunchResult *r){
    r->ok=0; r->pid=0; r->err[0]=0;
    /* host.dll / logic.dll を game dir へコピー（host は同 dir から logic.dll を探す） */
    wchar_t hostdll[MAX_PATH], logicdll[MAX_PATH];
    _snwprintf(hostdll, MAX_PATH, L"%s\\host.dll",  G_GAME_DIR); CopyFileW(G_HOST_DLL, hostdll, FALSE);
    _snwprintf(logicdll,MAX_PATH, L"%s\\logic.dll", G_GAME_DIR); CopyFileW(G_LOGIC_DLL,logicdll,FALSE);
    /* nrsedge.log を truncate（新規セッション）。status.json も消し前回状態の誤読を防ぐ。 */
    HANDLE h=CreateFileW(G_LOG,GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,0,NULL);
    if(h!=INVALID_HANDLE_VALUE) CloseHandle(h);
    DeleteFileW(G_STATUS);

    STARTUPINFOW si; ZeroMemory(&si,sizeof si); si.cb=sizeof si;
    PROCESS_INFORMATION pi; ZeroMemory(&pi,sizeof pi);
    if(!CreateProcessW(G_GAME_EXE, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED|CREATE_NO_WINDOW,
                       NULL, G_GAME_DIR, &si, &pi)){
        _snprintf(r->err,sizeof r->err,"CreateProcess err=%lu", GetLastError());
        return;
    }
    const char *err = inject(pi.hProcess, hostdll);
    if(err){
        /* SUSPENDED のまま放置せず始末（keychip ポートを掴むゾンビ nrs.exe を残さない）。 */
        _snprintf(r->err,sizeof r->err,"注入 %s", err);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return;
    }
    ResumeThread(pi.hThread);              /* フック設置済 → ゲーム本体を走らせる */
    r->pid = pi.dwProcessId; r->ok = 1;
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);  /* プロセスは走り続ける */
}

/* taskkill /F /IM nrs.exe。1=プロセスを終了 / 0=対象なし。GUI 非依存。 */
static int core_stop(void){
    STARTUPINFOW si; ZeroMemory(&si,sizeof si); si.cb=sizeof si;
    PROCESS_INFORMATION pi; ZeroMemory(&pi,sizeof pi);
    wchar_t cmd[]=L"taskkill /F /IM nrs.exe";
    DWORD code=1;   /* taskkill: 0=killed, 128=not found */
    if(CreateProcessW(NULL,cmd,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){
        WaitForSingleObject(pi.hProcess,5000); GetExitCodeProcess(pi.hProcess,&code);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    /* 明示停止は status.json を消す。/F はハードキルで ExitProcess フックが発火せず phase=ready が
     * 残るため。これで「こちらが止めた(file 無=none)」と「自滅した(ExitProcess フックで phase=exited)」を区別できる。 */
    DeleteFileW(G_STATUS);
    return code==0;
}

/* ---- GUI ラッパ（emit/set_status で結果を窓へ反映。挙動は従来どおり） ---- */
static int run_loader(void){   /* 1=注入まで成功 / 0=失敗（呼び出し側がボタンを ▶起動 へ戻す） */
    LaunchResult r; core_launch(&r);
    if(!r.ok){
        char buf[260]; _snprintf(buf,sizeof buf,"起動失敗: %s", r.err);
        emit("loader", buf, "error"); set_status(HEXRGB(0xff5f5f), buf);
        return 0;
    }
    char ok[128]; _snprintf(ok,sizeof ok,"host.dll 注入完了 pid=%lu", r.pid);
    emit("loader", ok, "info");
    set_status(HEXRGB(0x7bd66b), "起動: nrs.exe + host.dll 注入");
    return 1;   /* 観測は tail_thread が nrsedge.log を読む */
}

static void do_stop(void){
    core_stop();
    set_status(HEXRGB(0xffb454),"終了: nrs.exe kill");
}

/* ワーカースレッド本体（二重起動ガードは呼び出し側）。
 * th_launch: 起動失敗時は WM_APP_RUNSTATE(0) を UI スレッドへ投げてボタンを ▶起動 へ戻す。 */
static DWORD WINAPI th_launch(LPVOID a){ (void)a; if(!run_loader()) PostMessageW(g_main, WM_APP_RUNSTATE, 0, 0); g_busy=0; return 0; }
static DWORD WINAPI th_stop(LPVOID a){ (void)a; do_stop(); g_busy=0; return 0; }

static void start_worker(LPTHREAD_START_ROUTINE fn){
    if(g_busy){ set_status(HEXRGB(0xffb454),"処理中… しばらくお待ちください"); return; }
    g_busy=1;
    HANDLE h=CreateThread(NULL,0,fn,NULL,0,NULL); if(h) CloseHandle(h);
}

/* 単一トグルボタンの見た目を running 状態へ同期（UI スレッドから呼ぶこと）。
 * BS_OWNERDRAW なので InvalidateRect で draw_owner_button を再発火させ色も更新する。 */
static void set_run_button(int running){
    g_running = running;
    HWND b = GetDlgItem(g_main, ID_LAUNCH);
    SetWindowTextW(b, running ? L"■ 終了" : L"▶ 起動");
    InvalidateRect(b, NULL, TRUE);
}

/* ============================================================ 入力テスト（タイマ） */

static int key_down(int vk){ return vk && (GetAsyncKeyState(vk)&0x8000)!=0; }

static void poll_keys(void){
    if(g_capture_act>=0){
        /* キャプチャ中: 直前に上がっていて今押されたVKを採用（フォーカス非依存） */
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
    /* インジケータ点灯（GUI 直読・ゲーム不要） */
    for(int a=0;a<NACT;a++){
        COLORREF c = key_down(g_bind[a])? HEXRGB(0x3fe06a) : HEXRGB(0x444444);
        /* インジケータは STATIC。色は WM_CTLCOLORSTATIC で引くため、状態を子に持たせ Invalidate */
        SetWindowLongPtrW(g_bindind[a], GWLP_USERDATA, (LONG_PTR)c);
        InvalidateRect(g_bindind[a], NULL, FALSE);
    }
    int lx = key_down(g_bind[6])?0x0000 : (key_down(g_bind[7])?0xFFFF:0x8000); /* left/right */
    int ly = key_down(g_bind[4])?0x0000 : (key_down(g_bind[5])?0xFFFF:0x8000); /* up/down */
    char buf[128]; _snprintf(buf,sizeof buf,"analog X=%04X Y=%04X  (GUI 直接ポーリング・ゲーム不要)",lx,ly);
    wchar_t *w=u8tow(buf); SetWindowTextW(g_analog,w); free(w);
}

/* ============================================================ 検索 / 書出 / クリア */

static void search_next(void){
    wchar_t t[128]; GetWindowTextW(g_search,t,128); if(!t[0]) return;
    static LONG from=0;
    CHARRANGE all={from,-1};
    FINDTEXTEXW ft; ft.chrg=all; ft.lpstrText=t;
    LONG pos=(LONG)SendMessageW(g_log, EM_FINDTEXTEXW, FR_DOWN, (LPARAM)&ft);
    if(pos<0){ from=0; ft.chrg.cpMin=0; ft.chrg.cpMax=-1;
        pos=(LONG)SendMessageW(g_log, EM_FINDTEXTEXW, FR_DOWN, (LPARAM)&ft); }
    if(pos<0){ SetWindowTextW(g_logstatus, L"検索: 見つかりません"); return; }
    SendMessageW(g_log, EM_SETSEL, ft.chrgText.cpMin, ft.chrgText.cpMax);
    SendMessageW(g_log, EM_SCROLLCARET, 0, 0);
    from = ft.chrgText.cpMax;
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
    g_ent_n=0; g_errors=0; g_disp=0; g_shown=0;
    SetWindowTextW(g_log, L""); update_counts();
}

/* ============================================================ UI 構築 / レイアウト */

static HWND mk(const wchar_t *cls, const wchar_t *txt, DWORD style, int id, HFONT font){
    HWND h=CreateWindowExW(0, cls, txt, WS_CHILD|WS_VISIBLE|style, 0,0,10,10,
                           g_main, (HMENU)(INT_PTR)id, GetModuleHandleW(NULL), NULL);
    SendMessageW(h, WM_SETFONT, (WPARAM)font, TRUE);
    return h;
}

static void build_ui(void){
    /* 上段バー */
    /* 起動/終了は単一トグルボタン: 押すたびに ▶起動(緑) ⇄ ■終了(赤) を切替（draw_owner_button/WM_COMMAND が g_running を参照）。 */
    mk(L"BUTTON", L"▶ 起動", BS_OWNERDRAW, ID_LAUNCH, g_fontUI);
    HWND c;
    c=mk(L"BUTTON",L"FreePlay",     BS_AUTOCHECKBOX, ID_FREEPLAY, g_fontUI); SendMessageW(c,BM_SETCHECK,g_freeplay?BST_CHECKED:BST_UNCHECKED,0);
    c=mk(L"BUTTON",L"TEST モード",BS_AUTOCHECKBOX, ID_TEST, g_fontUI);     SendMessageW(c,BM_SETCHECK,g_test?BST_CHECKED:BST_UNCHECKED,0);
    /* Windowed チェックボックスは廃止: ウインドウモード固定（cfg へ windowed=1 を常時書出）。 */
    g_status = mk(L"STATIC", L"待機中", SS_RIGHT, ID_STATUS, g_fontUI);
    g_status_color = C_ACC;

    /* タブ */
    g_tab = mk(WC_TABCONTROLW, L"", 0, ID_TAB, g_fontUI);
    /* UNICODE 未定義のため TabCtrl_InsertItem は TCM_INSERTITEMA に解決される。
     * ワイド文字列を ANSI 経路で送ると文字化けするので W メッセージを明示送出する。 */
    TCITEMW ti; ti.mask=TCIF_TEXT;
    ti.pszText=(LPWSTR)L"ログ";              SendMessageW(g_tab, TCM_INSERTITEMW, 0, (LPARAM)&ti);
    ti.pszText=(LPWSTR)L"入力設定"; SendMessageW(g_tab, TCM_INSERTITEMW, 1, (LPARAM)&ti);

    /* --- ログタブ --- */
    mk(L"STATIC", L"Filter:", SS_RIGHT, ID_LBL_FILTER, g_fontUI);
    g_filter = mk(L"EDIT", L"", WS_BORDER|ES_AUTOHSCROLL, ID_FILTER, g_fontUI);
    mk(L"BUTTON", L"I/O 抑制", BS_AUTOCHECKBOX, ID_HIDEIO, g_fontUI);
    mk(L"BUTTON", L"エラーのみ", BS_AUTOCHECKBOX, ID_ERRONLY, g_fontUI);
    mk(L"STATIC", L"検索:", SS_RIGHT, ID_LBL_SEARCH, g_fontUI);
    g_search = mk(L"EDIT", L"", WS_BORDER|ES_AUTOHSCROLL, ID_SEARCH, g_fontUI);
    mk(L"BUTTON", L"次へ", BS_PUSHBUTTON, ID_SEARCHNEXT, g_fontUI);
    c=mk(L"BUTTON", L"自動スクロール", BS_AUTOCHECKBOX, ID_AUTOSCROLL, g_fontUI); SendMessageW(c,BM_SETCHECK,BST_CHECKED,0);
    mk(L"BUTTON", L"一時停止", BS_AUTOCHECKBOX, ID_PAUSE, g_fontUI);
    mk(L"BUTTON", L"クリア", BS_PUSHBUTTON, ID_CLEAR, g_fontUI);
    mk(L"BUTTON", L"JSONL書出", BS_PUSHBUTTON, ID_EXPORT, g_fontUI);

    g_log = CreateWindowExW(0, MSFTEDIT_CLASS, L"",
        WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
        0,0,10,10, g_main, (HMENU)ID_LOG, GetModuleHandleW(NULL), NULL);
    SendMessageW(g_log, WM_SETFONT, (WPARAM)g_font, TRUE);
    SendMessageW(g_log, EM_SETBKGNDCOLOR, 0, (LPARAM)C_BG);
    SendMessageW(g_log, EM_EXLIMITTEXT, 0, (LPARAM)0x7FFFFFFF);
    g_logstatus = mk(L"STATIC", L"", SS_LEFT, ID_LOGSTATUS, g_fontUI);

    /* --- 入力タブ --- */
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
}

/* タブ表示領域 */
static RECT tab_display(void){
    RECT rc; GetClientRect(g_tab,&rc); TabCtrl_AdjustRect(g_tab,FALSE,&rc);
    POINT tl={rc.left,rc.top}, br={rc.right,rc.bottom};
    ClientToScreen(g_tab,&tl); ClientToScreen(g_tab,&br);
    ScreenToClient(g_main,&tl); ScreenToClient(g_main,&br);
    RECT r={tl.x,tl.y,br.x,br.y}; return r;
}
static void mv(int id,int x,int y,int w,int h){ MoveWindow(GetDlgItem(g_main,id),x,y,w,h,TRUE); }

static void show_page(int page){
    int log_ids[]={ID_LBL_FILTER,ID_FILTER,ID_HIDEIO,ID_ERRONLY,ID_LBL_SEARCH,ID_SEARCH,
                   ID_SEARCHNEXT,ID_AUTOSCROLL,ID_PAUSE,ID_CLEAR,ID_EXPORT,ID_LOG,ID_LOGSTATUS};
    for(int i=0;i<(int)(sizeof log_ids/sizeof*log_ids);i++)
        ShowWindow(GetDlgItem(g_main,log_ids[i]), page==0?SW_SHOW:SW_HIDE);
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
}

static void layout(void){
    RECT rc; GetClientRect(g_main,&rc);
    int W=rc.right;
    /* 上段バー（y=0..40） */
    int x=8,y=8,bh=26;
    mv(ID_LAUNCH,x,y,80,bh); x+=92;
    mv(ID_FREEPLAY,x,y,86,bh); x+=92; mv(ID_TEST,x,y,100,bh); x+=104;
    mv(ID_STATUS, x, y+4, W-x-12, 18);
    /* タブ（44..下端） */
    MoveWindow(g_tab,4,44,W-8,rc.bottom-48,TRUE);
    RECT p=tab_display();
    /* ログツールバー（p 内 1行目） */
    int lx=p.left+4, ly=p.top+4;
    mv(ID_LBL_FILTER,lx,ly+4,46,18); lx+=50; mv(ID_FILTER,lx,ly,150,22); lx+=158;
    mv(ID_HIDEIO,lx,ly,80,22); lx+=84; mv(ID_ERRONLY,lx,ly,90,22); lx+=98;
    mv(ID_LBL_SEARCH,lx,ly+4,40,18); lx+=42; mv(ID_SEARCH,lx,ly,110,22); lx+=116;
    mv(ID_SEARCHNEXT,lx,ly,48,22); lx+=54; mv(ID_AUTOSCROLL,lx,ly,120,22); lx+=126;
    mv(ID_PAUSE,lx,ly,80,22); lx+=84; mv(ID_CLEAR,lx,ly,60,22); lx+=66; mv(ID_EXPORT,lx,ly,86,22);
    /* RichEdit + log status */
    int top2=ly+30;
    MoveWindow(g_log, p.left+4, top2, (p.right-p.left)-8, (p.bottom-top2)-26, TRUE);
    mv(ID_LOGSTATUS, p.left+4, p.bottom-22, (p.right-p.left)-8, 20);
    /* 入力タブ */
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
}

/* ============================================================ WndProc */

static void draw_owner_button(LPDRAWITEMSTRUCT d){
    COLORREF bg, fg;
    switch(d->CtlID){
        case ID_LAUNCH: if(g_running){ bg=HEXRGB(0xdd5555); fg=RGB(255,255,255); }   /* 実行中=赤(終了) */
                        else        { bg=HEXRGB(0x22dd66); fg=RGB(0,0,0);       }   /* 待機中=緑(起動) */
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
            if(!g_running){                                   /* 待機 → 起動 */
                write_cfg(); set_status(C_ACC,"起動中…");
                set_run_button(1);                            /* ■終了(赤)へ */
                start_worker(th_launch);
            } else {                                          /* 実行中 → 終了 */
                set_status(C_ACC,"終了中…");
                set_run_button(0);                            /* ▶起動(緑)へ戻す */
                start_worker(th_stop);
            }
        }
        else if(id==ID_FREEPLAY){ g_freeplay=SendMessageW((HWND)lp,BM_GETCHECK,0,0)==BST_CHECKED; write_cfg(); }
        else if(id==ID_TEST){ g_test=SendMessageW((HWND)lp,BM_GETCHECK,0,0)==BST_CHECKED; write_cfg(); }
        else if(id==ID_FILTER && code==EN_CHANGE){ log_rerender(); }
        else if(id==ID_HIDEIO || id==ID_ERRONLY){ log_rerender(); }
        else if(id==ID_SEARCHNEXT){ search_next(); }
        else if(id==ID_PAUSE){ g_paused=SendMessageW((HWND)lp,BM_GETCHECK,0,0)==BST_CHECKED; if(!g_paused) log_rerender(); }
        else if(id==ID_CLEAR){ log_clear(); }
        else if(id==ID_EXPORT){ export_jsonl(); }
        else if(id==ID_SAVE){ write_cfg(); SetWindowTextW(g_cap, L"保存しました（再起動で反映）"); }
        else if(id>=ID_BIND_BTN && id<ID_BIND_BTN+NACT){
            g_capture_act=id-ID_BIND_BTN;
            for(int vk=0;vk<256;vk++) g_prev_down[vk]=(GetAsyncKeyState(vk)&0x8000)!=0;
            char buf[128]; _snprintf(buf,sizeof buf,"'%s' の新キーを押してください…",ACTIONS[g_capture_act]);
            wchar_t *w=u8tow(buf); SetWindowTextW(g_cap,w); free(w);
        }
        return 0;
    }

    case WM_APP_LOGLINE: {
        char *line=(char*)lp; if(line){ ingest(line); free(line); }
        return 0;
    }
    case WM_APP_RUNSTATE:
        set_run_button((int)wp);   /* 起動失敗を検知したワーカーがボタンを ▶起動 へ戻す等 */
        return 0;
    case WM_APP_STATUS: {
        g_status_color=(COLORREF)wp; char *t=(char*)lp;
        if(t){ wchar_t *w=u8tow(t); SetWindowTextW(g_status,w); free(w); free(t); }
        InvalidateRect(g_status,NULL,TRUE);
        return 0;
    }

    case WM_TIMER:
        if(wp==1){ poll_keys(); }
        return 0;

    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hw,msg,wp,lp);
}

/* ============================================================ ヘッドレス CLI（AI 制御面）
 *
 * loader.exe は /SUBSYSTEM:WINDOWS だが、引数付き起動時は GUI を作らず CLI として動く（dual-mode）。
 * 各動詞は 1 コマンド=1 Bash 呼出・JSON on stdout・機械可読な exit code を返す。AI が RE ループを
 * 回す最小十分なサーフェス: start/stop/restart/status/wait/logs。
 *
 * stdout: WINDOWS サブシステム exe でも、親がパイプへリダイレクトして起動すれば（Claude の Bash/PS
 * ツールはそうする）継承された STD_OUTPUT_HANDLE に WriteFile で書ける（CRT の printf/fd1 は不定なので
 * 使わない）。リダイレクト無しの対話実行には AttachConsole(ATTACH_PARENT_PROCESS) でフォールバック。 */

static HANDLE g_out = NULL;
static void out_setup(void){
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if(h && h!=INVALID_HANDLE_VALUE){ g_out=h; return; }      /* リダイレクト済（パイプ/ファイル） */
    if(AttachConsole(ATTACH_PARENT_PROCESS)){                 /* 対話コンソールから直接実行 */
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

/* --key=val / --key val / 裸の --key（次が別オプション '-' 始まりなら "" を返す）。不在は NULL。 */
static const char* arg_val(int argc, char **argv, const char *key){
    size_t kl=strlen(key);
    for(int i=1;i<argc;i++){
        if(strncmp(argv[i],key,kl)!=0) continue;
        if(argv[i][kl]=='=') return argv[i]+kl+1;
        if(argv[i][kl]!=0) continue;                         /* --keyXXX のような前方一致は不採用 */
        if(i+1<argc && argv[i+1][0]!='-') return argv[i+1];
        return "";                                           /* 裸フラグ */
    }
    return NULL;
}

/* JSON から "key":"val" を取り出す（loader 側ローカル。status.c の同名とは別 TU）。 */
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

/* status.json を読み phase を取り出す。1=存在。out_json があれば内容を所有権付きで返す。 */
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

/* ---- verbs ---- */

static int cmd_start(int argc, char **argv){
    const char *gd=arg_val(argc,argv,"--game-dir");
    if(gd && gd[0]){ wchar_t *w=u8tow(gd); SetEnvironmentVariableW(L"NRS_GAME_DIR",w); free(w); resolve_paths(); }
    const char *fp=arg_val(argc,argv,"--freeplay"); if(fp&&fp[0]) g_freeplay=atoi(fp);
    const char *tm=arg_val(argc,argv,"--test");     if(tm&&tm[0]) g_test=atoi(tm);
    write_cfg();                                     /* host が attach 時に読む */

    if(proc_running(L"nrs.exe")){ outf("{\"result\":\"already_running\"}\n"); return 0; }

    LaunchResult r; core_launch(&r);
    if(!r.ok){ outf("{\"result\":\"launch_failed\",\"error\":\"%s\"}\n", r.err); return 3; }

    const char *wv=arg_val(argc,argv,"--wait");
    if(!wv){ outf("{\"result\":\"started\",\"pid\":%lu}\n", r.pid); return 0; }
    int secs = wv[0]? atoi(wv) : 60; if(secs<=0) secs=60;

    /* status.json を polling し ready / exited|error / timeout まで block。 */
    DWORD t0=GetTickCount();
    for(;;){
        Sleep(200);
        char phase[16]=""; read_phase(phase,sizeof phase,NULL);
        if(!strcmp(phase,"ready"))  { print_status_json(); return 0; }
        if(!strcmp(phase,"exited")||!strcmp(phase,"error")){ print_status_json(); return 4; }
        if(!proc_running(L"nrs.exe")){ print_status_json(); return 4; }   /* status 更新前に落ちた */
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
    return 5;                                        /* 起動中だが未 ready */
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

    /* tail のため一旦マッチ行を配列に貯め、末尾 N のみ出力。 */
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
      "      起動+注入。--wait で status.json を ready/exited まで待つ。\n"
      "      exit: 0=ready 2=timeout 3=launch失敗 4=早期exit\n"
      "  loader.exe stop                       nrs.exe を taskkill\n"
      "  loader.exe restart [--wait[=SEC]]     stop→start\n"
      "  loader.exe status [--json]            集約状態を出力 (0=ready 5=未ready 6=未起動)\n"
      "  loader.exe wait --event EV [--timeout=SEC]   ev 出現まで待つ (0=found 1=timeout)\n"
      "  loader.exe logs [--tail N] [--subsys S] [--cat C] [--grep STR]\n"
      "      C= error|warn|io|pcpa|dev|setup|info   S= jvs|keychip|touch|host|...\n");
}

/* CLI エントリ（wWinMain から __argc>1 で分岐）。返り値がプロセス exit code。 */
static int cli_main(void){
    out_setup();
    resolve_paths();
    load_cfg();
    int argc=__argc;
    char **argv=(char**)malloc(sizeof(char*)*(size_t)argc);
    for(int i=0;i<argc;i++) argv[i]=wtou8(__wargv[i]);

    const char *verb=argv[1];
    int rc=0;
    if      (!strcmp(verb,"start"))   rc=cmd_start(argc,argv);
    else if (!strcmp(verb,"stop"))    rc=cmd_stop(argc,argv);
    else if (!strcmp(verb,"restart")){ core_stop(); Sleep(600); rc=cmd_start(argc,argv); }
    else if (!strcmp(verb,"status"))  rc=cmd_status(argc,argv);
    else if (!strcmp(verb,"wait"))    rc=cmd_wait(argc,argv);
    else if (!strcmp(verb,"logs"))    rc=cmd_logs(argc,argv);
    else if (!strcmp(verb,"help")||!strcmp(verb,"--help")||!strcmp(verb,"-h")){ print_help(); }
    else { outf("unknown verb: %s\n", verb); print_help(); rc=64; }

    for(int i=0;i<argc;i++) free(argv[i]);
    free(argv);
    return rc;
}

/* ============================================================ WinMain */

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR cmd, int show){
    (void)hPrev;(void)cmd;(void)show;
    if(__argc>1) return cli_main();                /* 引数あり=ヘッドレス CLI（GUI を作らない） */
    resolve_paths();
    load_cfg();
    LoadLibraryW(L"Msftedit.dll");                 /* RICHEDIT50W を提供 */
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

    g_main=CreateWindowExW(0, L"nrsEdgePanel", L"nrs-edge control panel",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,CW_USEDEFAULT, 1200,780,
        NULL,NULL,hInst,NULL);

    build_ui();
    layout();
    show_page(0);
    ShowWindow(g_main, SW_SHOW); UpdateWindow(g_main);

    SetTimer(g_main, 1, 50, NULL);                 /* 入力ポーリング（Python _poll_keys 50ms） */
    CreateThread(NULL,0,tail_thread,NULL,0,NULL);  /* nrsedge.log tail */

    MSG m;
    while(GetMessageW(&m,NULL,0,0)>0){ TranslateMessage(&m); DispatchMessageW(&m); }
    return 0;
}
