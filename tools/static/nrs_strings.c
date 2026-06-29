/* nrs_strings.c — nrs.exe 文字列抽出（旧 tools/static/nrs_strings.py の native 版）。
 *
 * 外部依存ゼロ。ASCII([0x20-0x7E]{5,}) と UTF-16LE((?:[ascii]\x00){5,}) を抽出し、
 * オフセット順・重複排除して出力。既定は BBS 調査向けキーワードで絞り込み、--all で全件。
 * 対象は環境変数 NRS_EXE（既定 C:\src\bbs\nrs.exe）。
 *
 * 使い方:  nrs_strings.exe [--all]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ---- 注目キーワード（case-insensitive 部分一致）。com\d と IP は別途特別扱い。 ---- */
static const char *KW[] = {
    "\\\\.\\", "keychip","dongle","sbva","sega","ringedge","amlib","mxgethw","hwinfo",
    "jvs","coin","service",".sega.","naomi","alls","auth","license","teknoparrot",
    ".ini",".cfg",".dat","ram\\","rom\\","border","nrs","wsvga","1024","baud","comm",
    "serial","http://","https://","pcpa","amdongle","amjvs","amrtc","amplatform","amhm",
    "alpb","auth server",
};
#define NKW (int)(sizeof KW / sizeof KW[0])

static void str_tolower(const char *s, char *out, size_t cap){
    size_t i=0; for(; s[i] && i<cap-1; i++) out[i]=(char)tolower((unsigned char)s[i]); out[i]=0;
}
static int has_comN(const char *lo){
    for(const char *p=lo; (p=strstr(p,"com")); p+=3) if(isdigit((unsigned char)p[3])) return 1;
    return 0;
}
static int has_ip(const char *s){
    /* d{1,3}.d{1,3}.d{1,3}.d{1,3} を素朴に検出 */
    for(const char *p=s; *p; p++){
        const char *q=p; int groups=0, dig=0, ok=1;
        for(int g=0; g<4; g++){
            dig=0; while(isdigit((unsigned char)*q)){ q++; dig++; }
            if(dig<1||dig>3){ ok=0; break; }
            groups++;
            if(g<3){ if(*q!='.'){ ok=0; break; } q++; }
        }
        if(ok && groups==4) return 1;
    }
    return 0;
}
static int interesting(const char *s){
    char lo[1024]; str_tolower(s, lo, sizeof lo);
    for(int i=0;i<NKW;i++) if(strstr(lo, KW[i])) return 1;
    if(has_comN(lo)) return 1;
    if(has_ip(s)) return 1;
    return 0;
}

/* ---- 抽出結果 ---- */
typedef struct { long off; char enc; char *s; } Hit;
static Hit *g_hits; static size_t g_n, g_cap;
static void add_hit(long off, char enc, const char *s){
    if(g_n==g_cap){ g_cap=g_cap?g_cap*2:8192; g_hits=(Hit*)realloc(g_hits,g_cap*sizeof(Hit)); }
    g_hits[g_n].off=off; g_hits[g_n].enc=enc; g_hits[g_n].s=_strdup(s); g_n++;
}
static int cmp_off(const void *a,const void *b){
    long d=((const Hit*)a)->off - ((const Hit*)b)->off; return d<0?-1:(d>0?1:0);
}

/* ---- 簡易文字列ハッシュ集合（重複排除） ---- */
static char **g_seen; static size_t g_seen_cap;
static unsigned long djb2(const char *s){ unsigned long h=5381; int c; while((c=*s++)) h=((h<<5)+h)+(unsigned long)c; return h; }
static int seen_add(const char *s){   /* 既出なら 0、新規追加なら 1 */
    if(g_seen_cap==0){ g_seen_cap=1<<16; g_seen=(char**)calloc(g_seen_cap,sizeof(char*)); }
    unsigned long h=djb2(s)&(g_seen_cap-1);
    for(size_t i=0;i<g_seen_cap;i++){
        size_t idx=(h+i)&(g_seen_cap-1);
        if(!g_seen[idx]){ g_seen[idx]=_strdup(s); return 1; }
        if(strcmp(g_seen[idx],s)==0) return 0;
    }
    return 1; /* 満杯（事実上起きない） */
}

int main(int argc, char **argv){
    int show_all=0;
    for(int i=1;i<argc;i++) if(strcmp(argv[i],"--all")==0) show_all=1;

    const char *path=getenv("NRS_EXE"); if(!path) path="C:\\src\\bbs\\nrs.exe";
    FILE *f=fopen(path,"rb");
    if(!f){ fprintf(stderr,"ERROR: %s not found\n",path); return 1; }
    fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
    unsigned char *d=(unsigned char*)malloc((size_t)sz);
    if(!d || fread(d,1,(size_t)sz,f)!=(size_t)sz){ fprintf(stderr,"ERROR: read failed\n"); return 1; }
    fclose(f);

    char *buf=(char*)malloc((size_t)sz+1);  /* 抽出片の作業領域 */

    /* ASCII: [0x20-0x7E]{5,} */
    for(long i=0;i<sz;){
        if(d[i]>=0x20 && d[i]<=0x7E){
            long j=i, k=0;
            while(j<sz && d[j]>=0x20 && d[j]<=0x7E){ buf[k++]=(char)d[j]; j++; }
            if(k>=5){ buf[k]=0; add_hit(i,'A',buf); }
            i=j;
        } else i++;
    }
    /* UTF-16LE: (?:[0x20-0x7E]\x00){5,} */
    for(long i=0;i+1<sz;){
        if(d[i]>=0x20 && d[i]<=0x7E && d[i+1]==0x00){
            long j=i, k=0;
            while(j+1<sz && d[j]>=0x20 && d[j]<=0x7E && d[j+1]==0x00){ buf[k++]=(char)d[j]; j+=2; }
            if(k>=5){ buf[k]=0; add_hit(i,'U',buf); }
            i=j;
        } else i++;
    }

    qsort(g_hits, g_n, sizeof(Hit), cmp_off);

    int count=0;
    for(size_t i=0;i<g_n;i++){
        char *s=g_hits[i].s;
        /* strip 先頭末尾空白（Python の .strip()） */
        while(*s==' '||*s=='\t') s++;
        size_t L=strlen(s); while(L&&(s[L-1]==' '||s[L-1]=='\t')) s[--L]=0;
        if(L<5) continue;
        if(!seen_add(s)) continue;
        if(show_all || interesting(s)){
            printf("[0x%08lX] [%c] %s\n", g_hits[i].off, g_hits[i].enc, s);
            count++;
        }
    }
    printf("\n%d strings printed.\n", count);
    return 0;
}
