/* keychip PCP 応答ロジック（旧 pcpa_server.py の handle_request 移植・純粋関数）。
 * 設定値は cabinet/default.toml 相当をハードコード。winsock/host 非依存＝単体テスト可。 */
#include "keychip_proto.h"
#include <stdio.h>
#include <string.h>

/* cabinet/default.toml 相当（identity/network/billing） */
#define KC_GAMEID    "SBVA"
#define KC_REGION    "01"          /* 01=JAPAN */
#define KC_PLATID    "AAA"
#define KC_SYSFLAG   "01"          /* bit0=1: amDongleSetupKeychip case5 が keychip_ctx+0xc=1 を設定 →
                                      FUN_0096c5f0=1 → DAT_016014a3=1 → usbio escape（errNo 951 解消）。
                                      実機 keychip も bit0 立て（standalone は USB I/O 基板不在で e4=0 のため
                                      この keychip escape が唯一の経路）。DAT_016014a3 は usbio 2 関数のみが読み副作用なし。 */
#define KC_KEYID     "0000000000000000"
#define KC_MAINID    "00000000000"
#define NET_IP       "192.168.1.209"
#define NET_MASK     "255.255.255.0"
#define NET_GW       "192.168.1.1"
#define NET_DNS1     "192.168.1.1"
#define NET_DNS2     "0.0.0.0"
#define BILL_LIMIT   "FFFFFFFF"

static int starts(const char *line, const char *key) {
    return strncmp(line, key, strlen(key)) == 0;
}
/* "key=" を探し値を out(up to '&'/終端) へ。 */
static void find_val(const char *line, const char *key, char *out, int cap) {
    char pat[64]; snprintf(pat, sizeof pat, "%s=", key);
    const char *p = strstr(line, pat);
    out[0] = 0;
    if (!p) return;
    p += strlen(pat);
    int i = 0;
    while (p[i] && p[i] != '&' && p[i] != '\r' && p[i] != '\n' && i < cap - 1) { out[i] = p[i]; i++; }
    out[i] = 0;
}

const char *kc_respond(const char *line, char *buf, int cap) {
    char v[64];
    if (starts(line, "keychip.ds.compute") || starts(line, "keychip.ssd.proof") ||
        starts(line, "keychip.ssd.hostproof")) return "code=54";
    if (starts(line, "keychip.appboot.systemflag")) return "keychip.appboot.systemflag=" KC_SYSFLAG;
    if (starts(line, "keychip.version"))            return "keychip.version=0001";
    if (starts(line, "keychip.appboot.gameid"))     return "keychip.appboot.gameid=" KC_GAMEID;
    if (starts(line, "keychip.appboot.region"))     return "keychip.appboot.region=" KC_REGION;
    if (starts(line, "keychip.appboot.platformid")) return "keychip.appboot.platformid=" KC_PLATID;
    if (starts(line, "keychip.appboot.modeltype"))  return "keychip.appboot.modeltype=00";
    if (starts(line, "keychip.appboot.formattype")) return "keychip.appboot.formattype=00";
    if (starts(line, "keychip.appboot.networkaddr"))return "keychip.appboot.networkaddr=" NET_GW;
    if (starts(line, "keychip.appboot.dvdflag"))    return "keychip.appboot.dvdflag=00";
    if (starts(line, "keychip.appboot.seed"))       return "keychip.appboot.seed=-1";
    if (starts(line, "keychip.encrypt")) return "keychip.encrypt=00000000000000000000000000000000";
    if (starts(line, "keychip.decrypt")) return "keychip.decrypt=00000000000000000000000000000000";
    if (starts(line, "keychip.setiv"))   return "keychip.setiv=1";
    if (starts(line, "keychip.billing.keyid"))     return "keychip.billing.keyid=" KC_KEYID;
    if (starts(line, "keychip.billing.mainid"))    return "keychip.billing.mainid=" KC_MAINID;
    if (starts(line, "keychip.billing.playcount")) return "keychip.billing.playcount=00000000";
    if (starts(line, "keychip.billing.playlimit")) return "keychip.billing.playlimit=" BILL_LIMIT;
    if (starts(line, "keychip.billing.nearfull"))  return "keychip.billing.nearfull=00000000";
    if (starts(line, "keychip.tracedata.restore")) return "keychip.tracedata.restore=0";
    if (starts(line, "keychip.tracedata.put"))     return "keychip.tracedata.put=0";
    if (starts(line, "keychip.tracedata.get"))     return "keychip.tracedata.get=";
    if (starts(line, "keychip.tracedata.sectorerase")) return "keychip.tracedata.sectorerase=0";
    if (starts(line, "keychip.appboot.")) return "code=0";
    if (starts(line, "mxmaster.foreground.getcount")) {
        find_val(line, "mxmaster.foreground.getcount", v, sizeof v);
        snprintf(buf, cap, "mxmaster.foreground.getcount=%s\r\ncount=0", v); return buf;
    }
    if (starts(line, "mxmaster.foreground.active")) {
        find_val(line, "mxmaster.foreground.active", v, sizeof v);
        if (strcmp(v, "?") == 0 || strcmp(v, "1") == 0) return "mxmaster.foreground.active=1";
        snprintf(buf, cap, "mxmaster.foreground.active=%s", v); return buf;
    }
    if (starts(line, "mxmaster.foreground.next")) {
        find_val(line, "mxmaster.foreground.next", v, sizeof v);
        snprintf(buf, cap, "mxmaster.foreground.next=%s", v); return buf;
    }
    if (starts(line, "mxmaster.foreground.current")) return "mxmaster.foreground.current=1";
    if (starts(line, "mxmaster.foreground.fault"))   return "mxmaster.foreground.fault=0";
    if (starts(line, "mxmaster.foreground.setcount")) {
        char c[16]; find_val(line, "mxmaster.foreground.setcount", v, sizeof v);
        find_val(line, "count", c, sizeof c); if (!c[0]) strcpy(c, "0");
        snprintf(buf, cap, "mxmaster.foreground.setcount=%s\r\ncount=%s", v, c); return buf;
    }
    if (starts(line, "request=")) {
        find_val(line, "request", v, sizeof v);
        /* amInstall（port 40102, amDongle/amInstall SM）応答。FUN_00977d50 が "response" キーを req 名と
           照合し、FUN_009765d0 が "result"=="success" を要求。旧 "status=0"/"code=0" は形式不一致で SM が
           完走せず ctx[0xc] が busy のまま → amDongleBusy(0x975E00) RET0 patch が必要だった。正式形式で genuine
           完走させ、ブロッキング init amDongle_top_level_init(do{outerSM/keychipSM}while != done)を抜ける（RET0 撤去）。
           steer 先（実体確定。各 status→数値は FUN_009767f0/FUN_00976aa0/FUN_00977050 の strcmp 表）:
           - query_slot_status   → complete : スロット既インストール(FUN_009767f0: complete→3)。install(req type 2)不発で 40103 不使用。
           - query_application_status → inactive : アプリ未起動(FUN_00976aa0: inactive→0)。
           - query_appdata_status/check_appdata → error : appdata status の唯一の整合解。3 consumer の交差:
             (a) keychipSM case3 の query(ctx+8=0xe, FUN_00977d50)は status∈{0,1,2,3,-1}で gameid 不要に成功（4/5 は
                 gameid フィールド必須＝無いと "Failed to get appdata status"）、(b) keychipSM case4 は -1 で format 回避し
                 state7-done（3=needed と 4/5 は format/削除を誘発。-1 は gameid 一致非依存）、(c) appdata task(ctx+8=0xf,
                 FUN_00977230)は param∉{0,1,2}で terminate（0/1/2 は execute=1 で check_appdata⇄query を無限ループ）。
                 → error(-1, FUN_00977050: error→-1)のみが (a)∩(b)∩(c) を満たす。実証: errors=0・loop 無し・attract 到達。 */
        if (!strcmp(v, "query_slot_status"))
            return "response=query_slot_status&result=success&status=complete";
        if (!strcmp(v, "query_application_status"))
            return "response=query_application_status&result=success&status=inactive";
        if (!strcmp(v, "query_appdata_status"))
            return "response=query_appdata_status&result=success&status=error";
        if (!strcmp(v, "check_appdata"))
            return "response=check_appdata&result=success&status=error";
        if (!strcmp(v, "query_dhcp_status"))
            return "response=query_dhcp_status&result=0&dhcp_status=3&ip_address=" NET_IP
                   "&subnetmask=" NET_MASK "&gateway=" NET_GW;
        if (!strcmp(v, "query_nic_status"))
            return "response=query_nic_status&result=0&status=1&ip_address=" NET_IP
                   "&subnetmask=" NET_MASK "&gateway=" NET_GW
                   "&primary_dns=" NET_DNS1 "&secondary_dns=" NET_DNS2;
        if (!strcmp(v, "get_status"))      return "response=get_status&result=0&status=incorrect";
        if (!strcmp(v, "set_auth_params")) return "response=set_auth_params&result=0&bbflag=1";
        if (!strcmp(v, "isrelease"))       return "response=isrelease&result=0&release=1";
        if (!strcmp(v, "resume"))          return "response=resume&result=0";
        if (!strcmp(v, "pause"))           return "response=pause&result=0";
        if (!strcmp(v, "stopcatcher"))     return "response=stopcatcher&result=0";
        return "code=0";
    }
    return "code=0";
}
