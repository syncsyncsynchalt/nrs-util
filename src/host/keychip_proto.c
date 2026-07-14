/* keychip PCP 応答ロジック（純粋関数・winsock/host 非依存＝単体テスト可）。
 * 設定値は cabinet/default.toml 相当をハードコード。 */
#include "keychip_proto.h"
#include <stdio.h>
#include <string.h>

/* cabinet/default.toml 相当（identity/network/billing） */
#define KC_GAMEID    "SBVA"
#define KC_REGION    "01"          /* 01=JAPAN */
#define KC_PLATID    "AAA"
#define KC_SYSFLAG   "01"          /* bit0=1: amDongleSetupKeychip case5 → keychip_ctx+0xc=1 → FUN_0096c5f0=1 →
                                      DAT_016014a3=1 → usbio escape（errNo 951 解消）。実機 keychip も bit0 立て。 */
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
        /* amInstall（port 40102, amDongle SM）応答。FUN_009765d0 が result=="success" を要求（形式不一致だと SM が
           完走せず ctx[0xc] busy のまま）。steer 先（status→数値は FUN_009767f0/76aa0/77050 の strcmp 表）:
           - query_slot_status → complete : スロット既インストール(→3)。install(req type 2)不発で 40103 不使用。
           - query_application_status → inactive : アプリ未起動(→0)。
           - query_appdata_status/check_appdata → error(-1): 3 consumer の唯一の整合解:
             (a) keychipSM case3 query は status∈{0..3,-1}で gameid 不要に成功、(b) case4 は -1 で format 回避し state7-done、
             (c) appdata task は param∉{0,1,2}で terminate（0/1/2 は check_appdata⇄query 無限ループ）→ error のみ交差を満たす。 */
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
        /* amGfetcher 応答は result_field_checker(0x975140) を通り result!="success" は -5→無限再接続ループ。
           よって全て result=success 必須。get_status の status=uptodate は「配信データ最新＝取得不要」の standalone 正解。
           parser(0x974B00) case9 が work_version/work_time/order_time/release_time を要求（欠くと -150）ため 0 で同梱。 */
        if (!strcmp(v, "get_status"))
            return "response=get_status&result=success&status=uptodate"
                   "&work_version=0&work_time=0&order_time=0&release_time=0";
        if (!strcmp(v, "set_auth_params")) return "response=set_auth_params&result=success&bbflag=1";
        if (!strcmp(v, "isrelease"))       return "response=isrelease&result=success&release=1";
        /* resume パーサ(0x9746c0)は firstreq を要求（無いと -150 loop）。値は "1"/"0" のみ有効。resume=配信継続ゆえ 0。 */
        if (!strcmp(v, "resume"))          return "response=resume&result=success&firstreq=0";
        if (!strcmp(v, "pause"))           return "response=pause&result=success";
        if (!strcmp(v, "stopcatcher"))     return "response=stopcatcher&result=success";
        /* amGcatcher(配信 catcher, port 40110) SM: dispatcher amGcatcher_sm_dispatch(0x979200) が
           verb で分岐（case1=startcatcher/2=stopcatcher/3=isupdate/4=reloadinfo）。startcatcher/
           stopcatcher/reloadinfo は共通検証 amGcatcher_verb_result_check(0x978fe0) が response==verb
           かつ result==success のとき 0（成功）を返す（追加フィールド無し）。汎用 code=0 応答は response 不一致で
           負値→上位 SM が毎フレーム再送する無限 loop になる。 */
        if (!strcmp(v, "reloadinfo"))      return "response=reloadinfo&result=success";
        if (!strcmp(v, "startcatcher"))    return "response=startcatcher&result=success";
        /* isupdate(case3, amGcatcher_isupdate_parse 0x979110): 共通検証後に incompatible(int)/
           server(inet_addr)/4 スロット(originalf/originalb/patchf/patchb) を必須。incompatible/server
           欠落は isupdate_parse 自身が -0x96。各スロットは amGcatcher_slot_status_parse(0x978e10) が
           notavailable/available/needed/instant/erasable を 0..4 へ写像し、欠落/未知値で -0x96→loop。
           standalone は全 notavailable(更新無し)＝game は download SM(setthread/readsegment 等)へ入らず
           boot 継続。server は未使用だが inet_addr が INADDR_NONE を返さぬよう有効 IP を置く。 */
        if (!strcmp(v, "isupdate"))
            return "response=isupdate&result=success&incompatible=0&server=127.0.0.1"
                   "&originalf=notavailable&originalb=notavailable"
                   "&patchf=notavailable&patchb=notavailable";
        /* amStorage(port 40114, FUN_0097b300) query。応答から check/format フィールドを読み storage SM を進める。
           check/format=0＝チェック/フォーマット不要（storage 正常）。result=success 必須（amNet 系は非 success で再接続 loop）。 */
        if (!strcmp(v, "query_storage_status"))
            return "response=query_storage_status&result=success&check=0&format=0";
        if (!strcmp(v, "query_storage_count"))
            return "response=query_storage_count&result=success&count=0";
        return "code=0";
    }
    return "code=0";
}
