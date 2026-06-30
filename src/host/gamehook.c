/* game-function hooks: nrs.exe 内部関数を VA で hook。
 * reload-safe: detour は安定 host 側に置き、現行 logic を g_api 経由で呼ぶ（logic.dll swap で無効化しない）。
 * 対象（全て void/u32 (void)）: jvs_update_main(0x67B150) / sysinput(0x89B230) / dipsw read(0x45A0E0)。 */
#include "host.h"
#include "MinHook.h"

#define IMAGE_BASE 0x400000u

static void     (*o_jvs_update)(void);
static void     (*o_sysinput)(void);
static unsigned (*o_dipsw)(void);
static int      (*o_kchold)(void);
static long long (__stdcall *o_rtc_get)(void *tm, unsigned *flag);
static int (__fastcall *o_eeprom_init)(unsigned ecx, unsigned edx, void *size_ptr);
static int (*o_dipsw_init)(void);
static void (*o_board_check)(void);
static unsigned (*o_ext_install_kick)(void);
static int      (*o_extimg_gate_probe)(void);

/* jvs_update_main PRE: 入力を node BSS へ書いてから本体へ（旧 input.js）。 */
static void __cdecl d_jvs_update(void) {
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_jvs_tick) g_api->on_jvs_tick(g_state);
    ReleaseSRWLockShared(&g_logic_lock);
    o_jvs_update();
}
/* system input processor PRE: DAT_0160194c の TEST/SERVICE を読まれる前に確定。 */
static void __cdecl d_sysinput(void) {
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_sys_override) g_api->on_sys_override(g_state);
    ReleaseSRWLockShared(&g_logic_lock);
    o_sysinput();
}
/* dipsw read PRE+POST: PRE で dipsw ctx を provisioning（board_index を本体が読む前に H_MXSMBUS 化＝errCode 0xa→errNo 910 解消）、
 * POST で本体が DAT_0160194c bit0/1 を立て直すのを打ち消す。 */
static unsigned __cdecl d_dipsw(void) {
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_dipsw_provision) g_api->on_dipsw_provision(g_state);  /* PRE: 読取前に ctx provisioning */
    ReleaseSRWLockShared(&g_logic_lock);
    unsigned r = o_dipsw();
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_sys_override) g_api->on_sys_override(g_state);
    ReleaseSRWLockShared(&g_logic_lock);
    return r;
}

/* keychip_errCode1_latcher PRE: 真正 present なら present flag を立て直してから本体へ。 */
static int __cdecl d_kchold(void) {
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_keychip_hold) g_api->on_keychip_hold(g_state);
    ReleaseSRWLockShared(&g_logic_lock);
    return o_kchold();
}

/* amRtcGetServerTime(stdcall, longlong 戻り) POST: orig を呼び、失敗(-1)なら logic が PC 時刻で埋め成功を返す。
 * 規約厳密化が必須（disasm: RET 0x8 = stdcall / EAX:EDX = 64bit 戻り）。誤ると stack 破壊。 */
static long long __stdcall d_rtc_get(void *tm, unsigned *flag) {
    long long r = o_rtc_get(tm, flag);
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_rtc_get) r = g_api->on_rtc_get(g_state, tm, flag, r);
    ReleaseSRWLockShared(&g_logic_lock);
    return r;
}

/* amEepromInit(0x985160) 完全置換 detour（__thiscall: protocol=ECX, size_ptr=stack1, RET 4 ＝
 * __fastcall(ECX,EDX,stack) で捕捉）。orig は呼ばず（SetupDi 失敗経路と後始末 FUN_00984bd0 を回避）、
 * logic に EEPROM ctx を provisioning させ 0(成功)を返す。これで amlib_storage_init_all が storage-init の
 * 最中に genuine な amBackupRead(STATIC area0) を走らせ、seed 済み region_game_pcb=01 を得る。 */
static int __fastcall d_eeprom_init(unsigned ecx, unsigned edx, void *size_ptr) {
    (void)ecx; (void)edx; (void)size_ptr;
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_eeprom_init) g_api->on_eeprom_init(g_state);
    ReleaseSRWLockShared(&g_logic_lock);
    return 0;   /* amEepromInit 成功（amlib_eeprom_ok=1）*/
}

/* amDipswInit(0x9842A0) POST: 標準筐体に mxsmbus PnP が無く orig は SetupDi 失敗で handle(0xccf490)=-1 を残す。
 * orig の直後（呼出元 FUN_0045a040 が amDipswInit→直後に amDipswRead する、その間）で dipsw ctx を H_MXSMBUS へ
 * provisioning すると、続く amDipswRead が IOCTL(cmd5,vcode0)→0x20 で board_index=2 を読む（errCode 0xa→errNo 910 解消）。
 * read hook(d_dipsw)の PRE provisioning は board_index を確定する最初の read に間に合わないため、init detour で前倒しする
 * （EEPROM の amEepromInit detour と同型の早期 provisioning）。 */
static int __cdecl d_dipsw_init(void) {
    int r = o_dipsw_init();   /* 実 amDipswInit（standalone は失敗・handle=-1・initFlag=1）*/
    AcquireSRWLockShared(&g_logic_lock);
    if (g_api && g_api->on_dipsw_provision) g_api->on_dipsw_provision(g_state);
    ReleaseSRWLockShared(&g_logic_lock);
    return r;
}

/* amlib_storage_board_check(0x679CB0) PRE: board-table 判定の消費直前に標準筐体の board index(=2, table[2]=8) と
 * dipsw flag(0x20=0) を供給する。dipsw シリアル read(amDipswRead→FUN_009836e0)は標準筐体に mxsmbus PnP が無いと
 * handle 無効で garbage byte3(=0x5x)→board_index 5/flag 0x20 set を残し、ctx provisioning では board_index を確定する
 * 最初の read に間に合わない（ライブ実証）。consumer 側で供給すれば dipsw read のタイミングに非依存で errCode
 * 0xa(→errNo 910 "Wrong Resolution Setting")/0xb を確実に断つ。旧 dipsw byte patch(0x45A0F5/F9)と同じ effect を
 * 静的メモリパッチ無しの gamehook で実現（host が境界で正データを供給）。 */
static void __cdecl d_board_check(void) {
    uintptr_t b = (uintptr_t)GetModuleHandleW(NULL);
    *(unsigned char *)(b + (0x1601953u - IMAGE_BASE)) = 2;     /* board_index = 2（table[2]=8）*/
    *(unsigned int  *)(b + (0x160194Cu - IMAGE_BASE)) &= ~0x20u; /* DAT_0160194c bit0x20=0（0xb 回避）*/
    o_board_check();
}

/* keychip_appdata_delete_gate_probe(0x45A8F0, amlib_master_init から call＝SYSTEM STARTUP SM より前) POST:
 * この probe は extend-image/appdata ファイルの存在(__stat64i32)＋検証(FUN_00969a00)で DAT_01601b23(image-present gate)を
 * 1 にする本物の判定。standalone は extend-image ファイルが無く gate=0 のままで、state5 substate1 が
 * "CHECKING EXTEND IMAGE … NG" を出し install 試行に入る（install getter 経由は state 0xc=Install Error しか前進路が
 * 無く NG 表示）。実筐体「extend-image 導入済み」境界条件を供給＝gate=1 を force すると substate1 が skip 枝→"… OK"→
 * state6（INSTALLING 行を出さず install を完全 skip）＝TP の extend-image 提供と等価の純正 OK。
 * gate=1 は state1 case1 で extended リソース再ロード(FUN_007416e0 列)を誘発するが、これは image-present 時の genuine 挙動
 * （FUN_007416e0 は bounds-check 付きで idx 不正は graceful return 0）。下の install kicker POST は多層防御の fallback
 * （万一 gate 経路を通らず install 試行に入った場合に install_ctx を完了 provision＝最悪でも "NG"だが前進、旧 P_extimg 相当）。 */
static int __cdecl d_extimg_gate_probe(void) {
    int r = o_extimg_gate_probe();
    *(unsigned char *)((uintptr_t)GetModuleHandleW(NULL) + (0x1601B23u - IMAGE_BASE)) = 1; /* image-present gate=1 */
    return r;
}

/* extend-image install kicker (FUN_0072eaf0, boot SM SYSTEM_STARTUP state5 substate2) POST:
 * orig は devMgr+0x26d/0x26e=1 を立て ALL.Net 経由の extend-image install を開始させる。だが extend-image install は
 * 実体が ALL.Net 配信タスク(NetworkTask, install_ctx=devMgr+0x258=field[0x96])で、network 未エミュの standalone では
 * install SM が state を進められず詰まる（旧静的パッチ P_extimg 0x72B3A0 が getter を return 4 詐称していた所以）。
 * 実筐体で「イメージ導入済み」に当たる境界条件を供給＝install_ctx に state=0xc(完了)/error(+0x284)=0 を provisioning する。
 * state5 substate2 は同 tick で substate3 に fall-through し（disasm: 0x89a4c8 kicker→0x89a4eb 0x72b3a0 読取）、その
 * extend_image_install_status(0x72b3a0) が *param_2(devMgr+0x258)==0xc→return 4・*ESI(param_2[0xb]=devMgr+0x284)=0 を読む。
 * boot SM は (return>3 && error==0) を成功と解し state6 へ genuine 前進＝getter 無改変のまま P_extimg を撤去できる
 * （d_board_check / d_eeprom_init と同型の「詐称→純正供給」格上げ。host が境界で正データを供給）。
 * FUN_0072eaf0 の xref は boot SM 一箇所のみ＝SYSTEM TEST 等の他経路に副作用なし。devMgr は amlib_device_manager_ptr
 * (0x72b450, 副作用なしの getter)を呼んで取得（detour はゲームスレッド上で走る）。真の genuine 化（実 install SM 完走）は
 * ALL.Net 層エミュ＝Phase B2 が前提。回帰（state5 で EXTEND IMAGE NG / INSTALLING WAITING 固着）時は P_extimg を復活。 */
static unsigned __cdecl d_ext_install_kick(void) {
    unsigned r = o_ext_install_kick();   /* orig: devMgr+0x26d/0x26e=1（install 開始トリガ）*/
    unsigned (*devmgr_ptr)(void) = (unsigned (*)(void))
        ((uintptr_t)GetModuleHandleW(NULL) + (0x72B450u - IMAGE_BASE));   /* amlib_device_manager_ptr */
    uintptr_t dm = (uintptr_t)devmgr_ptr();
    if (dm) {
        *(unsigned *)(dm + 0x258) = 0xC;   /* install_ctx state = 0xc（完了→getter return 4）*/
        *(unsigned *)(dm + 0x284) = 0;     /* install_ctx error(param_2[0xb]) = 0（errCode latch 回避）*/
    }
    return r;
}

/* dinput_create_device(0x67CBE0) PRE/POST: SysMouse(=USB I/O board proxy)取得を窓生成タイミングに非依存化する。
 * count++ は SetCooperativeLevel(DAT_01696e0c, FOREGROUND|NONEXCLUSIVE) 成功が条件だが、起動初期（board check 内
 * FUN_0067c510 経由）は WGL 窓未生成で hwnd=0 → SetCoopLevel が E_HANDLE 失敗 → usbio_board_count=0 のまま →
 * usbio_errCode_mapper(0x6F0AD0)が errCode 0xf(=errNo 951 "USB Device Not Found")を latch。
 * 対策: hwnd 未生成時のみ取得可能な窓(WGL があればそれ、無ければデスクトップ窓)を一時供給し、ゲーム自身の
 * dinput_create_device に **genuine に** SysMouse を CreateDevice/SetDataFormat/SetCooperativeLevel/Acquire させて
 * count を立てさせる（count を直接書かない＝OS 境界エミュ）。本来の WGL 窓が出来たら次回呼出で作り直される。 */
static int gh(unsigned va, void *det, void **orig) {
    void *a = (void *)((uintptr_t)GetModuleHandleW(NULL) + (va - IMAGE_BASE));
    return (MH_CreateHook(a, det, orig) == MH_OK && MH_EnableHook(a) == MH_OK) ? 0 : -1;
}

int gamehooks_install(void) {   /* MH_Initialize は hooks_install で実施済 */
    int e = 0;
    e |= gh(0x67B150, (void *)d_jvs_update, (void **)&o_jvs_update);
    e |= gh(0x89B230, (void *)d_sysinput,   (void **)&o_sysinput);
    e |= gh(0x45A0E0, (void *)d_dipsw,      (void **)&o_dipsw);
    e |= gh(0x6F0A80, (void *)d_kchold,     (void **)&o_kchold);
    e |= gh(0x974040, (void *)d_rtc_get,    (void **)&o_rtc_get);
    e |= gh(0x985160, (void *)d_eeprom_init,(void **)&o_eeprom_init);
    e |= gh(0x9842A0, (void *)d_dipsw_init, (void **)&o_dipsw_init);   /* amDipswInit POST: dipsw ctx 早期 provisioning */
    e |= gh(0x679CB0, (void *)d_board_check,(void **)&o_board_check);  /* board check PRE: board index=2/flag 供給（errCode 0xa→errNo 910 解消）*/
    e |= gh(0x45A8F0, (void *)d_extimg_gate_probe,(void **)&o_extimg_gate_probe); /* image-present gate POST: DAT_01601b23=1（EXTEND IMAGE→OK skip）*/
    e |= gh(0x72EAF0, (void *)d_ext_install_kick,(void **)&o_ext_install_kick); /* extend-image install kicker POST: install_ctx 完了 provision（fallback／P_extimg 0x72B3A0 格上げ）*/
    return e;
}
