/* host 内部共有（host.c/hook.c/log.c/reload.c）。logic からは見えない。 */
#pragma once
#include "abi.h"

extern SRWLOCK       g_logic_lock;  /* on_* 呼出=read, reload=write */
extern const LogicApi *g_api;       /* 現行 logic.dll のテーブル（reload で差し替え） */
extern LogicState   *g_state;       /* host arena 上の logic 状態（reload を跨いで生存） */
extern HostServices  g_host;        /* logic へ渡すサービス */

/* log.c */
void  host_log(const char *level, const char *json_line);
/* host.c (arena) */
void *host_arena_alloc(size_t n);
/* hook.c */
int   hooks_install(void);
void *host_orig(int orig_id);
/* gamehook.c */
int   gamehooks_install(void);
/* keychip_server.c */
void  keychip_server_start(void);
/* netobs.c — U1 観測スパイク: winsock connect/resolve を log のみ（billing path B/U1）。確定後は撤去 */
void  netobs_install(void);
/* windowed.c */
void  windowed_install(void);
/* capture.c — GL フレームを capture.req トリガで capture.png へ保存（プロセス内 glReadPixels）*/
void  capture_install(void);
/* exitlog.c */
void  exitlog_install(void);
/* dbglog.c — nrs.exe の開発デバッグログ4系統(amiDebug A/B + 生 stdio C + SEH crash backtrace D)を host ログへ転送 */
void  dbglog_install(void);
/* config.c */
const NrsConfig *config_load(void);
/* reload.c */
int   reload_load_initial(void);    /* 初回ロード + bind */
void  reload_start_watcher(void);   /* logic.dll 変更監視スレッド */
