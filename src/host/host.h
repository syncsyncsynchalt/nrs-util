#pragma once
#include "abi.h"

extern SRWLOCK       g_logic_lock;
extern const LogicApi *g_api;
extern LogicState   *g_state;
extern HostServices  g_host;

void  host_log(const char *level, const char *json_line);
void *host_arena_alloc(size_t n);
int   hooks_install(void);
void *host_orig(int orig_id);
int   gamehooks_install(void);
void  keychip_server_start(void);
void  netobs_install(void);
void  allnet_install(void);
void  windowed_install(void);
void  capture_install(void);
void  exitlog_install(void);
void  dbglog_install(void);
const NrsConfig *config_load(void);
int   reload_load_initial(void);
void  reload_start_watcher(void);
