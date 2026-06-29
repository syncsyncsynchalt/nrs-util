/* ホスト側入力ポーリング（GetAsyncKeyState → NrsInput）。バインドは config(NrsConfig.bind[]) から。 */
#pragma once
#include "abi.h"
#include "mxjvs.h"

/* binds[ACT_*] = 各アクションの VK コード。NULL なら既定バインド。 */
void nrs_poll_input(NrsInput *out, const unsigned short *binds);
