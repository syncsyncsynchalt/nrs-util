/* 静的パッチ群を nrs.exe へ適用（bind 時に一度）。詳細は patches.c。 */
#pragma once
#include "abi.h"
void patches_apply(HostServices *h);
