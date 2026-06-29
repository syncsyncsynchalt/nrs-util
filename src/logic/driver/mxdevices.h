/* mxdrivers: columba(DMI) / mxsram / mxsuperio / mxsmbus(eeprom) / mxhwreset を
 * CreateFile+DeviceIoControl 境界でエミュ（旧 boot/mxdrivers/devices.js の移植）。 */
#pragma once
#include "abi.h"

/* bind 時に host サービスを渡す（nvram.bin 永続化に原 CreateFile を使うため）。reload-safe。 */
void mxdev_init(HostServices *host);
/* mxsmbus 擬似 HANDLE（AT24C64AN eeprom IOCTL の宛先）。eeprom 強制 provisioning が device handle に使う。 */
HANDLE mxdev_smbus_handle(void);
/* 名前が RingEdge デバイスなら擬似 HANDLE を *out へ。戻り 1=処理した。 */
int  mxdev_create(const wchar_t *name, HANDLE *out);
/* 擬似 HANDLE への DeviceIoControl を処理。*handled=1 なら host は原関数を呼ばない。 */
BOOL mxdev_ioctl(HANDLE h, DWORD code, void *in, DWORD inlen,
                 void *out, DWORD outlen, DWORD *ret, int *handled);
/* mxsram(ブロックデバイス)のデータ面: SetFilePointer 位置決め + ReadFile/WriteFile。
   実 RingEdge amSram の記録 R/W 経路。h が mxsram でなければ *handled=0。 */
DWORD mxdev_seek(HANDLE h, long dist, long *dist_high, DWORD method, int *handled);
BOOL  mxdev_read(HANDLE h, void *buf, DWORD n, DWORD *got, int *handled);
BOOL  mxdev_write(HANDLE h, const void *buf, DWORD n, DWORD *put, int *handled);
