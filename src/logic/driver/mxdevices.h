#pragma once
#include "abi.h"

void mxdev_init(HostServices *host);
HANDLE mxdev_smbus_handle(void);
int  mxdev_create(const wchar_t *name, HANDLE *out);
BOOL mxdev_ioctl(HANDLE h, DWORD code, void *in, DWORD inlen,
                 void *out, DWORD outlen, DWORD *ret, int *handled);
DWORD mxdev_seek(HANDLE h, long dist, long *dist_high, DWORD method, int *handled);
BOOL  mxdev_read(HANDLE h, void *buf, DWORD n, DWORD *got, int *handled);
BOOL  mxdev_write(HANDLE h, const void *buf, DWORD n, DWORD *put, int *handled);
